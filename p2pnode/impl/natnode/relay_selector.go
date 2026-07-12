package natnode

import (
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/relayquery"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	defaultRelayProbeConcurrency = 8
	defaultRelayRTTBandMin       = 10 * time.Millisecond
	defaultRelayRTTBandRatio     = 0.10
	defaultRelayControlStale     = 2 * time.Minute
)

type relayTCPProbe func(context.Context, relayquery.Info) (time.Duration, error)

type relaySelector struct {
	probe           relayTCPProbe
	now             func() time.Time
	probeTimeout    time.Duration
	concurrency     int
	rttBandMin      time.Duration
	rttBandRatio    float64
	controlStaleAge time.Duration
	includeIndex    bool
}

type relaySelection struct {
	Address       string
	NodeID        string
	RTT           time.Duration
	RTTBand       int64
	StableAge     time.Duration
	Eligible      int
	Fallback      bool
	SelectedIndex bool
}

type relayCandidate struct {
	info      relayquery.Info
	rtt       time.Duration
	rttBand   int64
	stableAge time.Duration
	distance  string
}

func newRelaySelector() relaySelector {
	return relaySelector{
		probe:           probeRelayTCP,
		now:             time.Now,
		probeTimeout:    relayProbeTimeout,
		concurrency:     defaultRelayProbeConcurrency,
		rttBandMin:      defaultRelayRTTBandMin,
		rttBandRatio:    defaultRelayRTTBandRatio,
		controlStaleAge: defaultRelayControlStale,
	}
}

func (s relaySelector) Select(ctx context.Context, selfID p2pnode.NodeID, indexAddr string, infos []relayquery.Info) relaySelection {
	s = s.normalized()
	infos = normalizeRelayCandidates(indexAddr, infos, s.includeIndex)
	if len(infos) == 0 {
		return relaySelection{Address: indexAddr, Fallback: true}
	}

	type probeResult struct {
		info relayquery.Info
		rtt  time.Duration
		err  error
	}
	results := make(chan probeResult, len(infos))
	semaphore := make(chan struct{}, s.concurrency)
	var waitGroup sync.WaitGroup
	for _, info := range infos {
		info := info
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				results <- probeResult{info: info, err: ctx.Err()}
				return
			}
			defer func() { <-semaphore }()
			probeCtx, cancel := context.WithTimeout(ctx, s.probeTimeout)
			rtt, err := s.probe(probeCtx, info)
			cancel()
			results <- probeResult{info: info, rtt: rtt, err: err}
		}()
	}
	waitGroup.Wait()
	close(results)

	now := s.now()
	eligible := make([]relayCandidate, 0, len(infos))
	bestRTT := time.Duration(0)
	for result := range results {
		if result.err != nil || result.rtt <= 0 {
			continue
		}
		if result.info.LastControlSeen > 0 {
			lastSeen := time.Unix(result.info.LastControlSeen, 0)
			if now.Sub(lastSeen) > s.controlStaleAge {
				continue
			}
		}
		stableAge := time.Duration(0)
		if result.info.ContinuousOnlineSince > 0 {
			since := time.Unix(result.info.ContinuousOnlineSince, 0)
			if !since.After(now) {
				stableAge = now.Sub(since)
			}
		}
		candidate := relayCandidate{
			info:      result.info,
			rtt:       result.rtt,
			stableAge: stableAge,
			distance:  selfID.XOR(p2pnode.NodeID(result.info.NodeID)).Text(16),
		}
		eligible = append(eligible, candidate)
		if bestRTT == 0 || result.rtt < bestRTT {
			bestRTT = result.rtt
		}
	}
	if len(eligible) == 0 {
		return relaySelection{Address: indexAddr, Fallback: true}
	}

	bandWidth := s.rttBandMin
	if proportional := time.Duration(float64(bestRTT) * s.rttBandRatio); proportional > bandWidth {
		bandWidth = proportional
	}
	for index := range eligible {
		eligible[index].rttBand = int64((eligible[index].rtt - bestRTT) / bandWidth)
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		left, right := eligible[i], eligible[j]
		if left.rttBand != right.rttBand {
			return left.rttBand < right.rttBand
		}
		if left.stableAge != right.stableAge {
			return left.stableAge > right.stableAge
		}
		if left.info.LoadPermille != right.info.LoadPermille {
			return left.info.LoadPermille < right.info.LoadPermille
		}
		if left.rtt != right.rtt {
			return left.rtt < right.rtt
		}
		if len(left.distance) != len(right.distance) {
			return len(left.distance) < len(right.distance)
		}
		if left.distance != right.distance {
			return left.distance < right.distance
		}
		return left.info.NodeID < right.info.NodeID
	})

	selected := eligible[0]
	return relaySelection{
		Address:       selected.info.Addr,
		NodeID:        selected.info.NodeID,
		RTT:           selected.rtt,
		RTTBand:       selected.rttBand,
		StableAge:     selected.stableAge,
		Eligible:      len(eligible),
		SelectedIndex: selected.info.Addr == indexAddr,
	}
}

func (s relaySelector) normalized() relaySelector {
	if s.probe == nil {
		s.probe = probeRelayTCP
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.probeTimeout <= 0 {
		s.probeTimeout = relayProbeTimeout
	}
	if s.concurrency <= 0 {
		s.concurrency = defaultRelayProbeConcurrency
	}
	if s.rttBandMin <= 0 {
		s.rttBandMin = defaultRelayRTTBandMin
	}
	if s.rttBandRatio <= 0 {
		s.rttBandRatio = defaultRelayRTTBandRatio
	}
	if s.controlStaleAge <= 0 {
		s.controlStaleAge = defaultRelayControlStale
	}
	return s
}

func normalizeRelayCandidates(indexAddr string, infos []relayquery.Info, includeIndex bool) []relayquery.Info {
	byAddress := make(map[string]relayquery.Info)
	for _, info := range infos {
		if info.Addr == "" || (!includeIndex && info.Addr == indexAddr) || !validRelayNodeID(info.NodeID) {
			continue
		}
		current, exists := byAddress[info.Addr]
		if !exists || info.LastControlSeen > current.LastControlSeen ||
			(info.LastControlSeen == current.LastControlSeen && info.NodeID < current.NodeID) {
			byAddress[info.Addr] = info
		}
	}
	result := make([]relayquery.Info, 0, len(byAddress))
	for _, info := range byAddress {
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].NodeID != result[j].NodeID {
			return result[i].NodeID < result[j].NodeID
		}
		return result[i].Addr < result[j].Addr
	})
	return result
}

func validRelayNodeID(nodeID string) bool {
	if len(nodeID) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(nodeID)
	return err == nil && len(decoded) == 32
}

func probeRelayTCP(ctx context.Context, info relayquery.Info) (time.Duration, error) {
	if info.Addr == "" {
		return 0, errors.New("empty relay address")
	}
	startedAt := time.Now()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", info.Addr)
	if err != nil {
		return 0, err
	}
	_ = connection.Close()
	rtt := time.Since(startedAt)
	if rtt <= 0 {
		rtt = time.Nanosecond
	}
	return rtt, nil
}
