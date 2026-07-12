package DHTable

import (
	"bnfs_p2p/interfaces"
	"sort"
	"time"
)

type rankedNode struct {
	node      interfaces.Node
	health    interfaces.NodeHealth
	rttBand   int64
	stableAge time.Duration
}

func defaultNodeHealth(now time.Time) interfaces.NodeHealth {
	return interfaces.NodeHealth{
		ContinuousHealthySince: now,
		LastSuccess:            now,
	}
}

func normalizeRankingPolicy(policy interfaces.NodeRankingPolicy) interfaces.NodeRankingPolicy {
	if policy.Now.IsZero() {
		policy.Now = time.Now()
	}
	if policy.RTTBandMin <= 0 {
		policy.RTTBandMin = 10 * time.Millisecond
	}
	if policy.RTTBandRatio <= 0 {
		policy.RTTBandRatio = 0.10
	}
	return policy
}

func rankNodeSnapshot(nodes []interfaces.Node, health map[string]interfaces.NodeHealth, policy interfaces.NodeRankingPolicy) []interfaces.Node {
	policy = normalizeRankingPolicy(policy)
	bestRTT := time.Duration(0)
	for _, node := range nodes {
		entry := health[node.PeerID()]
		if entry.RTT > 0 && (bestRTT == 0 || entry.RTT < bestRTT) {
			bestRTT = entry.RTT
		}
	}
	bandWidth := policy.RTTBandMin
	if proportional := time.Duration(float64(bestRTT) * policy.RTTBandRatio); proportional > bandWidth {
		bandWidth = proportional
	}
	if bandWidth <= 0 {
		bandWidth = time.Millisecond
	}

	ranked := make([]rankedNode, 0, len(nodes))
	for _, node := range nodes {
		entry := health[node.PeerID()]
		band := int64(^uint64(0) >> 1)
		if entry.RTT > 0 && bestRTT > 0 {
			band = int64((entry.RTT - bestRTT) / bandWidth)
		}
		stableAge := time.Duration(0)
		if !entry.ContinuousHealthySince.IsZero() && !entry.ContinuousHealthySince.After(policy.Now) {
			stableAge = policy.Now.Sub(entry.ContinuousHealthySince)
		}
		ranked = append(ranked, rankedNode{node: node, health: entry, rttBand: band, stableAge: stableAge})
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		left, right := ranked[i], ranked[j]
		if left.health.Suspect != right.health.Suspect {
			return !left.health.Suspect
		}
		if left.rttBand != right.rttBand {
			return left.rttBand < right.rttBand
		}
		if left.stableAge != right.stableAge {
			return left.stableAge > right.stableAge
		}
		if left.health.ConsecutiveFailures != right.health.ConsecutiveFailures {
			return left.health.ConsecutiveFailures < right.health.ConsecutiveFailures
		}
		if left.health.RTT != right.health.RTT {
			if left.health.RTT == 0 {
				return false
			}
			if right.health.RTT == 0 {
				return true
			}
			return left.health.RTT < right.health.RTT
		}
		return left.node.PeerID() < right.node.PeerID()
	})

	result := make([]interfaces.Node, len(ranked))
	for i := range ranked {
		result[i] = ranked[i].node
	}
	return result
}
