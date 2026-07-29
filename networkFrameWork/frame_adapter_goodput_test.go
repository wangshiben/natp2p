package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"testing"
	"time"
)

type frameRouteQualityTestStream struct {
	closed bool
}

func (stream *frameRouteQualityTestStream) Close() error {
	stream.closed = true
	return nil
}

func (*frameRouteQualityTestStream) NextMessage(context.Context) (*network.Message, error) {
	return nil, errors.New("unused")
}

func (*frameRouteQualityTestStream) SendMessage(context.Context, *network.Message) error {
	return nil
}

func (*frameRouteQualityTestStream) SendMessageAsync(context.Context, *network.Message, network.MessageResultCallback) error {
	return nil
}

func (*frameRouteQualityTestStream) NodeId() string {
	return "quality-peer"
}

func (*frameRouteQualityTestStream) ConnectionId() string {
	return "quality-connection"
}

func (*frameRouteQualityTestStream) SetCryptoSuite(network.EncrypSuite) {}

type frameRouteQualityHarness struct {
	dual       *DualStream
	endpoint   *DualFrameRelayEndpoint
	kcpLeg     *frameRouteQualityTestStream
	kcpAdapter *TcpFrameAdapter
	tcpAdapter *TcpFrameAdapter
}

func newFrameRouteQualityHarness(t *testing.T) *frameRouteQualityHarness {
	t.Helper()
	dual := newDualStreamWithPump("quality-peer", "quality-connection", false)
	kcpLeg := &frameRouteQualityTestStream{}
	tcpLeg := &frameRouteQualityTestStream{}
	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatalf("attach KCP: %v", err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatalf("attach TCP: %v", err)
	}
	t.Cleanup(func() { _ = dual.Close() })

	kcpStream := newTcpStream("quality-peer", "quality-connection", nil)
	tcpStream := newTcpStream("quality-peer", "quality-connection", nil)
	t.Cleanup(func() {
		kcpStream.streamCancel()
		tcpStream.streamCancel()
	})
	kcpAdapter := &TcpFrameAdapter{stream: kcpStream}
	tcpAdapter := &TcpFrameAdapter{stream: tcpStream}
	return &frameRouteQualityHarness{
		dual:       dual,
		kcpLeg:     kcpLeg,
		kcpAdapter: kcpAdapter,
		tcpAdapter: tcpAdapter,
		endpoint: &DualFrameRelayEndpoint{
			stream:        dual,
			adapters:      map[streamTransport]*TcpFrameAdapter{streamTransportKCP: kcpAdapter, streamTransportTCP: tcpAdapter},
			incomingIDs:   make(map[frameEndpointKey]uint64),
			ackIDs:        make(map[frameEndpointKey]uint64),
			routes:        make(map[uint64]*dualFrameRoute),
			slowKCPRoutes: make(map[streamTransport]int),
			kcpGoodput:    make(map[streamTransport]*frameRelayGoodputState),
			maxBytes:      defaultFrameRelayMaxCachedBytes,
			maxRouteBytes: defaultFrameRelayMaxRouteCachedBytes,
			maxRoutes:     defaultFrameRelayMaxRoutes,
		},
	}
}

func frameRouteQualityBudget(t *testing.T, payloadBytes int) time.Duration {
	t.Helper()
	budget, enabled := defaultKCPSendQualityPolicy().budget(payloadBytes)
	if !enabled {
		t.Fatalf("payload %d did not receive a quality budget", payloadBytes)
	}
	return budget
}

func completeFrameRouteQuality(
	t *testing.T,
	harness *frameRouteQualityHarness,
	payloadBytes int,
	createdAt time.Time,
	completedAt time.Time,
	source bool,
) (*dualFrameRoute, streamTransport) {
	t.Helper()
	route := &dualFrameRoute{
		kind:        streamTransportKCP,
		endpoint:    harness.kcpAdapter,
		totalFrames: 1,
		framesBySeq: make(map[uint32]*network.Frame),
		ackKeys:     make(map[frameEndpointKey]struct{}),
		createdAt:   createdAt,
		lastActive:  createdAt,
		generation:  1,
	}
	if source {
		sourceKey := frameEndpointKey{kind: streamTransportKCP, adapter: harness.kcpAdapter, messageID: 1}
		route.sourceKey = &sourceKey
	}
	frame := &network.Frame{
		MessageId:    1,
		TotalFrames:  1,
		FrameType:    network.FrameTypeData,
		ConnectionId: "quality-connection",
		Payload:      make([]byte, payloadBytes),
	}
	harness.endpoint.mu.Lock()
	if harness.endpoint.cacheFrameLocked(route, frame) {
		harness.endpoint.mu.Unlock()
		t.Fatal("quality test route unexpectedly exceeded its replay cache")
	}
	preferred := harness.endpoint.completeRouteLocked(route, completedAt)
	harness.endpoint.mu.Unlock()
	if preferred != streamTransportUnknown {
		harness.dual.setPreferred(preferred)
	}
	return route, preferred
}

func TestDualFrameRelayConsecutiveSlowKCPRoutesPreferTCPWithoutClosingKCP(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	const payloadBytes = 64 * 1024
	completedAt := time.Unix(1_800_000_000, 0)
	budget := frameRouteQualityBudget(t, payloadBytes)

	first, preferred := completeFrameRouteQuality(t, harness, payloadBytes, completedAt.Add(-budget-time.Millisecond), completedAt, false)
	if preferred != streamTransportUnknown || harness.dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("first slow route preferred=%s stream=%s", preferred, harness.dual.preferredTransport())
	}
	if first.framesBySeq != nil || first.payloadBytes != 0 {
		t.Fatal("completed slow route retained replay or quality payload")
	}

	_, preferred = completeFrameRouteQuality(t, harness, payloadBytes, completedAt.Add(-budget-time.Millisecond), completedAt, false)
	if preferred != streamTransportTCP || harness.dual.preferredTransport() != streamTransportTCP {
		t.Fatalf("second slow route preferred=%s stream=%s", preferred, harness.dual.preferredTransport())
	}
	harness.dual.mu.RLock()
	kcpAttached := harness.dual.streamLocked(streamTransportKCP) == harness.kcpLeg
	harness.dual.mu.RUnlock()
	if !kcpAttached || harness.kcpLeg.closed {
		t.Fatalf("quality demotion removed KCP: attached=%v closed=%v", kcpAttached, harness.kcpLeg.closed)
	}
}

func TestDualFrameRelayFastKCPRouteResetsSlowStreak(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	const payloadBytes = 64 * 1024
	completedAt := time.Unix(1_800_100_000, 0)
	budget := frameRouteQualityBudget(t, payloadBytes)
	slowStart := completedAt.Add(-budget - time.Millisecond)
	fastStart := completedAt.Add(-budget + time.Millisecond)

	completeFrameRouteQuality(t, harness, payloadBytes, slowStart, completedAt, false)
	completeFrameRouteQuality(t, harness, payloadBytes, fastStart, completedAt, false)
	_, preferred := completeFrameRouteQuality(t, harness, payloadBytes, slowStart, completedAt, false)
	if preferred != streamTransportUnknown || harness.dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("slow-fast-slow sequence demoted KCP: preferred=%s stream=%s", preferred, harness.dual.preferredTransport())
	}
	_, preferred = completeFrameRouteQuality(t, harness, payloadBytes, slowStart, completedAt, false)
	if preferred != streamTransportTCP {
		t.Fatalf("two slow routes after reset preferred=%s, want TCP", preferred)
	}
}

func TestDualFrameRelaySmallRouteDoesNotResetSlowStreak(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	const payloadBytes = 64 * 1024
	completedAt := time.Unix(1_800_200_000, 0)
	budget := frameRouteQualityBudget(t, payloadBytes)
	slowStart := completedAt.Add(-budget - time.Millisecond)

	completeFrameRouteQuality(t, harness, payloadBytes, slowStart, completedAt, false)
	_, preferred := completeFrameRouteQuality(t, harness, payloadBytes-1, completedAt.Add(-time.Hour), completedAt, false)
	if preferred != streamTransportUnknown || harness.dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("small route changed preference: preferred=%s stream=%s", preferred, harness.dual.preferredTransport())
	}
	_, preferred = completeFrameRouteQuality(t, harness, payloadBytes, slowStart, completedAt, false)
	if preferred != streamTransportTCP {
		t.Fatalf("small route reset slow streak: preferred=%s", preferred)
	}
}

func TestDualFrameRelaySourceRouteDoesNotCountAsSlowDestination(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	const payloadBytes = 64 * 1024
	completedAt := time.Unix(1_800_300_000, 0)
	budget := frameRouteQualityBudget(t, payloadBytes)
	slowStart := completedAt.Add(-budget - time.Millisecond)

	_, preferred := completeFrameRouteQuality(t, harness, payloadBytes, slowStart, completedAt, true)
	if preferred != streamTransportUnknown {
		t.Fatalf("source route preferred=%s, want no observation", preferred)
	}
	_, preferred = completeFrameRouteQuality(t, harness, payloadBytes, slowStart, completedAt, false)
	if preferred != streamTransportUnknown || harness.dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("source route incremented destination streak: preferred=%s stream=%s", preferred, harness.dual.preferredTransport())
	}
	_, preferred = completeFrameRouteQuality(t, harness, payloadBytes, slowStart, completedAt, false)
	if preferred != streamTransportTCP {
		t.Fatalf("two outbound slow routes preferred=%s, want TCP", preferred)
	}
}

func TestDualFrameRelayRepeatedFullACKCountsRouteOnce(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	const payloadBytes = 64 * 1024
	completedAt := time.Unix(1_800_400_000, 0)
	budget := frameRouteQualityBudget(t, payloadBytes)
	route, preferred := completeFrameRouteQuality(t, harness, payloadBytes, completedAt.Add(-budget-time.Millisecond), completedAt, false)
	if preferred != streamTransportUnknown {
		t.Fatalf("first route preferred=%s", preferred)
	}

	harness.endpoint.mu.Lock()
	preferred = harness.endpoint.completeRouteLocked(route, completedAt.Add(time.Second))
	harness.endpoint.mu.Unlock()
	if preferred != streamTransportUnknown || harness.dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("repeated ACK counted twice: preferred=%s stream=%s", preferred, harness.dual.preferredTransport())
	}
	_, preferred = completeFrameRouteQuality(t, harness, payloadBytes, completedAt.Add(-budget-time.Millisecond), completedAt, false)
	if preferred != streamTransportTCP {
		t.Fatalf("second distinct slow route preferred=%s, want TCP", preferred)
	}
}

func TestFrameAckPayloadBytesUsesConfirmedPayload(t *testing.T) {
	frames := map[uint32]*network.Frame{
		0: {SeqId: 0, Payload: make([]byte, 100)},
		1: {SeqId: 1, Payload: make([]byte, 200)},
		2: {SeqId: 2, Payload: make([]byte, 300)},
	}
	ack, err := network.BuildAckFrame(1, 3, []network.AckRange{{Start: 0, End: 1}})
	if err != nil {
		t.Fatalf("BuildAckFrame: %v", err)
	}
	ackedBytes, valid := frameAckPayloadBytes(ack, 3, frames)
	if !valid || ackedBytes != 300 {
		t.Fatalf("confirmed payload = (%d, %v), want (300, true)", ackedBytes, valid)
	}
}

func TestAcknowledgeFramePayloadCountsOnlyNewCumulativeRange(t *testing.T) {
	const totalFrames = 1000
	progress := &frameAckProgress{}
	lookups := 0
	payloadSize := func(uint32) (int, bool) {
		lookups++
		return 1, true
	}
	first, err := network.BuildAckFrame(1, totalFrames, []network.AckRange{{Start: 0, End: 899}})
	if err != nil {
		t.Fatalf("BuildAckFrame first: %v", err)
	}
	bytes, frames, valid := acknowledgeFramePayload(first, totalFrames, progress, payloadSize)
	if !valid || bytes != 900 || frames != 900 || lookups != 900 {
		t.Fatalf("first progress=(%d bytes, %d frames, valid=%v, lookups=%d)", bytes, frames, valid, lookups)
	}

	lookups = 0
	second, err := network.BuildAckFrame(1, totalFrames, network.FullAckRange(totalFrames))
	if err != nil {
		t.Fatalf("BuildAckFrame second: %v", err)
	}
	bytes, frames, valid = acknowledgeFramePayload(second, totalFrames, progress, payloadSize)
	if !valid || bytes != 100 || frames != 100 || lookups != 100 {
		t.Fatalf("incremental progress=(%d bytes, %d frames, valid=%v, lookups=%d)", bytes, frames, valid, lookups)
	}

	lookups = 0
	bytes, frames, valid = acknowledgeFramePayload(second, totalFrames, progress, payloadSize)
	if !valid || bytes != 0 || frames != 0 || lookups != 0 {
		t.Fatalf("duplicate progress=(%d bytes, %d frames, valid=%v, lookups=%d)", bytes, frames, valid, lookups)
	}
}

func TestDualFrameRelaySustainedLowKCPGoodputRequiresTwoWindows(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	route := &dualFrameRoute{kind: streamTransportKCP}
	startedAt := time.Unix(1_801_000_000, 0)
	windowBytes := int64(defaultKCPGoodputBytesPerSecond / 2 * int64(frameRelayGoodputWindow/time.Second))

	harness.endpoint.mu.Lock()
	harness.endpoint.observeKCPDataSentLocked(route, windowBytes, startedAt)
	harness.endpoint.observeKCPDataAckedLocked(route, windowBytes/2, startedAt.Add(frameRelayGoodputWindow))
	first := harness.endpoint.observeKCPGoodputWindowsLocked(startedAt.Add(frameRelayGoodputWindow), streamTransportTCP)
	harness.endpoint.observeKCPDataSentLocked(route, windowBytes, startedAt.Add(frameRelayGoodputWindow))
	harness.endpoint.observeKCPDataAckedLocked(route, windowBytes/2, startedAt.Add(2*frameRelayGoodputWindow))
	second := harness.endpoint.observeKCPGoodputWindowsLocked(startedAt.Add(2*frameRelayGoodputWindow), streamTransportTCP)
	harness.endpoint.mu.Unlock()

	if len(first) != 0 {
		t.Fatalf("one low window triggered %d decisions", len(first))
	}
	if len(second) != 1 || second[0].kcpKind != streamTransportKCP || second[0].tcpKind != streamTransportTCP {
		t.Fatalf("second low window decisions=%+v", second)
	}
	if second[0].goodput >= defaultKCPGoodputBytesPerSecond {
		t.Fatalf("reported low goodput=%d, threshold=%d", second[0].goodput, defaultKCPGoodputBytesPerSecond)
	}
}

func TestDualFrameRelaySourceLimitedKCPDoesNotTriggerFallback(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	route := &dualFrameRoute{kind: streamTransportKCP}
	startedAt := time.Unix(1_801_050_000, 0)
	windowBytes := int64(defaultKCPGoodputBytesPerSecond / 2 * int64(frameRelayGoodputWindow/time.Second))

	harness.endpoint.mu.Lock()
	harness.endpoint.observeKCPDataSentLocked(route, windowBytes, startedAt)
	harness.endpoint.observeKCPDataAckedLocked(route, windowBytes, startedAt)
	first := harness.endpoint.observeKCPGoodputWindowsLocked(
		startedAt.Add(frameRelayGoodputWindow), streamTransportTCP,
	)
	harness.endpoint.observeKCPDataSentLocked(route, windowBytes, startedAt.Add(frameRelayGoodputWindow))
	harness.endpoint.observeKCPDataAckedLocked(route, windowBytes, startedAt.Add(2*frameRelayGoodputWindow))
	second := harness.endpoint.observeKCPGoodputWindowsLocked(
		startedAt.Add(2*frameRelayGoodputWindow), streamTransportTCP,
	)
	state := harness.endpoint.kcpGoodput[streamTransportKCP]
	harness.endpoint.mu.Unlock()

	if len(first) != 0 || len(second) != 0 {
		t.Fatalf("fully acknowledged source-limited windows triggered fallback: first=%v second=%v", first, second)
	}
	if state == nil || state.lowWindowStreak != 0 || state.outstanding != 0 {
		t.Fatalf("source-limited state=%+v", state)
	}
}

func TestDualFrameRelayIdleWindowWithCarriedOutstandingDoesNotTriggerFallback(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	startedAt := time.Unix(1_801_075_000, 0)
	state := &frameRelayGoodputState{
		windowStarted:   startedAt,
		outstanding:     int64(defaultKCPGoodputMinPayload),
		lowWindowStreak: 1,
	}

	harness.endpoint.mu.Lock()
	harness.endpoint.kcpGoodput[streamTransportKCP] = state
	decisions := harness.endpoint.observeKCPGoodputWindowsLocked(
		startedAt.Add(frameRelayGoodputWindow), streamTransportTCP,
	)
	harness.endpoint.mu.Unlock()

	if len(decisions) != 0 {
		t.Fatalf("idle window with carried outstanding triggered fallback: %+v", decisions)
	}
	if state.lowWindowStreak != 0 {
		t.Fatalf("idle window retained low streak=%d", state.lowWindowStreak)
	}
}

func TestDualFrameRelayHealthyKCPWindowResetsLowStreak(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	route := &dualFrameRoute{kind: streamTransportKCP}
	startedAt := time.Unix(1_801_100_000, 0)
	slowBytes := int64(defaultKCPGoodputBytesPerSecond / 2 * int64(frameRelayGoodputWindow/time.Second))
	fastBytes := int64(defaultKCPGoodputBytesPerSecond * int64(frameRelayGoodputWindow/time.Second))

	harness.endpoint.mu.Lock()
	harness.endpoint.observeKCPDataSentLocked(route, slowBytes, startedAt)
	harness.endpoint.observeKCPDataAckedLocked(route, slowBytes/2, startedAt)
	first := harness.endpoint.observeKCPGoodputWindowsLocked(startedAt.Add(frameRelayGoodputWindow), streamTransportTCP)
	harness.endpoint.observeKCPDataSentLocked(route, fastBytes, startedAt.Add(frameRelayGoodputWindow))
	harness.endpoint.observeKCPDataAckedLocked(route, fastBytes, startedAt.Add(frameRelayGoodputWindow))
	healthy := harness.endpoint.observeKCPGoodputWindowsLocked(startedAt.Add(2*frameRelayGoodputWindow), streamTransportTCP)
	harness.endpoint.observeKCPDataSentLocked(route, slowBytes, startedAt.Add(2*frameRelayGoodputWindow))
	harness.endpoint.observeKCPDataAckedLocked(route, slowBytes/2, startedAt.Add(2*frameRelayGoodputWindow))
	afterReset := harness.endpoint.observeKCPGoodputWindowsLocked(startedAt.Add(3*frameRelayGoodputWindow), streamTransportTCP)
	harness.endpoint.mu.Unlock()

	if len(first) != 0 || len(healthy) != 0 || len(afterReset) != 0 {
		t.Fatalf("slow/healthy/slow sequence triggered decisions: first=%v healthy=%v after=%v", first, healthy, afterReset)
	}
}

func TestDualFrameRelayLowGoodputRebindsActiveRouteAndStartsCooldown(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	const logicalID = 77
	startedAt := time.Unix(1_801_200_000, 0)
	route := &dualFrameRoute{
		kind:        streamTransportKCP,
		connId:      "low-goodput-session",
		endpoint:    harness.kcpAdapter,
		dstID:       1,
		totalFrames: 2,
		framesBySeq: make(map[uint32]*network.Frame),
		ackKeys:     make(map[frameEndpointKey]struct{}),
		createdAt:   startedAt,
		lastActive:  startedAt,
		generation:  1,
	}
	frames := []*network.Frame{
		{MessageId: logicalID, SeqId: 0, TotalFrames: 2, FrameType: network.FrameTypeData, Payload: make([]byte, 128<<10)},
		{MessageId: logicalID, SeqId: 1, TotalFrames: 2, FrameType: network.FrameTypeData, Payload: make([]byte, 128<<10)},
	}

	harness.endpoint.mu.Lock()
	harness.endpoint.routes[logicalID] = route
	harness.endpoint.bindAckKeyLocked(logicalID, route, streamTransportKCP, harness.kcpAdapter, route.dstID)
	for _, frame := range frames {
		harness.endpoint.cacheFrameLocked(route, frame)
	}
	windowBytes := int64(defaultKCPGoodputBytesPerSecond / 2 * int64(frameRelayGoodputWindow/time.Second))
	harness.endpoint.observeKCPDataSentLocked(route, windowBytes, startedAt)
	harness.endpoint.observeKCPDataAckedLocked(route, windowBytes/2, startedAt)
	firstJobs, firstDecisions, firstUnavailable := harness.endpoint.prepareQualityReplayLocked(startedAt.Add(frameRelayGoodputWindow))
	harness.endpoint.observeKCPDataSentLocked(route, windowBytes, startedAt.Add(frameRelayGoodputWindow))
	harness.endpoint.observeKCPDataAckedLocked(route, windowBytes/2, startedAt.Add(frameRelayGoodputWindow))
	jobs, decisions, unavailable := harness.endpoint.prepareQualityReplayLocked(startedAt.Add(2 * frameRelayGoodputWindow))
	harness.endpoint.mu.Unlock()

	if len(firstJobs) != 0 || len(firstDecisions) != 0 || firstUnavailable != 0 {
		t.Fatalf("first window replay=(%d jobs, %d decisions, unavailable=%d)", len(firstJobs), len(firstDecisions), firstUnavailable)
	}
	if unavailable != 0 || len(decisions) != 1 || len(jobs) != 1 {
		t.Fatalf("low-goodput replay=(%d jobs, %d decisions, unavailable=%d)", len(jobs), len(decisions), unavailable)
	}
	if jobs[0].reason != "low-goodput" || len(jobs[0].frames) != len(frames) {
		t.Fatalf("replay job=%+v", jobs[0])
	}
	if route.kind != streamTransportTCP || route.endpoint != harness.tcpAdapter {
		t.Fatalf("route remained on %s/%p", route.kind, route.endpoint)
	}
	if !harness.endpoint.kcpCooldown.After(startedAt.Add(2 * frameRelayGoodputWindow)) {
		t.Fatalf("cooldown not started: %v", harness.endpoint.kcpCooldown)
	}
}

func TestDualFrameRelayAckProgressFeedsGoodputOnlyOnce(t *testing.T) {
	harness := newFrameRouteQualityHarness(t)
	startedAt := time.Unix(1_801_300_000, 0)
	route := &dualFrameRoute{
		kind:        streamTransportKCP,
		totalFrames: 3,
		framesBySeq: map[uint32]*network.Frame{
			0: {SeqId: 0, Payload: make([]byte, 100)},
			1: {SeqId: 1, Payload: make([]byte, 200)},
			2: {SeqId: 2, Payload: make([]byte, 300)},
		},
	}
	ack, err := network.BuildAckFrame(1, 3, []network.AckRange{{Start: 0, End: 1}})
	if err != nil {
		t.Fatalf("BuildAckFrame: %v", err)
	}

	harness.endpoint.mu.Lock()
	harness.endpoint.observeKCPDataSentLocked(route, 600, startedAt)
	harness.endpoint.observeAckProgressLocked(route, ack, startedAt.Add(time.Second))
	harness.endpoint.observeAckProgressLocked(route, ack, startedAt.Add(2*time.Second))
	state := harness.endpoint.kcpGoodput[streamTransportKCP]
	harness.endpoint.mu.Unlock()

	if route.ackedBytes != 300 || route.ackedFrames != 2 {
		t.Fatalf("route ACK progress = %d bytes/%d frames", route.ackedBytes, route.ackedFrames)
	}
	if state == nil || state.windowAcked != 300 || state.outstanding != 300 {
		t.Fatalf("goodput state=%+v", state)
	}
}
