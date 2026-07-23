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

	kcpAdapter := &TcpFrameAdapter{}
	tcpAdapter := &TcpFrameAdapter{}
	return &frameRouteQualityHarness{
		dual:       dual,
		kcpLeg:     kcpLeg,
		kcpAdapter: kcpAdapter,
		endpoint: &DualFrameRelayEndpoint{
			stream:        dual,
			adapters:      map[streamTransport]*TcpFrameAdapter{streamTransportKCP: kcpAdapter, streamTransportTCP: tcpAdapter},
			incomingIDs:   make(map[frameEndpointKey]uint64),
			ackIDs:        make(map[frameEndpointKey]uint64),
			routes:        make(map[uint64]*dualFrameRoute),
			slowKCPRoutes: make(map[streamTransport]int),
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
