package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestMuxConnFramingRoundTrip 验证 muxConn 的读写两端：
//   - 写：把多帧拼接的字节写进去，逐帧还原经 writeFn 输出，顺序、内容、connectionId 一致；
//   - 读：把序列化帧推进 incoming，network.ReadFrame 能从 muxConn 完整读回。
func TestMuxConnFramingRoundTrip(t *testing.T) {
	var got []*network.Frame
	var mu sync.Mutex
	c := newMuxConn("conn-A", func(f *network.Frame) error {
		mu.Lock()
		got = append(got, f)
		mu.Unlock()
		return nil
	})

	frames := []*network.Frame{
		{MessageId: 1, SeqId: 0, TotalFrames: 2, FrameType: network.FrameTypeData, ConnectionId: "conn-A", Payload: []byte("hello")},
		{MessageId: 1, SeqId: 1, TotalFrames: 2, FrameType: network.FrameTypeData, ConnectionId: "conn-A", Payload: []byte("world!!")},
		{MessageId: 0, SeqId: 0, TotalFrames: 1, AckId: 864, FrameType: network.FrameTypeFrameSizeChange, ConnectionId: "conn-A"},
	}

	// 写路径：把三帧拼成一次 Write（模拟 writeFrames 批量写）。
	var blob []byte
	for _, f := range frames {
		bs, err := f.ParseToBytes()
		if err != nil {
			t.Fatalf("ParseToBytes: %v", err)
		}
		blob = append(blob, bs...)
	}
	if n, err := c.Write(blob); err != nil || n != len(blob) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != len(frames) {
		t.Fatalf("writeFn 收到 %d 帧, 期望 %d", len(got), len(frames))
	}
	for i, f := range got {
		if f.MessageId != frames[i].MessageId || f.SeqId != frames[i].SeqId ||
			f.FrameType != frames[i].FrameType || f.ConnectionId != frames[i].ConnectionId {
			t.Errorf("帧[%d] 不匹配: got %+v want %+v", i, f, frames[i])
		}
	}

	// 读路径：把一帧序列化推入队列，ReadFrame 应完整读回。
	bs, _ := frames[0].ParseToBytes()
	c.push(bs)
	read, err := network.ReadFrame(c)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if read.ConnectionId != "conn-A" || string(read.Payload) != "hello" {
		t.Errorf("读回帧不匹配: %+v", read)
	}
}

func TestMuxConnUsesVirtualStreamFramePayload(t *testing.T) {
	connection := newMuxConn("frame-payload", func(*network.Frame) error { return nil })
	stream := newTcpStream("peer", "frame-payload", connection)
	t.Cleanup(func() {
		stream.Close()
		connection.Close()
	})
	if got := stream.frameSizeAdaptor.GetFrameSize(); got != endpointMuxFramePayload {
		t.Fatalf("virtual stream frame payload=%d, want %d", got, endpointMuxFramePayload)
	}
}

// TestEndpointMuxDispatch 验证按 connectionId demux：两个 connId 交错的帧分别落到各自 muxConn，
// 且每个新 connId 只回调 onNew 一次。
func TestEndpointMuxDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var newConns []string
	var mu sync.Mutex
	m := &EndpointFrameMux{
		ctx:   ctx,
		dual:  nil,
		conns: make(map[string]*muxConn),
		onNew: func(connId string, conn net.Conn) {
			mu.Lock()
			newConns = append(newConns, connId)
			mu.Unlock()
		},
	}

	mk := func(connId string, seq uint32) *network.Frame {
		return &network.Frame{MessageId: 1, SeqId: seq, TotalFrames: 3, FrameType: network.FrameTypeData, ConnectionId: connId, Payload: []byte("x")}
	}
	// 交错投递: A0, B0, A1, B1, A2, B2
	for seq := uint32(0); seq < 3; seq++ {
		m.dispatch(mk("conn-A", seq))
		m.dispatch(mk("conn-B", seq))
	}

	mu.Lock()
	if len(newConns) != 2 {
		t.Fatalf("onNew 被调 %d 次, 期望 2 (每连接一次): %v", len(newConns), newConns)
	}
	mu.Unlock()

	for _, id := range []string{"conn-A", "conn-B"} {
		c := m.conns[id]
		if c == nil {
			t.Fatalf("connId %s 没有 muxConn", id)
		}
		c.mu.Lock()
		qlen := len(c.queue)
		c.mu.Unlock()
		if qlen != 3 {
			t.Errorf("connId %s 缓冲帧数=%d, 期望 3", id, qlen)
		}
	}
}

func TestEndpointMuxClosedConnectionDropsLateFramesWithoutRecreation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var newConnections int
	mux := &EndpointFrameMux{
		ctx:     ctx,
		conns:   make(map[string]*muxConn),
		inbound: make(map[muxFrameKey]muxInboundRoute),
		retired: make(map[string]time.Time),
		onNew: func(string, net.Conn) {
			newConnections++
		},
	}
	first := &network.Frame{
		MessageId: 1, SeqId: 0, TotalFrames: 2, FrameType: network.FrameTypeData,
		ConnectionId: "closed-session", Payload: []byte("first"),
	}
	mux.dispatch(first)
	mux.CloseConnection(first.ConnectionId)

	for index := 0; index < 1000; index++ {
		frame := *first
		frame.MessageId = uint64(index + 2)
		frame.FrameType = network.FrameTypeRetransmit
		mux.dispatch(&frame)
	}

	if newConnections != 1 {
		t.Fatalf("late retransmits created %d logical connections, want 1", newConnections)
	}
	if mux.conns[first.ConnectionId] != nil {
		t.Fatal("retired connection was recreated")
	}
	if len(mux.inbound) != 0 {
		t.Fatalf("retired connection retained %d inbound routes", len(mux.inbound))
	}
}

func TestEndpointMuxUnknownControlFrameDoesNotCreateConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	newConnections := 0
	mux := &EndpointFrameMux{
		ctx:     ctx,
		conns:   make(map[string]*muxConn),
		inbound: make(map[muxFrameKey]muxInboundRoute),
		retired: make(map[string]time.Time),
		onNew: func(string, net.Conn) {
			newConnections++
		},
	}
	ack, err := network.BuildAckFrame(9, 1, network.FullAckRange(1))
	if err != nil {
		t.Fatalf("BuildAckFrame: %v", err)
	}
	ack.ConnectionId = "unknown-session"
	mux.dispatch(ack)

	if newConnections != 0 || len(mux.conns) != 0 {
		t.Fatalf("unknown ACK created a logical connection: callbacks=%d conns=%d", newConnections, len(mux.conns))
	}
}

func TestEndpointMuxExpiredTombstoneAllowsNewData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	newConnections := 0
	mux := &EndpointFrameMux{
		ctx:     ctx,
		conns:   make(map[string]*muxConn),
		inbound: make(map[muxFrameKey]muxInboundRoute),
		retired: map[string]time.Time{"reused-session": time.Now().Add(-time.Second)},
		onNew: func(string, net.Conn) {
			newConnections++
		},
	}
	mux.dispatch(&network.Frame{
		MessageId: 1, SeqId: 0, TotalFrames: 1, FrameType: network.FrameTypeData,
		ConnectionId: "reused-session",
	})

	if newConnections != 1 || mux.conns["reused-session"] == nil {
		t.Fatalf("expired tombstone blocked new data: callbacks=%d conn=%v", newConnections, mux.conns["reused-session"])
	}
}

func TestEndpointMuxTombstonesRemainBounded(t *testing.T) {
	mux := &EndpointFrameMux{
		conns:   make(map[string]*muxConn),
		inbound: make(map[muxFrameKey]muxInboundRoute),
		retired: make(map[string]time.Time),
	}
	for index := 0; index < endpointMuxTombstoneLimit+32; index++ {
		mux.CloseConnection(string(rune(index + 1)))
	}
	if len(mux.retired) != endpointMuxTombstoneLimit {
		t.Fatalf("tombstone count=%d, want %d", len(mux.retired), endpointMuxTombstoneLimit)
	}
}

func TestEndpointMuxCarrierQualityTrackingReclaimsAcknowledgedRoute(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	adapter := &TcpFrameAdapter{stream: newTcpStream("server", "", local)}
	defer adapter.stream.streamCancel()

	mux := &EndpointFrameMux{
		outbound:   make(map[muxFrameKey]*muxOutboundRoute),
		kcpGoodput: make(map[streamTransport]*frameRelayGoodputState),
	}
	startedAt := time.Unix(1_802_000_000, 0)
	for sequence, size := range []int{100, 200} {
		mux.observeOutboundFrame(adapter, &network.Frame{
			MessageId: 7, SeqId: uint32(sequence), TotalFrames: 2, FrameType: network.FrameTypeData,
			ConnectionId: "tracked-session", Payload: make([]byte, size),
		}, startedAt)
	}

	partial, err := network.BuildAckFrame(7, 2, []network.AckRange{{Start: 0, End: 0}})
	if err != nil {
		t.Fatalf("BuildAckFrame partial: %v", err)
	}
	partial.ConnectionId = "tracked-session"
	mux.mu.Lock()
	mux.observeOutboundAckLocked(partial, startedAt.Add(time.Second))
	mux.observeOutboundAckLocked(partial, startedAt.Add(time.Second))
	state := mux.kcpGoodput[streamTransportKCP]
	mux.mu.Unlock()
	if state == nil || state.windowAcked != 100 || state.outstanding != 200 {
		t.Fatalf("partial ACK state=%+v", state)
	}

	full, err := network.BuildAckFrame(7, 2, network.FullAckRange(2))
	if err != nil {
		t.Fatalf("BuildAckFrame full: %v", err)
	}
	full.ConnectionId = "tracked-session"
	mux.mu.Lock()
	mux.observeOutboundAckLocked(full, startedAt.Add(2*time.Second))
	remainingRoutes := len(mux.outbound)
	trackedFrames := mux.outboundFrames
	outstanding := mux.kcpGoodput[streamTransportKCP].outstanding
	mux.mu.Unlock()
	if remainingRoutes != 0 || trackedFrames != 0 || outstanding != 0 {
		t.Fatalf("completed route retained routes=%d frames=%d outstanding=%d", remainingRoutes, trackedFrames, outstanding)
	}
}

func TestEndpointMuxCarrierQualityTrackingReclaimsClosedSession(t *testing.T) {
	mux := &EndpointFrameMux{
		conns:      make(map[string]*muxConn),
		inbound:    make(map[muxFrameKey]muxInboundRoute),
		outbound:   make(map[muxFrameKey]*muxOutboundRoute),
		retired:    make(map[string]time.Time),
		kcpGoodput: make(map[streamTransport]*frameRelayGoodputState),
	}
	key := muxFrameKey{connectionID: "closed-session", messageID: 9}
	mux.outbound[key] = &muxOutboundRoute{
		kind:         streamTransportKCP,
		payloadBySeq: map[uint32]int{0: 100, 1: 200},
		sentBytes:    300,
	}
	mux.outboundFrames = 2
	mux.kcpGoodput[streamTransportKCP] = &frameRelayGoodputState{outstanding: 300}

	mux.CloseConnection(key.connectionID)

	if len(mux.outbound) != 0 || mux.outboundFrames != 0 ||
		mux.kcpGoodput[streamTransportKCP].outstanding != 0 {
		t.Fatalf("closed session retained routes=%d frames=%d state=%+v",
			len(mux.outbound), mux.outboundFrames, mux.kcpGoodput[streamTransportKCP])
	}
}

func TestEndpointMuxReturnsAckOnInboundCarrierLeg(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstLocal, firstRemote := net.Pipe()
	defer firstLocal.Close()
	defer firstRemote.Close()
	secondLocal, secondRemote := net.Pipe()
	defer secondLocal.Close()
	defer secondRemote.Close()

	first := &TcpFrameAdapter{stream: newTcpStream("server", "", firstLocal)}
	second := &TcpFrameAdapter{stream: newTcpStream("server", "", secondLocal)}
	mux := &EndpointFrameMux{
		ctx:        ctx,
		adapters:   []*TcpFrameAdapter{first, second},
		adapterSet: map[*TcpStream]struct{}{first.stream: {}, second.stream: {}},
		conns:      make(map[string]*muxConn),
		inbound:    make(map[muxFrameKey]muxInboundRoute),
		onNew:      func(string, net.Conn) {},
	}

	incoming := &network.Frame{
		MessageId: 17, SeqId: 0, TotalFrames: 1, FrameType: network.FrameTypeData,
		ConnectionId: "service-session",
	}
	mux.dispatchFromAdapter(second, incoming)
	ack, err := network.BuildAckFrame(incoming.MessageId, incoming.TotalFrames, network.FullAckRange(incoming.TotalFrames))
	if err != nil {
		t.Fatalf("BuildAckFrame: %v", err)
	}
	ack.ConnectionId = incoming.ConnectionId

	read := make(chan *network.Frame, 1)
	go func() {
		frame, _ := network.ReadFrame(secondRemote)
		read <- frame
	}()
	mux.writeFrame(ack)
	got := <-read
	if got == nil || got.FrameType != network.FrameTypeAck || got.MessageId != incoming.MessageId {
		t.Fatalf("inbound carrier ACK = %+v", got)
	}
	if len(mux.inbound) != 0 {
		t.Fatalf("completed ACK retained %d inbound routes", len(mux.inbound))
	}
}

func TestEndpointMuxSourceLimitedCarrierDoesNotTriggerFallback(t *testing.T) {
	startedAt := time.Unix(1_801_400_000, 0)
	windowBytes := int64(defaultKCPGoodputBytesPerSecond / 2 * int64(frameRelayGoodputWindow/time.Second))
	mux := &EndpointFrameMux{
		kcpGoodput: map[streamTransport]*frameRelayGoodputState{
			streamTransportKCP: {
				windowStarted: startedAt,
				windowSent:    windowBytes,
				windowAcked:   windowBytes,
			},
		},
	}

	mux.mu.Lock()
	first := mux.evaluateCarrierGoodputLocked(startedAt.Add(frameRelayGoodputWindow))
	state := mux.kcpGoodput[streamTransportKCP]
	state.windowSent = windowBytes
	state.windowAcked = windowBytes
	second := mux.evaluateCarrierGoodputLocked(startedAt.Add(2 * frameRelayGoodputWindow))
	mux.mu.Unlock()

	if len(first) != 0 || len(second) != 0 {
		t.Fatalf("fully acknowledged source-limited carrier triggered fallback: first=%v second=%v", first, second)
	}
	if state.lowWindowStreak != 0 || state.outstanding != 0 {
		t.Fatalf("source-limited carrier state=%+v", state)
	}
}

func TestEndpointMuxIdleWindowWithCarriedOutstandingDoesNotTriggerFallback(t *testing.T) {
	startedAt := time.Unix(1_801_450_000, 0)
	state := &frameRelayGoodputState{
		windowStarted:   startedAt,
		outstanding:     int64(defaultKCPGoodputMinPayload),
		lowWindowStreak: 1,
	}
	mux := &EndpointFrameMux{
		kcpGoodput: map[streamTransport]*frameRelayGoodputState{
			streamTransportKCP: state,
		},
	}

	mux.mu.Lock()
	decisions := mux.evaluateCarrierGoodputLocked(startedAt.Add(frameRelayGoodputWindow))
	mux.mu.Unlock()

	if len(decisions) != 0 {
		t.Fatalf("idle carrier window triggered fallback: %+v", decisions)
	}
	if state.lowWindowStreak != 0 {
		t.Fatalf("idle carrier window retained low streak=%d", state.lowWindowStreak)
	}
}

// 编译期确保 muxConn 实现 net.Conn。
var _ net.Conn = (*muxConn)(nil)
