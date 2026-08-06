package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
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

func TestEndpointMuxControlFramesBypassDataBacklog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := &EndpointFrameMux{
		ctx:       ctx,
		outCh:     make(chan *network.Frame, 1),
		controlCh: make(chan *network.Frame, 1),
	}
	data := &network.Frame{FrameType: network.FrameTypeData, ConnectionId: "data"}
	mux.outCh <- data
	ack := &network.Frame{FrameType: network.FrameTypeAck, ConnectionId: "control"}
	if err := mux.writeSharedContext(ctx, ack); err != nil {
		t.Fatalf("enqueue control frame: %v", err)
	}
	select {
	case got := <-mux.controlCh:
		if got != ack {
			t.Fatalf("control queue frame=%p, want %p", got, ack)
		}
	default:
		t.Fatal("control frame was blocked behind data queue")
	}
	if got := <-mux.outCh; got != data {
		t.Fatalf("data queue frame=%p, want %p", got, data)
	}
}

func endpointMuxKeepAliveTestFrame(t *testing.T) *network.Frame {
	t.Helper()
	message := &network.Message{
		Header: &network.Header{RouteName: KeepAliveRoute, NodeId: "peer", ConnectionId: "conn"},
	}
	payload, err := message.ParseToBytes()
	if err != nil {
		t.Fatalf("encode keepalive: %v", err)
	}
	return &network.Frame{
		MessageId:    1,
		SeqId:        0,
		TotalFrames:  1,
		FrameType:    network.FrameTypeData,
		ConnectionId: "conn",
		Payload:      payload,
	}
}

func TestEndpointMuxRecognizesBoundedLogicalKeepAliveAsControl(t *testing.T) {
	frame := endpointMuxKeepAliveTestFrame(t)
	if !endpointMuxControlFrame(frame) {
		t.Fatal("logical keepalive was not classified as control traffic")
	}
	frame.Payload = append(frame.Payload, make([]byte, endpointMuxKeepAliveMaxPayload)...)
	if endpointMuxControlFrame(frame) {
		t.Fatal("oversized route lookalike bypassed the data queue")
	}
}

func TestEndpointMuxIncidentBatchKeepAlivesBypassFullDataQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := &EndpointFrameMux{
		ctx:       ctx,
		outCh:     make(chan *network.Frame, 1024),
		controlCh: make(chan *network.Frame, 129),
	}
	for index := 0; index < cap(mux.outCh); index++ {
		mux.outCh <- &network.Frame{FrameType: network.FrameTypeData, ConnectionId: "bulk"}
	}
	for index := 0; index < cap(mux.controlCh); index++ {
		frame := endpointMuxKeepAliveTestFrame(t)
		frame.MessageId = uint64(index + 1)
		if err := mux.writeSharedContext(ctx, frame); err != nil {
			t.Fatalf("enqueue keepalive %d: %v", index, err)
		}
	}
	if got := len(mux.controlCh); got != 129 {
		t.Fatalf("control queue depth=%d, want 129 incident probes", got)
	}
	if got := len(mux.outCh); got != cap(mux.outCh) {
		t.Fatalf("data queue depth=%d, want full backlog %d", got, cap(mux.outCh))
	}
}

func TestEndpointMuxControlBurstStillServicesData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := &EndpointFrameMux{
		ctx:       ctx,
		outCh:     make(chan *network.Frame, 1),
		controlCh: make(chan *network.Frame, endpointMuxMaxControlBurst+1),
	}
	data := &network.Frame{FrameType: network.FrameTypeData, ConnectionId: "data"}
	mux.outCh <- data
	for index := 0; index < cap(mux.controlCh); index++ {
		mux.controlCh <- &network.Frame{FrameType: network.FrameTypeAck, ConnectionId: "control"}
	}
	for index := 0; index < endpointMuxMaxControlBurst; index++ {
		frame, ok := mux.nextOutboundFrame()
		if !ok || frame == data {
			t.Fatalf("frame %d did not honor control burst", index)
		}
	}
	frame, ok := mux.nextOutboundFrame()
	if !ok || frame != data {
		t.Fatalf("frame after control burst=%p ok=%t, want data %p", frame, ok, data)
	}
}

func TestEndpointMuxSnapshotReportsBothQueueClasses(t *testing.T) {
	mux := &EndpointFrameMux{
		outCh:     make(chan *network.Frame, 4),
		controlCh: make(chan *network.Frame, 3),
	}
	mux.outCh <- &network.Frame{FrameType: network.FrameTypeData}
	mux.controlCh <- &network.Frame{FrameType: network.FrameTypeAck}
	mux.controlCh <- &network.Frame{FrameType: network.FrameTypeAck}
	snapshot := mux.Snapshot()
	if snapshot.DataQueueDepth != 1 || snapshot.DataQueueCapacity != 4 ||
		snapshot.ControlQueueDepth != 2 || snapshot.ControlQueueCapacity != 3 {
		t.Fatalf("queue snapshot=%+v", snapshot)
	}
}

func endpointMuxBillableFrame(t *testing.T, messageID uint64, sequence uint32, total uint32) *network.Frame {
	t.Helper()
	message := makeTestMessage(64)
	message.Header.BillingSessionID[0] = 1
	message.Header.BillingSequence = 1
	message.Header.BillingBytes = uint64(len(message.Payload))
	wire, err := message.ParseToBytes()
	if err != nil {
		t.Fatalf("encode billable message: %v", err)
	}
	payload := []byte("continuation")
	if sequence == 0 {
		payload = wire
	}
	return &network.Frame{
		MessageId: messageID, SeqId: sequence, TotalFrames: total,
		FrameType: network.FrameTypeData, ConnectionId: message.Header.ConnectionId,
		Payload: payload,
	}
}

func TestEndpointMuxRejectsOldBillingGenerationAfterRelayChange(t *testing.T) {
	dual := newDualStream("peer", "billing-generation")
	t.Cleanup(func() { _ = dual.Close() })
	mux := &EndpointFrameMux{
		dual:               dual,
		billingGenerations: make(map[muxFrameKey]*muxBillingGenerationRoute),
	}
	first := endpointMuxBillableFrame(t, 41, 0, 2)
	if err := mux.trackOutboundBillingGeneration(first, time.Now()); err != nil {
		t.Fatalf("track first billable frame: %v", err)
	}
	dual.relayGeneration.Add(1)
	if !mux.outboundBillingGenerationStale(first, time.Now()) {
		t.Fatal("queued billable frame from the old Relay generation was not marked stale")
	}
	continuation := endpointMuxBillableFrame(t, first.MessageId, 1, first.TotalFrames)
	continuation.ConnectionId = first.ConnectionId
	if err := mux.trackOutboundBillingGeneration(continuation, time.Now()); !errors.Is(err, ErrRelayChangedDuringSend) {
		t.Fatalf("old-generation continuation error=%v, want %v", err, ErrRelayChangedDuringSend)
	}
}

func TestEndpointMuxBillingGenerationIsReleasedByFullAck(t *testing.T) {
	dual := newDualStream("peer", "billing-generation-ack")
	t.Cleanup(func() { _ = dual.Close() })
	mux := &EndpointFrameMux{
		dual:               dual,
		billingGenerations: make(map[muxFrameKey]*muxBillingGenerationRoute),
	}
	frame := endpointMuxBillableFrame(t, 42, 0, 1)
	if err := mux.trackOutboundBillingGeneration(frame, time.Now()); err != nil {
		t.Fatal(err)
	}
	ack, err := network.BuildAckFrame(frame.MessageId, frame.TotalFrames, network.FullAckRange(frame.TotalFrames))
	if err != nil {
		t.Fatal(err)
	}
	ack.ConnectionId = frame.ConnectionId
	mux.mu.Lock()
	mux.observeBillingGenerationAckLocked(ack, time.Now())
	remaining := len(mux.billingGenerations)
	mux.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("fully acknowledged billing generation retained %d routes", remaining)
	}
}

func TestEndpointMuxDataQueueCapacityMatchesCarrierWindow(t *testing.T) {
	if endpointMuxDataQueueCapacity != 64 {
		t.Fatalf("data queue capacity=%d, want 64 frames (two frames per carrier slot)", endpointMuxDataQueueCapacity)
	}
}

func TestMuxConnWriteHonorsDeadlineWhileSharedQueueIsBlocked(t *testing.T) {
	started := make(chan struct{})
	conn := newMuxConnWithContext("deadline", func(ctx context.Context, _ *network.Frame) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	defer conn.Close()
	frame := &network.Frame{FrameType: network.FrameTypeAck, ConnectionId: "deadline"}
	wire, err := frame.ParseToBytes()
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write(wire)
		result <- writeErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("mux write did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked mux write error=%v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked mux write ignored deadline")
	}
}

func TestCallerDeadlineDoesNotPoisonVirtualMuxStream(t *testing.T) {
	muxContext, cancelMux := context.WithCancel(context.Background())
	defer cancelMux()
	mux := &EndpointFrameMux{
		ctx:       muxContext,
		outCh:     make(chan *network.Frame),
		controlCh: make(chan *network.Frame),
	}
	conn := newMuxConnWithContext("caller-deadline", mux.writeSharedContext)
	stream := newTcpStream("peer", "caller-deadline", conn)
	stream.writeTimeout = 0
	t.Cleanup(func() { _ = stream.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := stream.SendMessage(ctx, makeTestMessage(8))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SendMessage error=%v, want caller deadline", err)
	}
	if fatal := stream.fatal(); fatal != nil {
		t.Fatalf("caller deadline poisoned virtual stream: %v", fatal)
	}
	select {
	case <-conn.closeCh:
		t.Fatal("caller deadline closed virtual mux connection")
	default:
	}
}

func TestRelayGenerationWriteErrorDoesNotPoisonVirtualMuxStream(t *testing.T) {
	connection := newMuxConnWithContext("relay-generation", func(context.Context, *network.Frame) error {
		return ErrRelayChangedDuringSend
	})
	stream := newTcpStream("peer", "relay-generation", connection)
	stream.writeTimeout = 0
	stream.SetCryptoSuite(&countingE2ESuite{})
	t.Cleanup(func() { _ = stream.Close() })

	message := makeTestMessage(64)
	message.Header.BillingSessionID[0] = 1
	message.Header.BillingSequence = 1
	message.Header.BillingBytes = uint64(len(message.Payload))
	if err := stream.SendMessage(context.Background(), message); !errors.Is(err, ErrRelayChangedDuringSend) {
		t.Fatalf("billable send error=%v, want %v", err, ErrRelayChangedDuringSend)
	}
	if fatal := stream.fatal(); fatal != nil {
		t.Fatalf("Relay generation change poisoned virtual stream: %v", fatal)
	}
	select {
	case <-connection.closeCh:
		t.Fatal("Relay generation change closed virtual mux connection")
	default:
	}

	connection.writeFn = func(context.Context, *network.Frame) error { return nil }
	ack, err := network.BuildAckFrame(1, 1, network.FullAckRange(1))
	if err != nil {
		t.Fatal(err)
	}
	ack.ConnectionId = connection.connId
	if err := stream.HandleFrame(context.Background(), ack); err != nil {
		t.Fatalf("virtual stream was not reusable after Relay generation change: %v", err)
	}
}

func TestVirtualMuxStreamUsesCallerControlledWriteLifetime(t *testing.T) {
	connection := newMuxConnWithContext("write-lifetime", func(context.Context, *network.Frame) error {
		return nil
	})
	stream := newTcpStream("peer", "write-lifetime", connection)
	t.Cleanup(func() { _ = stream.Close() })

	if stream.writeTimeout != 0 {
		t.Fatalf("virtual mux write timeout=%s, want caller-controlled lifetime", stream.writeTimeout)
	}
}

func TestKeepAliveDoesNotKillLocallyBackpressuredMux(t *testing.T) {
	muxContext, cancelMux := context.WithCancel(context.Background())
	defer cancelMux()
	mux := &EndpointFrameMux{
		ctx:       muxContext,
		outCh:     make(chan *network.Frame),
		controlCh: make(chan *network.Frame),
	}
	conn := newMuxConnWithContext("keepalive-backpressure", mux.writeSharedContext)
	stream := newTcpStream("peer", "keepalive-backpressure", conn)
	stream.writeTimeout = 0
	stream.keepAlivePolicy = streamKeepAlivePolicy{
		idleBaseline: 5 * time.Millisecond,
		probeBase:    5 * time.Millisecond,
		maxProbes:    2,
		probeTimeout: 10 * time.Millisecond,
	}
	t.Cleanup(func() { _ = stream.Close() })
	stream.StartKeepAlive()
	time.Sleep(120 * time.Millisecond)
	if fatal := stream.fatal(); fatal != nil {
		t.Fatalf("local mux backpressure was treated as peer death: %v", fatal)
	}
	select {
	case <-conn.closeCh:
		t.Fatal("local mux backpressure closed virtual connection")
	default:
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
		ctx:       ctx,
		conns:     make(map[string]*muxConn),
		inbound:   make(map[muxFrameKey]muxInboundRoute),
		retired:   make(map[string]time.Time),
		controlCh: make(chan *network.Frame, 1),
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
	select {
	case control := <-mux.controlCh:
		if control.FrameType != network.FrameTypeConnectionClose ||
			control.ConnectionId != first.ConnectionId {
			t.Fatalf("close control = %+v", control)
		}
	default:
		t.Fatal("closing a logical connection did not enqueue close control")
	}

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
