package networkFrameWork

import (
	"bnfs_p2p/network"
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type firstWriteGateConn struct {
	net.Conn
	armed       atomic.Bool
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func newFirstWriteGateConn(connection net.Conn) *firstWriteGateConn {
	return &firstWriteGateConn{
		Conn:    connection,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (connection *firstWriteGateConn) Write(payload []byte) (int, error) {
	if connection.armed.CompareAndSwap(true, false) {
		connection.enteredOnce.Do(func() { close(connection.entered) })
		<-connection.release
	}
	return connection.Conn.Write(payload)
}

func (connection *firstWriteGateConn) arm() {
	connection.armed.Store(true)
}

func (connection *firstWriteGateConn) unblock() {
	connection.releaseOnce.Do(func() { close(connection.release) })
}

func TestRelayBusinessFirstMessagePrecedesClientAck(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动测试 Relay 失败: %v", err)
	}
	defer listener.Close()

	cover := NewTransportCover()
	registrationGate := make(chan *firstWriteGateConn, 1)
	var accepted atomic.Int32
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			if accepted.Add(1) == 1 {
				gate := newFirstWriteGateConn(connection)
				registrationGate <- gate
				connection = gate
			}
			go func() { _ = cover.ListenTCPConnection(connection) }()
		}
	}()

	serverIdentity, err := newRelayTestIdentity("ordered-first-message-server")
	if err != nil {
		t.Fatalf("创建 Server 身份失败: %v", err)
	}
	serverStream, err := TryRegisterRelayStreamTCP(serverIdentity.publicKey, listener.Addr().String())
	if err != nil {
		t.Fatalf("注册 Server 失败: %v", err)
	}
	defer serverStream.Close()
	if err := waitForRelayGroup(cover, serverIdentity.nodeID, 3*time.Second); err != nil {
		t.Fatalf("等待 Server 注册完成失败: %v", err)
	}
	serverCarrier, ok := serverStream.(*TcpStream)
	if !ok {
		t.Fatalf("Server 注册流类型错误: %T", serverStream)
	}
	serverCarrier.setTestAckDelay(initialAckTimeout + 200*time.Millisecond)

	gate := <-registrationGate
	t.Cleanup(gate.unblock)
	gate.arm()

	clientIdentity, err := newRelayTestIdentity("ordered-first-message-client")
	if err != nil {
		t.Fatalf("创建 Client 身份失败: %v", err)
	}
	type connectResult struct {
		stream       network.Stream
		connectionID string
		err          error
	}
	connected := make(chan connectResult, 1)
	go func() {
		stream, connectionID, connectErr := TryConnectTCPOnlyStream(
			listener.Addr().String(), serverIdentity.nodeID, clientIdentity.publicKey,
		)
		connected <- connectResult{stream: stream, connectionID: connectionID, err: connectErr}
	}()

	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("Relay 未尝试向 Server 转发业务公钥首帧")
	}
	select {
	case result := <-connected:
		if result.stream != nil {
			_ = result.stream.Close()
		}
		t.Fatalf("Server 公钥首帧仍被阻塞时 Client 已收到 ACK: err=%v", result.err)
	case <-time.After(150 * time.Millisecond):
	}

	ackWaitStarted := time.Now()
	gate.unblock()
	var result connectResult
	select {
	case result = <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("解除 Server 首帧阻塞后 Client 仍未完成连接")
	}
	if result.err != nil {
		t.Fatalf("Client 连接失败: %v", result.err)
	}
	if elapsed := time.Since(ackWaitStarted); elapsed < initialAckTimeout {
		t.Fatalf("Client 未等待 Server ACK 即完成连接: elapsed=%v", elapsed)
	}
	serverCarrier.setTestAckDelay(0)
	defer result.stream.Close()

	noiseHello := []byte("BNFSN2H1-ordered-after-public-key")
	sendCtx, cancelSend := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelSend()
	if err := result.stream.SendMessage(sendCtx, &network.Message{
		Header: &network.Header{
			NodeId:        serverIdentity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  result.connectionID,
		},
		Payload: noiseHello,
	}); err != nil {
		t.Fatalf("发送 Noise hello 失败: %v", err)
	}

	first, err := nextNonKeepAliveMessage(context.Background(), serverStream, 3*time.Second)
	if err != nil {
		t.Fatalf("Server 未收到业务公钥首帧: %v", err)
	}
	if got := string(first.Payload); got != clientIdentity.publicKey {
		t.Fatalf("Server 收到的首帧越序: got=%q want client public key", got)
	}
	second, err := nextNonKeepAliveMessage(context.Background(), serverStream, 3*time.Second)
	if err != nil {
		t.Fatalf("Server 未收到后续 Noise hello: %v", err)
	}
	if got := string(second.Payload); got != string(noiseHello) {
		t.Fatalf("Server 收到的第二帧错误: got=%q want=%q", got, noiseHello)
	}
}

func TestStreamGroupResumeNeverForwardsFirstMessage(t *testing.T) {
	relay := newRelaySlotTestTCPStream(t, "resume-forwarding-relay")
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	t.Cleanup(group.Close)
	knownConnectionID := "known-same-generation"
	group.inheritConnectionIDs([]string{knownConnectionID})

	tests := []struct {
		name         string
		connectionID string
		wantForward  bool
	}{
		{name: "same generation", connectionID: knownConnectionID, wantForward: false},
		{name: "unknown cross relay", connectionID: "unknown-cross-relay", wantForward: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stream := newRelaySlotTestTCPStream(t, test.name)
			forward, err := group.StreamOn(stream, &network.Message{Header: &network.Header{
				NodeId:        group.nodeId,
				NodeIdVersion: 1,
				ConnectionId:  test.connectionID,
				LegFlags:      network.LegFlagResume,
			}})
			if err != nil {
				t.Fatalf("Resume StreamOn 失败: %v", err)
			}
			if forward != test.wantForward {
				t.Fatalf("Resume 首帧转发判断错误: got=%v want=%v", forward, test.wantForward)
			}
		})
	}
}

func TestStreamGroupResumeSetupFailureAllowsRetry(t *testing.T) {
	relay := newRelaySlotTestTCPStream(t, "resume-retry-relay")
	sentinel := errors.New("temporary resume setup failure")
	var hookCalls int
	group := newStreamGroupWithRelaySlot(relay, func(network.Stream, network.Stream, *network.Message) error {
		hookCalls++
		if hookCalls == 1 {
			return sentinel
		}
		return nil
	}, false)
	t.Cleanup(group.Close)

	connectionID := "unknown-cross-relay-retry"
	resumeMessage := &network.Message{Header: &network.Header{
		NodeId:        group.nodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionID,
		LegFlags:      network.LegFlagResume,
	}}
	first := newRelaySlotTestTCPStream(t, "resume-retry-first")
	if _, err := group.StreamOn(first, cloneMessage(resumeMessage)); !errors.Is(err, sentinel) {
		t.Fatalf("首次 Resume 未返回临时 setup 错误: %v", err)
	}
	group.lock.Lock()
	_, tombstoned := group.closedConnectionIDs[connectionID]
	group.lock.Unlock()
	if tombstoned {
		t.Fatal("临时 Resume setup 失败被错误写入初始化 tombstone")
	}

	retry := newRelaySlotTestTCPStream(t, "resume-retry-second")
	forward, err := group.StreamOn(retry, cloneMessage(resumeMessage))
	if err != nil {
		t.Fatalf("临时失败后的 Resume 重试被拒绝: %v", err)
	}
	if forward {
		t.Fatal("Resume 重试不应再次转发公钥首帧")
	}
}

func TestStreamGroupMissingAwaitDoesNotCreateInitializationTombstone(t *testing.T) {
	relay := newRelaySlotTestTCPStream(t, "missing-await-relay")
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	t.Cleanup(group.Close)

	connectionID := "missing-await-during-resume-race"
	if err := group.AwaitFirstMessage(connectionID); err == nil {
		t.Fatal("缺失 connectionResource 的 AwaitFirstMessage 意外成功")
	}
	group.lock.Lock()
	_, tombstoned := group.closedConnectionIDs[connectionID]
	group.lock.Unlock()
	if tombstoned {
		t.Fatal("无法确认初始化代次时不应写入 ConnectionId tombstone")
	}
}

func TestStreamGroupNormalCloseAllowsKnownResume(t *testing.T) {
	relay := newRelaySlotTestTCPStream(t, "normal-close-relay")
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	t.Cleanup(group.Close)

	connectionID := "normal-close-known-resume"
	first := newRelaySlotTestTCPStream(t, "normal-close-first")
	forward, err := group.StreamOn(first, &network.Message{Header: &network.Header{
		NodeId:        group.nodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionID,
	}})
	if err != nil || !forward {
		t.Fatalf("建立普通业务连接失败: forward=%v err=%v", forward, err)
	}
	if err := group.CloseTargetConnection(connectionID); err != nil {
		t.Fatalf("关闭普通业务连接失败: %v", err)
	}
	group.lock.Lock()
	_, tombstoned := group.closedConnectionIDs[connectionID]
	group.lock.Unlock()
	if tombstoned {
		t.Fatal("正常数据期关闭被错误写入初始化失败 tombstone")
	}

	resume := newRelaySlotTestTCPStream(t, "normal-close-resume")
	forward, err = group.StreamOn(resume, &network.Message{Header: &network.Header{
		NodeId:        group.nodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionID,
		LegFlags:      network.LegFlagResume,
	}})
	if err != nil {
		t.Fatalf("正常关闭后的同代 Resume 被错误拒绝: %v", err)
	}
	if forward {
		t.Fatal("正常关闭后的同代 Resume 不应重复转发业务首帧")
	}
}

func TestStreamGroupBeforeHookFailureRejectsLateResume(t *testing.T) {
	relay := newRelaySlotTestTCPStream(t, "hook-failure-relay")
	sentinel := errors.New("forced before-connection hook failure")
	group := newStreamGroupWithRelaySlot(relay, func(network.Stream, network.Stream, *network.Message) error {
		return sentinel
	}, false)
	t.Cleanup(group.Close)

	connectionID := "hook-failure-late-resume"
	first := newRelaySlotTestTCPStream(t, "hook-failure-first")
	_, err := group.StreamOn(first, &network.Message{Header: &network.Header{
		NodeId:        group.nodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionID,
	}})
	if !errors.Is(err, sentinel) {
		t.Fatalf("beforeConnectionHook 失败未原样返回: %v", err)
	}

	resume := newRelaySlotTestTCPStream(t, "hook-failure-resume")
	_, err = group.StreamOn(resume, &network.Message{Header: &network.Header{
		NodeId:        group.nodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionID,
		LegFlags:      network.LegFlagResume,
	}})
	if !errors.Is(err, ErrBusinessConnectionInitializationFailed) {
		t.Fatalf("beforeConnectionHook 失败后的迟到 Resume 未被拒绝: %v", err)
	}
}

func TestStreamGroupCanceledSetupRejectsLateResume(t *testing.T) {
	relay := newRelaySlotTestTCPStream(t, "canceled-setup-relay")
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	t.Cleanup(group.Close)

	connectionID := "canceled-setup-late-resume"
	business := newRelaySlotTestTCPStream(t, "canceled-setup-business")
	resourceContext, cancelResource := context.WithCancel(group.ctx)
	logicalStream := ensureDualStream(business)
	resource := &connectionResource{
		stream:     logicalStream,
		frame:      logicalStream.EnableFrameRelay(),
		ctx:        resourceContext,
		flag:       cancelResource,
		setupReady: make(chan struct{}),
		firstReady: make(chan struct{}),
	}
	group.lock.Lock()
	group.connectionMap[connectionID] = resource
	addBoundedKnownConnectionID(group.knownConnectionIDs, group.connectionMap, connectionID)
	group.lock.Unlock()
	cancelResource()

	if err := group.AwaitFirstMessage(connectionID); !errors.Is(err, context.Canceled) {
		t.Fatalf("setup 取消未返回 context.Canceled: %v", err)
	}
	group.lock.Lock()
	_, stillPresent := group.connectionMap[connectionID]
	_, tombstoned := group.closedConnectionIDs[connectionID]
	group.lock.Unlock()
	if stillPresent || !tombstoned {
		t.Fatalf("setup 取消未原子清理并写 tombstone: present=%v tombstoned=%v", stillPresent, tombstoned)
	}

	resume := newRelaySlotTestTCPStream(t, "canceled-setup-resume")
	_, err := group.StreamOn(resume, &network.Message{Header: &network.Header{
		NodeId:        group.nodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionID,
		LegFlags:      network.LegFlagResume,
	}})
	if !errors.Is(err, ErrBusinessConnectionInitializationFailed) {
		t.Fatalf("setup 取消后的迟到 Resume 未被拒绝: %v", err)
	}
}

func TestInitializationFailureCleanupDoesNotRemoveFreshReplacement(t *testing.T) {
	relay := newRelaySlotTestTCPStream(t, "initialization-aba-relay")
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	t.Cleanup(group.Close)

	connectionID := "initialization-failure-aba"
	first := newRelaySlotTestTCPStream(t, "initialization-aba-first")
	if _, err := group.StreamOn(first, &network.Message{Header: &network.Header{
		NodeId: group.nodeId, NodeIdVersion: 1, ConnectionId: connectionID,
	}}); err != nil {
		t.Fatalf("建立旧资源失败: %v", err)
	}
	group.lock.Lock()
	oldResource := group.connectionMap[connectionID]
	group.lock.Unlock()
	group.failBusinessConnectionInitialization(connectionID, oldResource)

	replacementStream := newRelaySlotTestTCPStream(t, "initialization-aba-replacement")
	if _, err := group.StreamOn(replacementStream, &network.Message{Header: &network.Header{
		NodeId: group.nodeId, NodeIdVersion: 1, ConnectionId: connectionID,
	}}); err != nil {
		t.Fatalf("同 ConnectionId 的 fresh 重试失败: %v", err)
	}
	group.lock.Lock()
	replacement := group.connectionMap[connectionID]
	_, tombstonedBeforeLateCleanup := group.closedConnectionIDs[connectionID]
	group.lock.Unlock()
	if replacement == nil || replacement == oldResource || tombstonedBeforeLateCleanup {
		t.Fatalf("fresh replacement 状态错误: replacement=%p old=%p tombstoned=%v",
			replacement, oldResource, tombstonedBeforeLateCleanup)
	}

	group.failBusinessConnectionInitialization(connectionID, oldResource)
	group.lock.Lock()
	current := group.connectionMap[connectionID]
	_, tombstonedAfterLateCleanup := group.closedConnectionIDs[connectionID]
	group.lock.Unlock()
	if current != replacement || tombstonedAfterLateCleanup {
		t.Fatalf("迟到旧失败清理破坏 fresh replacement: current=%p replacement=%p tombstoned=%v",
			current, replacement, tombstonedAfterLateCleanup)
	}
	select {
	case <-replacement.ctx.Done():
		t.Fatal("迟到旧失败清理关闭了 fresh replacement")
	default:
	}
}

type stagedWriteGateConn struct {
	net.Conn
	beforeWrite chan struct{}
	allowWrite  chan struct{}
	wrote       chan struct{}
	allowReturn chan struct{}
	gateOnce    sync.Once
	writeOnce   sync.Once
	returnOnce  sync.Once
}

func newStagedWriteGateConn(connection net.Conn) *stagedWriteGateConn {
	return &stagedWriteGateConn{
		Conn:        connection,
		beforeWrite: make(chan struct{}),
		allowWrite:  make(chan struct{}),
		wrote:       make(chan struct{}),
		allowReturn: make(chan struct{}),
	}
}

func (connection *stagedWriteGateConn) Write(payload []byte) (int, error) {
	blocked := false
	connection.gateOnce.Do(func() {
		blocked = true
		close(connection.beforeWrite)
		<-connection.allowWrite
	})
	written, err := connection.Conn.Write(payload)
	if blocked {
		close(connection.wrote)
		<-connection.allowReturn
	}
	return written, err
}

func (connection *stagedWriteGateConn) releaseWrite() {
	connection.writeOnce.Do(func() { close(connection.allowWrite) })
}

func (connection *stagedWriteGateConn) releaseReturn() {
	connection.returnOnce.Do(func() { close(connection.allowReturn) })
}

type countedFrameConn struct {
	net.Conn
	connectionID string
	dataFrames   atomic.Int32
	retransmits  atomic.Int32
}

func (connection *countedFrameConn) Write(payload []byte) (int, error) {
	reader := bytes.NewReader(payload)
	for reader.Len() > 0 {
		frame, err := network.ReadFrame(reader)
		if err != nil {
			break
		}
		if frame.ConnectionId != connection.connectionID {
			continue
		}
		switch frame.FrameType {
		case network.FrameTypeData:
			connection.dataFrames.Add(1)
		case network.FrameTypeRetransmit:
			connection.retransmits.Add(1)
		}
	}
	return connection.Conn.Write(payload)
}

type failingAwaitTCPStream struct {
	*TcpStream
	err         error
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func (stream *failingAwaitTCPStream) TCPStream() *TcpStream {
	return stream.TcpStream
}

func (stream *failingAwaitTCPStream) SendMessageAwaitAck(ctx context.Context, _ *network.Message) error {
	stream.enteredOnce.Do(func() { close(stream.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stream.release:
		return stream.err
	}
}

func (stream *failingAwaitTCPStream) unblock() {
	stream.releaseOnce.Do(func() { close(stream.release) })
}

func newTestBusinessLeg(
	t *testing.T,
	cover *TransportCover,
	firstMessage *network.Message,
) (*TcpStream, <-chan error, <-chan error) {
	t.Helper()
	clientConnection, relayConnection := net.Pipe()
	client := startTcpStream(firstMessage.Header.NodeId, firstMessage.Header.ConnectionId, clientConnection)
	t.Cleanup(func() {
		_ = client.Close()
		_ = relayConnection.Close()
	})
	listenDone := make(chan error, 1)
	go func() { listenDone <- cover.ListenTCPConnection(relayConnection) }()
	sendDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sendDone <- client.SendMessage(ctx, cloneMessage(firstMessage))
	}()
	return client, sendDone, listenDone
}

func newTestBusinessLegWithClientConn(
	t *testing.T,
	cover *TransportCover,
	firstMessage *network.Message,
	clientConnection net.Conn,
	relayConnection net.Conn,
) (*TcpStream, <-chan error, <-chan error) {
	t.Helper()
	client := startTcpStream(firstMessage.Header.NodeId, firstMessage.Header.ConnectionId, clientConnection)
	t.Cleanup(func() {
		_ = client.Close()
		_ = relayConnection.Close()
	})
	listenDone := make(chan error, 1)
	go func() { listenDone <- cover.ListenTCPConnection(relayConnection) }()
	sendDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sendDone <- client.SendMessage(ctx, cloneMessage(firstMessage))
	}()
	return client, sendDone, listenDone
}

func waitTestResult(t *testing.T, result <-chan error, description string) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("%s: %v", description, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s超时", description)
	}
}

func expectNoTestMessage(t *testing.T, stream network.Stream, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	message, err := stream.NextMessage(ctx)
	if err == nil {
		t.Fatalf("意外收到消息: payload=%q", message.Payload)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("等待无消息时返回异常错误: %v", err)
	}
}

func TestRelayFirstMessageGatePreservesOrderAcrossServerLegs(t *testing.T) {
	relayConnectionA, serverConnectionA := net.Pipe()
	serverGate := newStagedWriteGateConn(serverConnectionA)
	t.Cleanup(func() {
		serverGate.releaseWrite()
		serverGate.releaseReturn()
	})
	relayA := startTcpStream("cross-leg-server", "", relayConnectionA)
	serverA := startTcpStream("cross-leg-client", "cross-leg-order", serverGate)
	relayConnectionB, serverConnectionB := net.Pipe()
	relayB := startTcpStream("cross-leg-server", "", relayConnectionB)
	serverB := startTcpStream("cross-leg-client", "cross-leg-order", serverConnectionB)
	t.Cleanup(func() {
		_ = relayA.Close()
		_ = relayB.Close()
		_ = serverA.Close()
		_ = serverB.Close()
	})

	group := newStreamGroupWithRelaySlot(relayA, defaultHookfunc, false)
	if err := group.AttachRelayStreamCoexist(relayB, true); err != nil {
		t.Fatalf("挂载第二条 Server leg 失败: %v", err)
	}
	t.Cleanup(group.Close)
	go group.StartListen()
	cover := NewTransportCover()
	cover.StreamGroup[group.nodeId] = group

	connectionID := "cross-server-leg-order"
	publicKey := []byte("cross-server-leg-public-key")
	firstMessage := &network.Message{
		Header:  &network.Header{NodeId: group.nodeId, NodeIdVersion: 1, ConnectionId: connectionID},
		Payload: publicKey,
	}
	client, firstDone, _ := newTestBusinessLeg(t, cover, firstMessage)
	select {
	case <-serverGate.beforeWrite:
	case <-time.After(3 * time.Second):
		t.Fatal("Server A 未进入首帧 ACK 写屏障")
	}
	relayDual := group.relayStream.(*DualStream)
	relayDual.setPreferred(relayBackupLegID(streamTransportTCP))
	serverGate.releaseWrite()
	select {
	case <-serverGate.wrote:
	case <-time.After(3 * time.Second):
		t.Fatal("Server A 首帧 ACK 未写入 Relay")
	}
	waitTestResult(t, firstDone, "等待 Client 首帧 ACK")

	noise := []byte("BNFSN2H1-cross-server-leg")
	noiseDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		noiseDone <- client.SendMessage(ctx, &network.Message{
			Header:  &network.Header{NodeId: group.nodeId, NodeIdVersion: 1, ConnectionId: connectionID},
			Payload: noise,
		})
	}()
	expectNoTestMessage(t, serverB, 150*time.Millisecond)
	serverGate.releaseReturn()
	waitTestResult(t, noiseDone, "跨 Server leg 发送 Noise")

	first, err := nextNonKeepAliveMessage(context.Background(), serverA, 3*time.Second)
	if err != nil {
		t.Fatalf("Server A 读取公钥首帧失败: %v", err)
	}
	if !bytes.Equal(first.Payload, publicKey) {
		t.Fatalf("Server A 首帧错误: got=%q want=%q", first.Payload, publicKey)
	}
	second, err := nextNonKeepAliveMessage(context.Background(), serverA, 3*time.Second)
	if err != nil {
		t.Fatalf("Server A 读取 Noise 失败: %v", err)
	}
	if !bytes.Equal(second.Payload, noise) {
		t.Fatalf("Server A 第二帧错误: got=%q want=%q", second.Payload, noise)
	}
}

func TestRelayFirstMessageRetransmitDeliveredOnce(t *testing.T) {
	relayConnection, serverConnection := net.Pipe()
	relay := startTcpStream("retransmit-server", "", relayConnection)
	server := startTcpStream("retransmit-client", "retransmit-first", serverConnection)
	server.setTestAckDelay(initialAckTimeout + 100*time.Millisecond)
	t.Cleanup(func() {
		_ = relay.Close()
		_ = server.Close()
	})
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	t.Cleanup(group.Close)
	cover := NewTransportCover()
	cover.StreamGroup[group.nodeId] = group

	connectionID := "first-message-retransmit-once"
	publicKey := []byte("retransmit-public-key")
	firstMessage := &network.Message{
		Header:  &network.Header{NodeId: group.nodeId, NodeIdVersion: 1, ConnectionId: connectionID},
		Payload: publicKey,
	}
	clientConnection, relayBusinessConnection := net.Pipe()
	counted := &countedFrameConn{Conn: clientConnection, connectionID: connectionID}
	_, sendDone, _ := newTestBusinessLegWithClientConn(t, cover, firstMessage, counted, relayBusinessConnection)
	waitTestResult(t, sendDone, "等待重传后的首帧 ACK")
	if counted.dataFrames.Load() != 1 || counted.retransmits.Load() < 1 {
		t.Fatalf("未确定性触发一次首帧重传: data=%d retransmit=%d",
			counted.dataFrames.Load(), counted.retransmits.Load())
	}

	message, err := nextNonKeepAliveMessage(context.Background(), server, 3*time.Second)
	if err != nil {
		t.Fatalf("Server 读取公钥首帧失败: %v", err)
	}
	if !bytes.Equal(message.Payload, publicKey) {
		t.Fatalf("Server 公钥首帧错误: got=%q want=%q", message.Payload, publicKey)
	}
	expectNoTestMessage(t, server, 250*time.Millisecond)
}

func TestRelayConcurrentBusinessLegWaitsSharedFirstMessageGate(t *testing.T) {
	relayConnection, serverConnection := net.Pipe()
	relayGate := newFirstWriteGateConn(relayConnection)
	relayGate.arm()
	t.Cleanup(relayGate.unblock)
	relay := startTcpStream("concurrent-leg-server", "", relayGate)
	server := startTcpStream("concurrent-leg-client", "concurrent-leg", serverConnection)
	t.Cleanup(func() {
		_ = relay.Close()
		_ = server.Close()
	})
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	t.Cleanup(group.Close)
	cover := NewTransportCover()
	cover.StreamGroup[group.nodeId] = group

	connectionID := "concurrent-business-leg-gate"
	firstMessage := &network.Message{
		Header:  &network.Header{NodeId: group.nodeId, NodeIdVersion: 1, ConnectionId: connectionID},
		Payload: []byte("concurrent-leg-public-key"),
	}
	_, firstDone, _ := newTestBusinessLeg(t, cover, firstMessage)
	select {
	case <-relayGate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("首条业务 leg 未进入共享首帧 gate")
	}
	secondMessage := cloneMessage(firstMessage)
	secondMessage.Header.LegFlags = network.LegFlagExtra | network.LegFlagResume
	_, secondDone, _ := newTestBusinessLeg(t, cover, secondMessage)

	deadline := time.Now().Add(2 * time.Second)
	attachedLegs := 0
	for time.Now().Before(deadline) {
		group.lock.Lock()
		resource := group.connectionMap[connectionID]
		legCount := 0
		if resource != nil {
			if dual, ok := resource.stream.(*DualStream); ok {
				dual.mu.RLock()
				legCount = len(dual.legs)
				dual.mu.RUnlock()
			}
		}
		group.lock.Unlock()
		if legCount == 2 {
			attachedLegs = legCount
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if attachedLegs != 2 {
		t.Fatal("并发第二业务 leg 未在 gate 等待期间挂入共享 connectionResource")
	}
	select {
	case err := <-firstDone:
		t.Fatalf("首条业务 leg 在 gate 释放前完成: %v", err)
	default:
	}
	select {
	case err := <-secondDone:
		t.Fatalf("并发第二业务 leg 未等待 shared gate: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	relayGate.unblock()
	waitTestResult(t, firstDone, "释放 gate 后完成首条业务 leg")
	waitTestResult(t, secondDone, "释放 gate 后完成第二业务 leg")
	message, err := nextNonKeepAliveMessage(context.Background(), server, 3*time.Second)
	if err != nil {
		t.Fatalf("Server 读取唯一公钥首帧失败: %v", err)
	}
	if !bytes.Equal(message.Payload, firstMessage.Payload) {
		t.Fatalf("Server 公钥首帧错误: got=%q want=%q", message.Payload, firstMessage.Payload)
	}
	expectNoTestMessage(t, server, 200*time.Millisecond)
}

func TestRelayAwaitedFirstMessageFailureRemovesConnectionResource(t *testing.T) {
	relayConnection, relayPeer := net.Pipe()
	baseRelay := startTcpStream("failed-await-server", "", relayConnection)
	sentinel := errors.New("forced awaited first-message failure")
	failingRelay := &failingAwaitTCPStream{
		TcpStream: baseRelay,
		err:       sentinel,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	t.Cleanup(func() {
		failingRelay.unblock()
		_ = baseRelay.Close()
		_ = relayPeer.Close()
	})
	group := newStreamGroupWithRelaySlot(failingRelay, defaultHookfunc, false)
	t.Cleanup(group.Close)
	cover := NewTransportCover()
	cover.StreamGroup[group.nodeId] = group

	connectionID := "failed-awaited-first-message"
	firstMessage := &network.Message{
		Header:  &network.Header{NodeId: group.nodeId, NodeIdVersion: 1, ConnectionId: connectionID},
		Payload: []byte("failed-await-public-key"),
	}
	_, sendDone, listenDone := newTestBusinessLeg(t, cover, firstMessage)
	select {
	case <-failingRelay.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("未进入受控 awaited send")
	}
	group.lock.Lock()
	resource := group.connectionMap[connectionID]
	group.lock.Unlock()
	if resource == nil {
		t.Fatal("awaited send 失败前 connectionResource 已提前消失")
	}

	failingRelay.unblock()
	select {
	case err := <-listenDone:
		if !errors.Is(err, sentinel) {
			t.Fatalf("Relay 未返回 awaited send 原始错误: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("awaited send 失败后 Relay 未退出")
	}
	select {
	case err := <-sendDone:
		if err == nil {
			t.Fatal("awaited send 失败后 Client 首帧意外成功")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("awaited send 失败后 Client 未解除阻塞")
	}

	group.lock.Lock()
	_, stillPresent := group.connectionMap[connectionID]
	group.lock.Unlock()
	if stillPresent {
		t.Fatal("awaited send 失败后 connectionResource 未从 group 删除")
	}
	select {
	case <-resource.ctx.Done():
	default:
		t.Fatal("awaited send 失败后 connectionResource context 未取消")
	}
	if dual, ok := resource.stream.(*DualStream); ok {
		select {
		case <-dual.ctx.Done():
		default:
			t.Fatal("awaited send 失败后 connectionResource 的全部业务 leg 未关闭")
		}
	}

	lateResume := cloneMessage(firstMessage)
	lateResume.Header.LegFlags = network.LegFlagExtra | network.LegFlagResume
	_, lateSendDone, lateListenDone := newTestBusinessLeg(t, cover, lateResume)
	select {
	case err := <-lateListenDone:
		if !errors.Is(err, ErrBusinessConnectionInitializationFailed) {
			t.Fatalf("迟到 Resume 未命中已关闭 ConnectionId tombstone: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("迟到 Resume 未被 bounded tombstone 及时拒绝")
	}
	select {
	case err := <-lateSendDone:
		if err == nil {
			t.Fatal("迟到 Resume 在首帧初始化失败后意外复活")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("迟到 Resume 被拒后 Client 未解除阻塞")
	}
	group.lock.Lock()
	_, resurrected := group.connectionMap[connectionID]
	_, tombstoned := group.closedConnectionIDs[connectionID]
	tombstoneCount := len(group.closedConnectionIDs)
	group.lock.Unlock()
	if resurrected || !tombstoned || tombstoneCount > retiredBusinessConnectionLimit {
		t.Fatalf("失败连接 tombstone 状态错误: resurrected=%v tombstoned=%v count=%d",
			resurrected, tombstoned, tombstoneCount)
	}
}
