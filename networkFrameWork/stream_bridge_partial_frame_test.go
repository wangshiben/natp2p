package networkFrameWork

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/network"
)

type noFINBridgeCarrier struct {
	net.Conn
}

func (c *noFINBridgeCarrier) Write(payload []byte) (int, error) {
	return len(payload), nil
}

type blockingBridgeWriteConn struct {
	net.Conn
	writeStarted chan struct{}
	unblock      chan struct{}
	startOnce    sync.Once
	unblockOnce  sync.Once
}

type closeObservedBridgeConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *closeObservedBridgeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *blockingBridgeWriteConn) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	<-c.unblock
	return 0, net.ErrClosed
}

func (c *blockingBridgeWriteConn) Close() error {
	c.unblockWrite()
	return c.Conn.Close()
}

func (c *blockingBridgeWriteConn) unblockWrite() {
	c.unblockOnce.Do(func() { close(c.unblock) })
}

type deadlineBlockingBridgeConn struct {
	net.Conn

	mu              sync.Mutex
	writeDeadline   time.Time
	deadlineChanged chan struct{}
	writeStartedAt  time.Time
	writeTimedOutAt time.Time
	deadlineSetAt   time.Time
	firstDeadline   time.Time

	writeStarted     chan struct{}
	writeTimedOut    chan struct{}
	closed           chan struct{}
	writeStartOnce   sync.Once
	writeTimeoutOnce sync.Once
	closeOnce        sync.Once
}

func newDeadlineBlockingBridgeConn(conn net.Conn) *deadlineBlockingBridgeConn {
	return &deadlineBlockingBridgeConn{
		Conn:            conn,
		deadlineChanged: make(chan struct{}),
		writeStarted:    make(chan struct{}),
		writeTimedOut:   make(chan struct{}),
		closed:          make(chan struct{}),
	}
}

func (c *deadlineBlockingBridgeConn) Write([]byte) (int, error) {
	c.writeStartOnce.Do(func() {
		c.mu.Lock()
		c.writeStartedAt = time.Now()
		c.mu.Unlock()
		close(c.writeStarted)
	})
	for {
		c.mu.Lock()
		deadline := c.writeDeadline
		deadlineChanged := c.deadlineChanged
		c.mu.Unlock()

		if deadline.IsZero() {
			select {
			case <-deadlineChanged:
				continue
			case <-c.closed:
				return 0, net.ErrClosed
			}
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			c.recordWriteTimeout()
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			c.recordWriteTimeout()
			return 0, os.ErrDeadlineExceeded
		case <-deadlineChanged:
			if !timer.Stop() {
				<-timer.C
			}
		case <-c.closed:
			if !timer.Stop() {
				<-timer.C
			}
			return 0, net.ErrClosed
		}
	}
}

func (c *deadlineBlockingBridgeConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.firstDeadline.IsZero() && !deadline.IsZero() {
		c.deadlineSetAt = time.Now()
		c.firstDeadline = deadline
	}
	c.writeDeadline = deadline
	deadlineChanged := c.deadlineChanged
	c.deadlineChanged = make(chan struct{})
	close(deadlineChanged)
	c.mu.Unlock()
	return nil
}

func (c *deadlineBlockingBridgeConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		err = c.Conn.Close()
	})
	return err
}

func (c *deadlineBlockingBridgeConn) recordWriteTimeout() {
	c.writeTimeoutOnce.Do(func() {
		c.mu.Lock()
		c.writeTimedOutAt = time.Now()
		c.mu.Unlock()
		close(c.writeTimedOut)
	})
}

func (c *deadlineBlockingBridgeConn) timing() (time.Time, time.Time, time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlineSetAt, c.firstDeadline, c.writeStartedAt, c.writeTimedOutAt
}

func TestCrossRelayBridgeResumeCannotReplaceOccupiedNormalOrExtraSlot(t *testing.T) {
	const connectionID = "12121212-3434-5656-7878-909090909090"

	peerBridgeConn, peerRemoteConn := net.Pipe()
	bridge := NewCrossRelayBridge(context.Background(), "peer", "target", "origin", connectionID)
	bridge.SetDialFunc(func(string, string, string, string) (net.Conn, error) {
		return peerBridgeConn, nil
	})
	t.Cleanup(func() {
		bridge.Close()
		_ = peerRemoteConn.Close()
	})

	newLeg := func(nodeID string) (*TcpStream, net.Conn) {
		local, remote := net.Pipe()
		stream := newTcpStream(nodeID, connectionID, local)
		t.Cleanup(func() {
			_ = stream.Close()
			_ = remote.Close()
		})
		return stream, remote
	}

	oldNormal, _ := newLeg("old-normal")
	if err := bridge.SpliceLegWithFlags(oldNormal, false, false); err != nil {
		t.Fatalf("splice old normal leg: %v", err)
	}
	oldExtra, _ := newLeg("old-extra")
	if err := bridge.SpliceLegWithFlags(oldExtra, true, false); err != nil {
		t.Fatalf("splice old extra leg: %v", err)
	}

	resumedNormal, _ := newLeg("resumed-normal")
	if err := bridge.SpliceLegWithFlags(resumedNormal, false, true); !errors.Is(err, ErrResumeSlotOccupied) {
		t.Fatalf("resume normal should be rejected with ErrResumeSlotOccupied: %v", err)
	}
	resumedExtra, _ := newLeg("resumed-extra")
	if err := bridge.SpliceLegWithFlags(resumedExtra, true, true); !errors.Is(err, ErrResumeSlotOccupied) {
		t.Fatalf("resume extra should be rejected with ErrResumeSlotOccupied: %v", err)
	}

	bridge.mu.Lock()
	localDual := bridge.localDual
	bridge.mu.Unlock()
	if localDual == nil {
		t.Fatal("bridge lost local dual stream after rejected resume")
	}
	localDual.mu.RLock()
	normalEntry := localDual.legs[streamTransportTCP]
	extraEntry := localDual.legs[relayBackupLegID(streamTransportTCP)]
	localDual.mu.RUnlock()
	if normalEntry == nil || normalEntry.stream != oldNormal || extraEntry == nil || extraEntry.stream != oldExtra {
		t.Fatalf("rejected resume changed occupied slots: normal=%v extra=%v", normalEntry, extraEntry)
	}
	if oldNormal.IsClosed() || oldExtra.IsClosed() {
		t.Fatal("rejected resume closed an existing healthy bridge leg")
	}
	select {
	case <-bridge.Done():
		t.Fatal("rejected resume closed the cross-relay bridge")
	default:
	}
}

func TestCrossRelayBridgeCloseDoesNotWaitForBlockedDial(t *testing.T) {
	const connectionID = "34343434-5656-7878-9090-121212121212"

	localBridgeConn, localRemoteConn := net.Pipe()
	dialedConn, dialedRemoteConn := net.Pipe()
	observedDialedConn := &closeObservedBridgeConn{
		Conn:   dialedConn,
		closed: make(chan struct{}),
	}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var releaseDialOnce sync.Once
	release := func() {
		releaseDialOnce.Do(func() { close(releaseDial) })
	}
	bridge := NewCrossRelayBridge(context.Background(), "peer", "target", "origin", connectionID)
	bridge.SetDialFunc(func(string, string, string, string) (net.Conn, error) {
		close(dialStarted)
		<-releaseDial
		return observedDialedConn, nil
	})
	stream := newTcpStream("node", connectionID, localBridgeConn)
	t.Cleanup(func() {
		release()
		bridge.Close()
		_ = stream.Close()
		_ = localRemoteConn.Close()
		_ = observedDialedConn.Close()
		_ = dialedRemoteConn.Close()
	})

	spliceDone := make(chan error, 1)
	go func() {
		spliceDone <- bridge.SpliceLeg(stream)
	}()
	select {
	case <-dialStarted:
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("SpliceLeg did not enter the blocking dial")
	}

	closeDone := make(chan struct{})
	go func() {
		bridge.Close()
		close(closeDone)
	}()
	closeTimedOut := false
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		closeTimedOut = true
	}
	release()
	if closeTimedOut {
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
			t.Fatal("CrossRelayBridge.Close remained blocked after dial release")
		}
	}

	var spliceErr error
	select {
	case spliceErr = <-spliceDone:
	case <-time.After(2 * time.Second):
		t.Fatal("SpliceLeg did not return after the blocked dial was released")
	}
	select {
	case <-observedDialedConn.closed:
	case <-time.After(time.Second):
		t.Fatal("connection returned by the late dial was not closed")
	}
	if closeTimedOut {
		t.Fatal("CrossRelayBridge.Close waited for SetDialFunc to return")
	}
	if spliceErr == nil || !strings.Contains(spliceErr.Error(), "bridge closed") {
		t.Fatalf("SpliceLeg error after concurrent close = %v, want bridge closed", spliceErr)
	}
}

func TestCrossRelayBridgeDropsPartialFrameBeforeBackupRetransmit(t *testing.T) {
	const (
		connectionID    = "11111111-2222-3333-4444-555555555555"
		remoteMessageID = uint64(73)
	)

	oldBridgeConn, oldRemoteConn := net.Pipe()
	backupBridgeConn, backupRemoteConn := net.Pipe()
	peerBridgeConn, peerRemoteConn := net.Pipe()
	bridge := NewCrossRelayBridge(context.Background(), "peer", "target", "origin", connectionID)
	bridge.SetDialFunc(func(string, string, string, string) (net.Conn, error) {
		return peerBridgeConn, nil
	})
	t.Cleanup(func() {
		bridge.Close()
		_ = oldRemoteConn.Close()
		_ = backupRemoteConn.Close()
		_ = peerRemoteConn.Close()
	})

	oldStream := newTcpStream("node", connectionID, oldBridgeConn)
	if err := bridge.SpliceLegCoexist(oldStream, false); err != nil {
		t.Fatalf("splice old bridge leg: %v", err)
	}
	backupStream := newTcpStream("node", connectionID, backupBridgeConn)
	if err := bridge.SpliceLegCoexist(backupStream, true); err != nil {
		t.Fatalf("splice backup bridge leg: %v", err)
	}

	wantMessage := &network.Message{
		Header: &network.Header{
			RouteName:     "/bridge/partial-frame",
			NodeId:        "source-node",
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: []byte("complete payload from the backup leg"),
	}
	frames, err := wantMessage.SplitToFrames(remoteMessageID, network.DefaultMaxFramePayload)
	if err != nil {
		t.Fatalf("split test message: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("test message split into %d frames, want 1", len(frames))
	}
	frames[0].ConnectionId = connectionID
	wireFrame, err := frames[0].AppendTo(nil)
	if err != nil {
		t.Fatalf("encode test frame: %v", err)
	}
	cut := len(wireFrame) / 2
	if _, err := oldRemoteConn.Write(wireFrame[:cut]); err != nil {
		t.Fatalf("write partial frame on old leg: %v", err)
	}
	if err := oldRemoteConn.Close(); err != nil {
		t.Fatalf("close old leg: %v", err)
	}
	if _, err := backupRemoteConn.Write(wireFrame); err != nil {
		t.Fatalf("retransmit complete frame on backup leg: %v", err)
	}

	if err := peerRemoteConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set peer read deadline: %v", err)
	}
	forwarded, err := network.ReadFrame(peerRemoteConn)
	if err != nil {
		t.Fatalf("read forwarded frame: %v", err)
	}
	if forwarded.ConnectionId != connectionID {
		t.Fatalf("forwarded connection ID = %q, want %q", forwarded.ConnectionId, connectionID)
	}
	assembler := network.NewFrameAssembler()
	gotMessage, err := assembler.Add(forwarded)
	if err != nil {
		t.Fatalf("assemble forwarded frame: %v", err)
	}
	if gotMessage == nil {
		t.Fatal("forwarded frame did not form a complete message")
	}
	if gotMessage.Header.RouteName != wantMessage.Header.RouteName {
		t.Fatalf("forwarded route = %q, want %q", gotMessage.Header.RouteName, wantMessage.Header.RouteName)
	}
	if !bytes.Equal(gotMessage.Payload, wantMessage.Payload) {
		t.Fatalf("forwarded payload = %q, want %q", gotMessage.Payload, wantMessage.Payload)
	}

	if err := peerRemoteConn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set duplicate read deadline: %v", err)
	}
	if duplicate, duplicateErr := network.ReadFrame(peerRemoteConn); duplicateErr == nil {
		t.Fatalf("peer received an unexpected second frame: %+v", duplicate)
	} else if timeout, ok := duplicateErr.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("second read error = %v, want timeout", duplicateErr)
	}
}

func TestCrossRelayBridgeReservesSynthesizedHelloMessageID(t *testing.T) {
	const (
		connectionID    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		remoteMessageID = uint64(91)
	)

	localBridgeConn, localRemoteConn := net.Pipe()
	peerBridgeConn, peerRemoteConn := net.Pipe()
	bridge := NewCrossRelayBridge(context.Background(), "peer", "target", "origin", connectionID)
	bridge.SetDialFunc(func(string, string, string, string) (net.Conn, error) {
		return peerBridgeConn, nil
	})
	t.Cleanup(func() {
		bridge.Close()
		_ = localRemoteConn.Close()
		_ = peerRemoteConn.Close()
	})

	localStream := newTcpStream("node", connectionID, localBridgeConn)
	if err := bridge.SpliceLeg(localStream); err != nil {
		t.Fatalf("splice local bridge leg: %v", err)
	}

	wantMessage := &network.Message{
		Header: &network.Header{
			RouteName:     "/bridge/after-prefix",
			NodeId:        "source-node",
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: []byte("first business payload after synthesized hello"),
	}
	frames, err := wantMessage.SplitToFrames(remoteMessageID, network.DefaultMaxFramePayload)
	if err != nil {
		t.Fatalf("split business message: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("business message split into %d frames, want 1", len(frames))
	}
	frames[0].ConnectionId = connectionID
	wireFrame, err := frames[0].AppendTo(nil)
	if err != nil {
		t.Fatalf("encode business frame: %v", err)
	}
	if _, err := localRemoteConn.Write(wireFrame); err != nil {
		t.Fatalf("write first business frame: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		bridge.mu.Lock()
		peerFrame := bridge.peerFrame
		bridge.mu.Unlock()
		routeReady := false
		if peerFrame != nil {
			peerFrame.mu.Lock()
			routeReady = len(peerFrame.routes) > 0
			peerFrame.mu.Unlock()
		}
		if routeReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer carrier route was not created")
		}
		time.Sleep(time.Millisecond)
	}

	helloAck, err := network.BuildAckFrame(1, 1, network.FullAckRange(1))
	if err != nil {
		t.Fatalf("build synthesized hello ACK: %v", err)
	}
	helloAck.ConnectionId = connectionID
	helloAckWire, err := helloAck.AppendTo(nil)
	if err != nil {
		t.Fatalf("encode synthesized hello ACK: %v", err)
	}
	if _, err := peerRemoteConn.Write(helloAckWire); err != nil {
		t.Fatalf("write synthesized hello ACK: %v", err)
	}

	if err := localRemoteConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set premature ACK deadline: %v", err)
	}
	if premature, prematureErr := network.ReadFrame(localRemoteConn); prematureErr == nil {
		t.Fatalf("synthesized hello ACK prematurely confirmed the business route: %+v", premature)
	} else if timeout, ok := prematureErr.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("premature ACK read error = %v, want timeout", prematureErr)
	}

	remoteStream := newTcpStream("source", connectionID, peerRemoteConn)
	remoteStream.firstMsgID = 1
	remoteStream.firstMsgTotalFrames = 1
	remoteStream.firstMsgAcked.Store(true)
	remoteStream.SetPureForwarder(true)
	remoteFrame := NewTcpFrameAdapter(remoteStream)
	remoteStream.StartLoops()
	t.Cleanup(func() { _ = remoteStream.Close() })

	readContext, cancelRead := context.WithTimeout(context.Background(), 2*time.Second)
	forwarded, err := remoteFrame.NextFrame(readContext)
	cancelRead()
	if err != nil {
		t.Fatalf("read first business frame after synthesized hello: %v", err)
	}
	if forwarded.MessageId == 1 {
		t.Fatal("first business frame reused synthesized hello carrier MessageId 1")
	}
	assembler := network.NewFrameAssembler()
	gotMessage, err := assembler.Add(forwarded)
	if err != nil {
		t.Fatalf("assemble first business frame: %v", err)
	}
	if gotMessage == nil || !bytes.Equal(gotMessage.Payload, wantMessage.Payload) {
		t.Fatalf("first business message = %#v, want payload %q", gotMessage, wantMessage.Payload)
	}

	if err := remoteStream.sendAck(forwarded.MessageId, forwarded.TotalFrames, network.FullAckRange(forwarded.TotalFrames)); err != nil {
		t.Fatalf("ACK first business frame: %v", err)
	}
	if err := localRemoteConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set business ACK deadline: %v", err)
	}
	businessAck, err := network.ReadFrame(localRemoteConn)
	if err != nil {
		t.Fatalf("read business ACK: %v", err)
	}
	if businessAck.FrameType != network.FrameTypeAck || businessAck.MessageId != remoteMessageID {
		t.Fatalf("business ACK = type %d message %d, want ACK for %d", businessAck.FrameType, businessAck.MessageId, remoteMessageID)
	}
}

func TestCrossRelayBridgeCloseDoesNotWaitForBlockedReplacementReplay(t *testing.T) {
	const connectionID = "23232323-4545-6767-8989-010101010101"

	oldBridgeConn, oldRemoteConn := net.Pipe()
	peerBridgeConn, peerRemoteConn := net.Pipe()
	bridge := NewCrossRelayBridge(context.Background(), "peer", "target", "origin", connectionID)
	bridge.SetDialFunc(func(string, string, string, string) (net.Conn, error) {
		return peerBridgeConn, nil
	})
	t.Cleanup(func() {
		bridge.Close()
		_ = oldRemoteConn.Close()
		_ = peerRemoteConn.Close()
	})

	oldStream := newTcpStream("old-node", connectionID, oldBridgeConn)
	if err := bridge.SpliceLegWithFlags(oldStream, false, false); err != nil {
		t.Fatalf("splice old bridge leg: %v", err)
	}

	activeFrame := &network.Frame{
		MessageId:    707,
		SeqId:        0,
		TotalFrames:  2,
		FrameType:    network.FrameTypeData,
		ConnectionId: connectionID,
		Payload:      []byte("cached before replacement"),
	}
	wireFrame, err := activeFrame.AppendTo(nil)
	if err != nil {
		t.Fatalf("encode active frame: %v", err)
	}
	if _, err := peerRemoteConn.Write(wireFrame); err != nil {
		t.Fatalf("write active peer frame: %v", err)
	}
	if err := oldRemoteConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set old leg read deadline: %v", err)
	}
	if _, err := network.ReadFrame(oldRemoteConn); err != nil {
		t.Fatalf("read frame from old leg: %v", err)
	}

	replacementPipe, replacementRemote := net.Pipe()
	blockingConn := &blockingBridgeWriteConn{
		Conn:         replacementPipe,
		writeStarted: make(chan struct{}),
		unblock:      make(chan struct{}),
	}
	replacementStream := newTcpStream("replacement-node", connectionID, blockingConn)
	t.Cleanup(func() {
		blockingConn.unblockWrite()
		_ = replacementStream.Close()
		_ = replacementRemote.Close()
	})
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- bridge.SpliceLegWithFlags(replacementStream, false, false)
	}()
	select {
	case <-blockingConn.writeStarted:
	case <-time.After(2 * time.Second):
		blockingConn.unblockWrite()
		t.Fatal("replacement replay did not reach the blocking write")
	}

	closeDone := make(chan struct{})
	go func() {
		bridge.Close()
		close(closeDone)
	}()
	closeTimedOut := false
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		closeTimedOut = true
		blockingConn.unblockWrite()
	}
	if closeTimedOut {
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
			t.Fatal("CrossRelayBridge.Close remained blocked after replay was released")
		}
	}
	select {
	case <-attachDone:
	case <-time.After(2 * time.Second):
		blockingConn.unblockWrite()
		t.Fatal("replacement splice did not exit after bridge close")
	}
	if closeTimedOut {
		t.Fatal("CrossRelayBridge.Close waited for the bridge mutex held by replacement replay")
	}
}

func TestCrossRelayBridgeDoesNotInjectKeepAliveIntoInitialLocalLeg(t *testing.T) {
	const connectionID = "99999999-8888-7777-6666-555555555555"

	localPipe, localRemote := net.Pipe()
	peerBridgeConn, peerRemoteConn := net.Pipe()
	bridge := NewCrossRelayBridge(context.Background(), "peer", "target", "origin", connectionID)
	bridge.SetDialFunc(func(string, string, string, string) (net.Conn, error) {
		return peerBridgeConn, nil
	})
	t.Cleanup(func() {
		bridge.Close()
		_ = localRemote.Close()
		_ = peerRemoteConn.Close()
	})

	stream := newTcpStream("node", connectionID, localPipe)
	stream.keepAlivePolicy = streamKeepAlivePolicy{
		idleBaseline: 5 * time.Millisecond,
		probeBase:    5 * time.Millisecond,
		maxProbes:    2,
		probeTimeout: 20 * time.Millisecond,
	}
	if err := bridge.SpliceLeg(stream); err != nil {
		t.Fatalf("splice initial bridge leg: %v", err)
	}

	if err := localRemote.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set local leg read deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if count, err := localRemote.Read(buffer); err == nil || count != 0 {
		t.Fatalf("relay injected %d byte(s) into initial NAT leg, want no physical keepalive", count)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read initial NAT leg: %v", err)
	}
}

func TestCrossRelayBridgeDoesNotInjectKeepAliveIntoAdditionalLocalLeg(t *testing.T) {
	const connectionID = "45454545-6767-8989-0101-232323232323"
	policy := streamKeepAlivePolicy{
		idleBaseline: 5 * time.Millisecond,
		probeBase:    5 * time.Millisecond,
		maxProbes:    2,
		probeTimeout: 25 * time.Millisecond,
	}

	initialPipe, initialRemote := net.Pipe()
	additionalPipe, additionalRemote := net.Pipe()
	peerBridgeConn, peerRemoteConn := net.Pipe()
	bridge := NewCrossRelayBridge(context.Background(), "peer", "target", "origin", connectionID)
	bridge.SetDialFunc(func(string, string, string, string) (net.Conn, error) {
		return peerBridgeConn, nil
	})
	t.Cleanup(func() {
		bridge.Close()
		_ = initialRemote.Close()
		_ = additionalRemote.Close()
		_ = peerRemoteConn.Close()
	})

	initialStream := newTcpStream("node", connectionID, initialPipe)
	if err := bridge.SpliceLeg(initialStream); err != nil {
		t.Fatalf("splice initial bridge leg: %v", err)
	}
	additionalStream := newTcpStream("node", connectionID, additionalPipe)
	additionalStream.keepAlivePolicy = policy
	if err := bridge.SpliceLegCoexist(additionalStream, true); err != nil {
		t.Fatalf("splice additional bridge leg: %v", err)
	}
	if err := additionalRemote.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set additional leg read deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if count, err := additionalRemote.Read(buffer); err == nil || count != 0 {
		t.Fatalf("relay injected %d byte(s) into additional NAT leg, want no physical keepalive", count)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read additional NAT leg: %v", err)
	}
}
