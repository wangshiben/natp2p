package networkFrameWork

import (
	"bnfs_p2p/network"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type deadlineControlledMuxPhysicalConn struct {
	net.Conn

	mu              sync.Mutex
	blockWrites     bool
	blockedWrites   int
	writeDeadline   time.Time
	deadlineChanged chan struct{}
	closed          chan struct{}
	blockedWrite    chan []byte
	deadlineApplied chan time.Time
	blockedOnce     sync.Once
	closeOnce       sync.Once
}

type shortWriteMuxPhysicalConn struct {
	net.Conn

	mu         sync.Mutex
	shortWrite bool
}

func newDeadlineControlledMuxPhysicalConn(conn net.Conn) *deadlineControlledMuxPhysicalConn {
	return &deadlineControlledMuxPhysicalConn{
		Conn:            conn,
		deadlineChanged: make(chan struct{}),
		closed:          make(chan struct{}),
		blockedWrite:    make(chan []byte, 1),
		deadlineApplied: make(chan time.Time, 1),
	}
}

func (conn *deadlineControlledMuxPhysicalConn) blockFutureWrites() {
	conn.mu.Lock()
	conn.blockWrites = true
	conn.mu.Unlock()
}

func (conn *shortWriteMuxPhysicalConn) failFutureWritesShort() {
	conn.mu.Lock()
	conn.shortWrite = true
	conn.mu.Unlock()
}

func (conn *shortWriteMuxPhysicalConn) Write(payload []byte) (int, error) {
	conn.mu.Lock()
	shortWrite := conn.shortWrite
	conn.mu.Unlock()
	if !shortWrite {
		return conn.Conn.Write(payload)
	}
	return len(payload) / 2, nil
}

func (conn *deadlineControlledMuxPhysicalConn) Write(payload []byte) (int, error) {
	conn.mu.Lock()
	blocked := conn.blockWrites
	if blocked {
		conn.blockedWrites++
	}
	conn.mu.Unlock()
	if !blocked {
		return conn.Conn.Write(payload)
	}

	wirePayload := append([]byte(nil), payload...)
	conn.blockedOnce.Do(func() { conn.blockedWrite <- wirePayload })
	for {
		conn.mu.Lock()
		deadline := conn.writeDeadline
		deadlineChanged := conn.deadlineChanged
		conn.mu.Unlock()

		if deadline.IsZero() {
			select {
			case <-deadlineChanged:
				continue
			case <-conn.closed:
				return 0, net.ErrClosed
			}
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(remaining)
		select {
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		case <-deadlineChanged:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-conn.closed:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return 0, net.ErrClosed
		}
	}
}

func (conn *deadlineControlledMuxPhysicalConn) SetWriteDeadline(deadline time.Time) error {
	conn.mu.Lock()
	conn.writeDeadline = deadline
	deadlineChanged := conn.deadlineChanged
	conn.deadlineChanged = make(chan struct{})
	close(deadlineChanged)
	conn.mu.Unlock()
	if !deadline.IsZero() {
		select {
		case conn.deadlineApplied <- deadline:
		default:
		}
	}
	return nil
}

func (conn *deadlineControlledMuxPhysicalConn) Close() error {
	var closeErr error
	conn.closeOnce.Do(func() {
		close(conn.closed)
		closeErr = conn.Conn.Close()
	})
	return closeErr
}

func (conn *deadlineControlledMuxPhysicalConn) blockedWriteCount() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.blockedWrites
}

func TestLogicalConnSetWriteDeadlineBoundsBlockedMuxDataWrite(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	physicalConn := newDeadlineControlledMuxPhysicalConn(clientPipe)
	clientSession := NewMuxSession(context.Background(), physicalConn, true)
	serverSession := NewMuxSession(context.Background(), serverPipe, false)
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	stream, err := clientSession.OpenStream("deadline-logical-conn", "target-node", "origin-public-key")
	if err != nil {
		t.Fatalf("open mux stream: %v", err)
	}
	if _, err := serverSession.Accept(); err != nil {
		t.Fatalf("accept mux stream: %v", err)
	}
	logicalConn := NewSingleLegConn(stream)
	physicalConn.blockFutureWrites()

	type writeResult struct {
		n   int
		err error
		at  time.Time
	}
	payload := []byte("blocked-mux-data")
	writeStartedAt := time.Now()
	resultCh := make(chan writeResult, 1)
	go func() {
		n, writeErr := logicalConn.Write(payload)
		resultCh <- writeResult{n: n, err: writeErr, at: time.Now()}
	}()

	var wirePayload []byte
	select {
	case wirePayload = <-physicalConn.blockedWrite:
	case <-time.After(time.Second):
		t.Fatal("mux DATA did not reach the physical connection")
	}
	frame, err := network.ReadFrame(bytes.NewReader(wirePayload))
	if err != nil {
		t.Fatalf("decode blocked physical write: %v", err)
	}
	if frame.FrameType != muxFrameData || frame.ConnectionId != logicalConn.LogicalID() || !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("blocked physical frame = {type:%d id:%q payload:%q}, want mux DATA for %q", frame.FrameType, frame.ConnectionId, frame.Payload, logicalConn.LogicalID())
	}
	deadline := time.Now().Add(150 * time.Millisecond)
	if err := logicalConn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set logical write deadline during physical write: %v", err)
	}

	select {
	case applied := <-physicalConn.deadlineApplied:
		if !applied.Equal(deadline) {
			t.Fatalf("physical write deadline = %s, want %s", applied, deadline)
		}
	case <-time.After(time.Second):
		t.Fatal("logical write deadline did not reach the physical connection")
	}

	select {
	case result := <-resultCh:
		if result.n != 0 {
			t.Fatalf("blocked logical write reported %d bytes, want 0", result.n)
		}
		if !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked logical write error = %v, want deadline exceeded", result.err)
		}
		if timeoutErr, ok := result.err.(net.Error); !ok || !timeoutErr.Timeout() {
			t.Fatalf("blocked logical write error = %T %v, want timeout net.Error", result.err, result.err)
		}
		if elapsed := result.at.Sub(writeStartedAt); elapsed > time.Second {
			t.Fatalf("blocked logical write returned after %s, want at most 1s", elapsed)
		}
	case <-time.After(time.Second):
		_ = physicalConn.Close()
		t.Fatal("blocked logical write did not return within its deadline")
	}
	if !clientSession.IsClosed() {
		t.Fatal("physical write timeout did not close the mux session")
	}
}

func TestLogicalConnSetWriteDeadlineBoundsQueuedMuxDataWrite(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	physicalConn := newDeadlineControlledMuxPhysicalConn(clientPipe)
	clientSession := NewMuxSession(context.Background(), physicalConn, true)
	serverSession := NewMuxSession(context.Background(), serverPipe, false)
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	openLogicalConn := func(id string) *LogicalConn {
		t.Helper()
		stream, err := clientSession.OpenStream(id, "target-node", "origin-public-key")
		if err != nil {
			t.Fatalf("open mux stream %q: %v", id, err)
		}
		if _, err := serverSession.Accept(); err != nil {
			t.Fatalf("accept mux stream %q: %v", id, err)
		}
		return NewSingleLegConn(stream)
	}
	blockingConn := openLogicalConn("write-gate-blocker")
	queuedConn := openLogicalConn("write-gate-queued")
	physicalConn.blockFutureWrites()

	type writeResult struct {
		n   int
		err error
	}
	blockingResultCh := make(chan writeResult, 1)
	go func() {
		n, writeErr := blockingConn.Write([]byte("hold-physical-write"))
		blockingResultCh <- writeResult{n: n, err: writeErr}
	}()
	select {
	case <-physicalConn.blockedWrite:
	case <-time.After(time.Second):
		t.Fatal("blocking mux DATA did not reach the physical connection")
	}

	queuedResultCh := make(chan writeResult, 1)
	go func() {
		n, writeErr := queuedConn.Write([]byte("wait-behind-physical-write"))
		queuedResultCh <- writeResult{n: n, err: writeErr}
	}()
	pendingDeadline := time.Now().Add(time.Second)
	for clientSession.PendingFrames() < 2 && time.Now().Before(pendingDeadline) {
		time.Sleep(time.Millisecond)
	}
	if pending := clientSession.PendingFrames(); pending < 2 {
		t.Fatalf("pending mux frames = %d, want active plus queued writes", pending)
	}

	deadline := time.Now().Add(150 * time.Millisecond)
	if err := queuedConn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set queued logical write deadline: %v", err)
	}
	select {
	case result := <-queuedResultCh:
		if result.n != 0 || !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Fatalf("queued logical write = (%d, %v), want (0, deadline exceeded)", result.n, result.err)
		}
	case <-time.After(time.Second):
		_ = physicalConn.Close()
		t.Fatal("queued logical write did not return within its deadline")
	}
	if attempts := physicalConn.blockedWriteCount(); attempts != 1 {
		t.Fatalf("physical blocked write attempts = %d, want only the active stream", attempts)
	}
	select {
	case applied := <-physicalConn.deadlineApplied:
		t.Fatalf("queued stream deadline %s was incorrectly applied to another stream's physical write", applied)
	default:
	}
	select {
	case result := <-blockingResultCh:
		t.Fatalf("another stream's deadline interrupted the active write: (%d, %v)", result.n, result.err)
	default:
	}

	_ = physicalConn.Close()
	select {
	case <-blockingResultCh:
	case <-time.After(time.Second):
		t.Fatal("active physical write did not return after connection close")
	}
}

func newManualMuxSession(t *testing.T, acceptCapacity int) *MuxSession {
	t.Helper()
	localConn, remoteConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	session := &MuxSession{
		conn:      localConn,
		ctx:       ctx,
		cancel:    cancel,
		writeGate: make(chan struct{}, 1),
		streams:   make(map[string]*MuxStream),
		accept:    make(chan *MuxStream, acceptCapacity),
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = remoteConn.Close()
	})
	return session
}

func TestMuxSessionCloseUnblocksHandleOpen(t *testing.T) {
	session := newManualMuxSession(t, 0)
	handleDone := make(chan struct{})
	go func() {
		session.handleOpen("close-race", encodeMuxOpen("target-node", "origin-public-key"))
		close(handleDone)
	}()

	registrationDeadline := time.Now().Add(time.Second)
	for session.ActiveStreams() != 1 && time.Now().Before(registrationDeadline) {
		time.Sleep(time.Millisecond)
	}
	if active := session.ActiveStreams(); active != 1 {
		t.Fatalf("active mux streams = %d, want blocked OPEN registration", active)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close mux session: %v", err)
	}
	select {
	case <-handleDone:
	case <-time.After(time.Second):
		t.Fatal("session close did not unblock handleOpen")
	}
	if _, err := session.Accept(); !errors.Is(err, errMuxClosed) {
		t.Fatalf("Accept after Close = %v, want %v", err, errMuxClosed)
	}
}

func TestMuxSessionCloseUnblocksBlockedAccept(t *testing.T) {
	session := newManualMuxSession(t, 0)
	acceptStarted := make(chan struct{})
	acceptResultCh := make(chan error, 1)
	go func() {
		close(acceptStarted)
		_, err := session.Accept()
		acceptResultCh <- err
	}()
	<-acceptStarted
	if err := session.Close(); err != nil {
		t.Fatalf("close mux session: %v", err)
	}
	select {
	case err := <-acceptResultCh:
		if !errors.Is(err, errMuxClosed) {
			t.Fatalf("blocked Accept after Close = %v, want %v", err, errMuxClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("session Close did not unblock Accept")
	}
}

func TestMuxSessionAcceptRechecksCancellationAfterReceive(t *testing.T) {
	session := newManualMuxSession(t, 1)
	session.accept <- newMuxStream(session, "received-during-close")

	session.mu.Lock()
	acceptResultCh := make(chan error, 1)
	go func() {
		_, err := session.Accept()
		acceptResultCh <- err
	}()
	receiveDeadline := time.Now().Add(time.Second)
	for len(session.accept) != 0 && time.Now().Before(receiveDeadline) {
		time.Sleep(time.Millisecond)
	}
	if len(session.accept) != 0 {
		session.mu.Unlock()
		t.Fatal("Accept did not receive the stream before cancellation")
	}
	session.cancel()
	session.mu.Unlock()

	select {
	case err := <-acceptResultCh:
		if !errors.Is(err, errMuxClosed) {
			t.Fatalf("Accept racing with cancellation = %v, want %v", err, errMuxClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not recheck cancellation after receiving a stream")
	}
}

func TestMuxSessionAcceptRejectsBufferedStreamAfterClose(t *testing.T) {
	session := newManualMuxSession(t, 1)
	session.accept <- newMuxStream(session, "stale-buffered-open")
	if err := session.Close(); err != nil {
		t.Fatalf("close mux session: %v", err)
	}
	if stream, err := session.Accept(); stream != nil || !errors.Is(err, errMuxClosed) {
		t.Fatalf("Accept after Close = (%v, %v), want (nil, %v)", stream, err, errMuxClosed)
	}
}

func TestMuxSessionParentCancelClosesPhysicalConnAndAccept(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	session := NewMuxSession(ctx, localConn, false)
	t.Cleanup(func() {
		_ = session.Close()
		_ = remoteConn.Close()
	})

	acceptResultCh := make(chan error, 1)
	go func() {
		_, err := session.Accept()
		acceptResultCh <- err
	}()
	physicalReadResultCh := make(chan error, 1)
	go func() {
		_, err := remoteConn.Read(make([]byte, 1))
		physicalReadResultCh <- err
	}()
	cancel()

	select {
	case err := <-acceptResultCh:
		if !errors.Is(err, errMuxClosed) {
			t.Fatalf("Accept after parent cancel = %v, want %v", err, errMuxClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancel did not unblock Accept")
	}
	select {
	case err := <-physicalReadResultCh:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("remote physical Read after parent cancel = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancel did not close the physical mux connection")
	}
}

func TestMuxSessionParentCancelClosesStreamsWithoutOrphans(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	serverCtx, cancelServer := context.WithCancel(context.Background())
	clientSession := NewMuxSession(context.Background(), clientConn, true)
	serverSession := NewMuxSession(serverCtx, serverConn, false)
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	clientStream, err := clientSession.OpenStream("parent-cancel-stream", "target-node", "origin-public-key")
	if err != nil {
		t.Fatalf("open mux stream: %v", err)
	}
	serverStream, err := serverSession.Accept()
	if err != nil {
		t.Fatalf("accept mux stream: %v", err)
	}
	readResultCh := make(chan error, 1)
	go func() {
		_, err := serverStream.Read(make([]byte, 1))
		readResultCh <- err
	}()
	acceptResultCh := make(chan error, 1)
	go func() {
		_, err := serverSession.Accept()
		acceptResultCh <- err
	}()
	cancelServer()

	select {
	case err := <-readResultCh:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("stream Read after parent cancel = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancel did not unblock stream Read")
	}
	select {
	case err := <-acceptResultCh:
		if !errors.Is(err, errMuxClosed) {
			t.Fatalf("Accept after parent cancel = %v, want %v", err, errMuxClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancel did not unblock the next Accept")
	}
	select {
	case <-clientSession.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("server parent cancel did not close the peer physical session")
	}
	select {
	case <-clientStream.Done():
	case <-time.After(time.Second):
		t.Fatal("peer stream remained open after physical session shutdown")
	}
	serverSession.mu.Lock()
	orphanStreams := len(serverSession.streams)
	serverSession.mu.Unlock()
	if orphanStreams != 0 || serverSession.ActiveStreams() != 0 {
		t.Fatalf("server session retained orphan streams: map=%d active=%d", orphanStreams, serverSession.ActiveStreams())
	}
}

func TestMuxStreamCloseInterruptsActivePhysicalDataWrite(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	physicalConn := newDeadlineControlledMuxPhysicalConn(clientPipe)
	clientSession := NewMuxSession(context.Background(), physicalConn, true)
	serverSession := NewMuxSession(context.Background(), serverPipe, false)
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	stream, err := clientSession.OpenStream("close-active-data", "target-node", "origin-public-key")
	if err != nil {
		t.Fatalf("open mux stream: %v", err)
	}
	if _, err := serverSession.Accept(); err != nil {
		t.Fatalf("accept mux stream: %v", err)
	}
	physicalConn.blockFutureWrites()

	writeResultCh := make(chan error, 1)
	go func() {
		_, writeErr := stream.Write([]byte("active-data"))
		writeResultCh <- writeErr
	}()
	select {
	case <-physicalConn.blockedWrite:
	case <-time.After(time.Second):
		t.Fatal("DATA did not reach the blocking physical write")
	}

	closeResultCh := make(chan error, 1)
	closeStartedAt := time.Now()
	go func() { closeResultCh <- stream.Close() }()
	select {
	case closeErr := <-closeResultCh:
		if closeErr != nil {
			t.Fatalf("MuxStream.Close: %v", closeErr)
		}
		if elapsed := time.Since(closeStartedAt); elapsed > time.Second {
			t.Fatalf("MuxStream.Close returned after %s, want at most 1s", elapsed)
		}
	case <-time.After(time.Second):
		_ = physicalConn.Close()
		t.Fatal("MuxStream.Close blocked behind its active physical DATA write")
	}
	select {
	case writeErr := <-writeResultCh:
		if !errors.Is(writeErr, os.ErrDeadlineExceeded) {
			t.Fatalf("interrupted DATA write = %v, want deadline exceeded", writeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("active DATA write remained blocked after stream Close")
	}
	if !clientSession.IsClosed() {
		t.Fatal("interrupted physical frame write did not terminate the mux session")
	}
}

func TestMuxStreamCloseInterruptsQueuedDataWrite(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	physicalConn := newDeadlineControlledMuxPhysicalConn(clientPipe)
	clientSession := NewMuxSession(context.Background(), physicalConn, true)
	serverSession := NewMuxSession(context.Background(), serverPipe, false)
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	openStream := func(id string) *MuxStream {
		t.Helper()
		stream, err := clientSession.OpenStream(id, "target-node", "origin-public-key")
		if err != nil {
			t.Fatalf("open mux stream %q: %v", id, err)
		}
		if _, err := serverSession.Accept(); err != nil {
			t.Fatalf("accept mux stream %q: %v", id, err)
		}
		return stream
	}
	blockingStream := openStream("close-queue-blocker")
	queuedStream := openStream("close-queued-data")
	physicalConn.blockFutureWrites()

	blockingResultCh := make(chan error, 1)
	go func() {
		_, writeErr := blockingStream.Write([]byte("blocking-data"))
		blockingResultCh <- writeErr
	}()
	select {
	case <-physicalConn.blockedWrite:
	case <-time.After(time.Second):
		t.Fatal("blocking DATA did not reach the physical connection")
	}

	queuedResultCh := make(chan error, 1)
	go func() {
		_, writeErr := queuedStream.Write([]byte("queued-data"))
		queuedResultCh <- writeErr
	}()
	pendingDeadline := time.Now().Add(time.Second)
	for clientSession.PendingFrames() < 2 && time.Now().Before(pendingDeadline) {
		time.Sleep(time.Millisecond)
	}
	if pending := clientSession.PendingFrames(); pending < 2 {
		t.Fatalf("pending mux frames = %d, want active plus queued DATA", pending)
	}

	closeResultCh := make(chan error, 1)
	closeStartedAt := time.Now()
	go func() { closeResultCh <- queuedStream.Close() }()
	select {
	case closeErr := <-closeResultCh:
		if closeErr != nil {
			t.Fatalf("queued MuxStream.Close: %v", closeErr)
		}
		if elapsed := time.Since(closeStartedAt); elapsed > time.Second {
			t.Fatalf("queued MuxStream.Close returned after %s, want at most 1s", elapsed)
		}
	case <-time.After(time.Second):
		_ = physicalConn.Close()
		t.Fatal("MuxStream.Close blocked behind queued DATA")
	}
	select {
	case writeErr := <-queuedResultCh:
		if !errors.Is(writeErr, errMuxStreamGone) {
			t.Fatalf("queued DATA write = %v, want %v", writeErr, errMuxStreamGone)
		}
	case <-time.After(time.Second):
		t.Fatal("queued DATA write remained blocked after stream Close")
	}
	if attempts := physicalConn.blockedWriteCount(); attempts != 1 {
		t.Fatalf("physical blocked write attempts = %d, want only the unrelated active stream", attempts)
	}
	if clientSession.IsClosed() {
		t.Fatal("closing a queued stream terminated the shared mux session")
	}
	select {
	case writeErr := <-blockingResultCh:
		t.Fatalf("queued stream Close interrupted another stream's active DATA: %v", writeErr)
	default:
	}

	_ = physicalConn.Close()
	select {
	case <-blockingResultCh:
	case <-time.After(time.Second):
		t.Fatal("blocking DATA did not return after physical connection close")
	}
}

func TestMuxSessionShortPhysicalWriteClosesSession(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	physicalConn := &shortWriteMuxPhysicalConn{Conn: clientPipe}
	clientSession := NewMuxSession(context.Background(), physicalConn, true)
	serverSession := NewMuxSession(context.Background(), serverPipe, false)
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	stream, err := clientSession.OpenStream("short-physical-write", "target-node", "origin-public-key")
	if err != nil {
		t.Fatalf("open mux stream: %v", err)
	}
	if _, err := serverSession.Accept(); err != nil {
		t.Fatalf("accept mux stream: %v", err)
	}
	physicalConn.failFutureWritesShort()

	written, err := stream.Write([]byte("short-write-data"))
	if written != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("logical write = (%d, %v), want (0, %v)", written, err, io.ErrShortWrite)
	}
	if !clientSession.IsClosed() {
		t.Fatal("short physical write did not close the mux session")
	}
}
