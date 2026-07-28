package networkFrameWork

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bnfs_p2p/network"
)

type relayBatchTestEndpoint struct {
	nodeID       string
	connectionID string
	batches      chan []*network.Frame
	closed       chan struct{}
	closeOnce    sync.Once
	nextID       atomic.Uint64

	mu           sync.Mutex
	singleCalls  int
	batchCalls   int
	handled      []*network.Frame
	writeErr     error
	writeStarted chan struct{}
	startOnce    sync.Once
	writeRelease <-chan struct{}
}

func newRelayBatchTestEndpoint(nodeID, connectionID string) *relayBatchTestEndpoint {
	return &relayBatchTestEndpoint{
		nodeID:       nodeID,
		connectionID: connectionID,
		batches:      make(chan []*network.Frame, 4),
		closed:       make(chan struct{}),
	}
}

func (endpoint *relayBatchTestEndpoint) NextFrame(ctx context.Context) (*network.Frame, error) {
	frames, err := endpoint.NextFrameBatch(ctx, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(frames) == 0 {
		return nil, errors.New("empty test frame batch")
	}
	return frames[0], nil
}

func (endpoint *relayBatchTestEndpoint) NextFrameBatch(ctx context.Context, _, _ int) ([]*network.Frame, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-endpoint.closed:
		return nil, errors.New("test endpoint closed")
	case frames := <-endpoint.batches:
		return frames, nil
	}
}

func (endpoint *relayBatchTestEndpoint) HandleFrame(ctx context.Context, frame *network.Frame) error {
	return endpoint.recordWrite(ctx, []*network.Frame{frame}, false)
}

func (endpoint *relayBatchTestEndpoint) HandleFrameBatch(ctx context.Context, frames []*network.Frame) error {
	return endpoint.recordWrite(ctx, frames, true)
}

func (endpoint *relayBatchTestEndpoint) recordWrite(ctx context.Context, frames []*network.Frame, batch bool) error {
	endpoint.mu.Lock()
	if batch {
		endpoint.batchCalls++
	} else {
		endpoint.singleCalls++
	}
	endpoint.mu.Unlock()

	if endpoint.writeStarted != nil {
		endpoint.startOnce.Do(func() { close(endpoint.writeStarted) })
	}
	if endpoint.writeRelease != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-endpoint.writeRelease:
		}
	}
	if endpoint.writeErr != nil {
		return endpoint.writeErr
	}

	endpoint.mu.Lock()
	for _, frame := range frames {
		endpoint.handled = append(endpoint.handled, cloneFrame(frame))
	}
	endpoint.mu.Unlock()
	return nil
}

func (endpoint *relayBatchTestEndpoint) AllocMessageId() uint64 {
	return endpoint.nextID.Add(1)
}

func (endpoint *relayBatchTestEndpoint) NodeId() string {
	return endpoint.nodeID
}

func (endpoint *relayBatchTestEndpoint) ConnectionId() string {
	return endpoint.connectionID
}

func (endpoint *relayBatchTestEndpoint) Close() error {
	endpoint.closeOnce.Do(func() { close(endpoint.closed) })
	return nil
}

func (endpoint *relayBatchTestEndpoint) snapshot() (singleCalls, batchCalls int, handled []*network.Frame) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	handled = make([]*network.Frame, len(endpoint.handled))
	for index, frame := range endpoint.handled {
		handled[index] = cloneFrame(frame)
	}
	return endpoint.singleCalls, endpoint.batchCalls, handled
}

func relayBatchFrames(count, payloadBytes int, messageID uint64, connectionID string) []*network.Frame {
	frames := make([]*network.Frame, count)
	for index := range frames {
		frames[index] = &network.Frame{
			MessageId:    messageID,
			SeqId:        uint32(index),
			TotalFrames:  uint32(count),
			FrameType:    network.FrameTypeData,
			ConnectionId: connectionID,
			Payload:      bytes.Repeat([]byte{byte(index)}, payloadBytes),
		}
	}
	return frames
}

func relayBatchWireSizedFrame(t *testing.T, wireBytes int, sequence uint32) *network.Frame {
	t.Helper()
	connectionID := "c"
	payloadBytes := wireBytes - network.FrameHeaderLength - len(connectionID)
	if payloadBytes < 0 {
		t.Fatalf("wire size %d is smaller than frame overhead", wireBytes)
	}
	frame := &network.Frame{
		MessageId:    1,
		SeqId:        sequence,
		TotalFrames:  3,
		FrameType:    network.FrameTypeData,
		ConnectionId: connectionID,
		Payload:      make([]byte, payloadBytes),
	}
	got, err := frame.WireSize()
	if err != nil || got != wireBytes {
		t.Fatalf("WireSize() = (%d, %v), want (%d, nil)", got, err, wireBytes)
	}
	return frame
}

func waitRelayBatchCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func TestPullFrameBatchFIFOAndLimits(t *testing.T) {
	t.Run("32 frame boundary", func(t *testing.T) {
		input := make(chan *network.Frame, 40)
		frames := relayBatchFrames(40, 8, 1, "conn-fifo")
		for _, frame := range frames {
			input <- frame
		}
		streamDone := make(chan struct{})
		var pending *network.Frame
		streamErr := func() error { return errors.New("stream stopped") }

		first, err := pullFrameBatch(context.Background(), streamDone, streamErr, input, &pending, 32, 1<<20)
		if err != nil {
			t.Fatalf("first pull: %v", err)
		}
		second, err := pullFrameBatch(context.Background(), streamDone, streamErr, input, &pending, 32, 1<<20)
		if err != nil {
			t.Fatalf("second pull: %v", err)
		}
		if len(first) != 32 || len(second) != 8 {
			t.Fatalf("batch lengths = (%d, %d), want (32, 8)", len(first), len(second))
		}
		combined := append(append([]*network.Frame(nil), first...), second...)
		for index, frame := range combined {
			if frame != frames[index] || frame.SeqId != uint32(index) {
				t.Fatalf("FIFO changed at index %d: got seq=%d", index, frame.SeqId)
			}
		}
	})

	t.Run("32 KiB boundary", func(t *testing.T) {
		input := make(chan *network.Frame, 3)
		frames := []*network.Frame{
			relayBatchWireSizedFrame(t, 16<<10, 0),
			relayBatchWireSizedFrame(t, 16<<10, 1),
			relayBatchWireSizedFrame(t, 128, 2),
		}
		for _, frame := range frames {
			input <- frame
		}
		streamDone := make(chan struct{})
		var pending *network.Frame
		streamErr := func() error { return errors.New("stream stopped") }

		first, err := pullFrameBatch(context.Background(), streamDone, streamErr, input, &pending, 32, 32<<10)
		if err != nil {
			t.Fatalf("first pull: %v", err)
		}
		if len(first) != 2 || first[0] != frames[0] || first[1] != frames[1] || pending != frames[2] {
			t.Fatalf("byte-limited batch did not preserve the overflow frame: len=%d pending=%p", len(first), pending)
		}
		second, err := pullFrameBatch(context.Background(), streamDone, streamErr, input, &pending, 32, 32<<10)
		if err != nil || len(second) != 1 || second[0] != frames[2] || pending != nil {
			t.Fatalf("pending pull = (%v, %v), pending=%p", second, err, pending)
		}
	})
}

func TestPullFrameBatchReturnsBufferedShortBatchWithoutWaiting(t *testing.T) {
	input := make(chan *network.Frame, 1)
	input <- relayBatchFrames(1, 8, 1, "conn-short")[0]
	streamDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var pending *network.Frame

	result := make(chan struct {
		frames []*network.Frame
		err    error
	}, 1)
	go func() {
		frames, err := pullFrameBatch(ctx, streamDone, func() error { return errors.New("stream stopped") }, input, &pending, 32, 32<<10)
		result <- struct {
			frames []*network.Frame
			err    error
		}{frames: frames, err: err}
	}()

	select {
	case got := <-result:
		if got.err != nil || len(got.frames) != 1 {
			t.Fatalf("short buffered pull = (%d frames, %v), want (1, nil)", len(got.frames), got.err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("pullFrameBatch waited for an already-short buffered batch to fill")
	}
}

func TestPullFrameBatchDrainsBufferedFrameAfterStreamStops(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		input := make(chan *network.Frame, 1)
		want := relayBatchFrames(1, 8, 1, "conn-final-ack")[0]
		input <- want
		streamDone := make(chan struct{})
		close(streamDone)
		var pending *network.Frame

		frames, err := pullFrameBatch(
			context.Background(),
			streamDone,
			func() error { return errors.New("stream stopped") },
			input,
			&pending,
			32,
			32<<10,
		)
		if err != nil || len(frames) != 1 || frames[0] != want {
			t.Fatalf("iteration %d final buffered pull = (%v, %v), want final frame", iteration, frames, err)
		}
	}
}

func TestPullFrameBatchDrainsBufferedFrameBeforeCancellation(t *testing.T) {
	input := make(chan *network.Frame, 1)
	want := relayBatchFrames(1, 8, 1, "conn-cancelled-final-ack")[0]
	input <- want
	streamDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var pending *network.Frame

	frames, err := pullFrameBatch(
		ctx,
		streamDone,
		func() error { return errors.New("stream stopped") },
		input,
		&pending,
		32,
		32<<10,
	)
	if err != nil || len(frames) != 1 || frames[0] != want {
		t.Fatalf("cancelled final buffered pull = (%v, %v), want final frame", frames, err)
	}
}

func TestPullFrameBatchHonorsCancellationWhileWaitingForFirstFrame(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	streamDone := make(chan struct{})
	input := make(chan *network.Frame)
	var pending *network.Frame
	frames, err := pullFrameBatch(ctx, streamDone, func() error { return errors.New("stream stopped") }, input, &pending, 32, 32<<10)
	if !errors.Is(err, context.Canceled) || frames != nil {
		t.Fatalf("cancelled pull = (%v, %v), want (nil, context.Canceled)", frames, err)
	}
}

func TestWriteEndpointFrameBatchUsesOneBatchCallInFIFOOrder(t *testing.T) {
	endpoint := newRelayBatchTestEndpoint("destination", "conn-direct")
	frames := relayBatchFrames(4, 16, 9, "conn-direct")
	if err := writeEndpointFrameBatch(context.Background(), endpoint, frames); err != nil {
		t.Fatalf("writeEndpointFrameBatch: %v", err)
	}
	singleCalls, batchCalls, handled := endpoint.snapshot()
	if singleCalls != 0 || batchCalls != 1 || len(handled) != len(frames) {
		t.Fatalf("write calls = single:%d batch:%d handled:%d", singleCalls, batchCalls, len(handled))
	}
	for index, frame := range handled {
		if frame.SeqId != uint32(index) || !bytes.Equal(frame.Payload, frames[index].Payload) {
			t.Fatalf("batch order changed at index %d", index)
		}
	}
}

func TestPumpClientToRelayUsesOneBatchWriteInFIFOOrder(t *testing.T) {
	client := newRelayBatchTestEndpoint("client", "conn-pump")
	relay := newRelayBatchTestEndpoint("relay", "")
	relay.writeStarted = make(chan struct{})
	routes := newFrameRouteRegistry()
	frames := relayBatchFrames(4, 32, 77, client.ConnectionId())
	client.batches <- frames

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pumpClientToRelay(ctx, client, relay, routes, nil, "relay")
		close(done)
	}()
	select {
	case <-relay.writeStarted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("pump did not issue the batch write")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pump did not stop after cancellation")
	}

	singleCalls, batchCalls, handled := relay.snapshot()
	if singleCalls != 0 || batchCalls != 1 || len(handled) != len(frames) {
		t.Fatalf("pump writes = single:%d batch:%d handled:%d", singleCalls, batchCalls, len(handled))
	}
	destinationID := handled[0].MessageId
	if destinationID == frames[0].MessageId {
		t.Fatal("pump did not translate the source MessageId")
	}
	for index, frame := range handled {
		if frame.MessageId != destinationID || frame.SeqId != uint32(index) || !bytes.Equal(frame.Payload, frames[index].Payload) {
			t.Fatalf("pump batch order or route translation changed at index %d", index)
		}
		if frames[index].MessageId != 77 {
			t.Fatalf("pump mutated source frame %d", index)
		}
	}
}

func TestPumpRelayBatchAccountingRollsBackFailuresAndIsolatesHookBoundary(t *testing.T) {
	relay := newRelayBatchTestEndpoint("relay", "")
	failedClient := newRelayBatchTestEndpoint("failed-client", "conn-hook-fail")
	failedClient.writeErr = errors.New("injected data batch failure")
	successfulClient := newRelayBatchTestEndpoint("successful-client", "conn-hook-success")
	routes := newFrameRouteRegistry()

	failedFrames := relayBatchFrames(2, 10, 201, failedClient.ConnectionId())
	successfulFrames := []*network.Frame{
		{
			MessageId:    202,
			SeqId:        0,
			TotalFrames:  3,
			FrameType:    network.FrameTypeData,
			ConnectionId: successfulClient.ConnectionId(),
			Payload:      make([]byte, 15),
		},
		{
			MessageId:    202,
			SeqId:        1,
			TotalFrames:  3,
			FrameType:    network.FrameTypeData,
			ConnectionId: successfulClient.ConnectionId(),
			Payload:      make([]byte, 15),
		},
		{
			MessageId:    202,
			SeqId:        2,
			TotalFrames:  3,
			FrameType:    network.FrameTypeData,
			ConnectionId: successfulClient.ConnectionId(),
			Payload:      make([]byte, 70),
		},
	}
	relay.batches <- failedFrames
	relay.batches <- successfulFrames

	hookStats := make(chan ForwardStats, 1)
	hookConfig := &ForwardHookConfig{
		ThresholdBytes: 100,
		Hook: func(_ context.Context, stats *ForwardStats) error {
			hookStats <- *stats
			return nil
		},
	}
	clientFailure := make(chan struct{}, 1)
	lookup := func(connectionID string) FrameRelayEndpoint {
		switch connectionID {
		case failedClient.ConnectionId():
			return failedClient
		case successfulClient.ConnectionId():
			return successfulClient
		default:
			return nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pumpRelayToClients(ctx, relay, lookup, routes, hookConfig, "server-hook", func(string, FrameRelayEndpoint) {
			clientFailure <- struct{}{}
		})
		close(done)
	}()
	select {
	case <-clientFailure:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("failed data batch did not report its write failure")
	}

	var stats ForwardStats
	select {
	case stats = <-hookStats:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("successful frames did not reach the hook threshold")
	}
	waitRelayBatchCondition(t, func() bool {
		_, _, handled := successfulClient.snapshot()
		return len(handled) == len(successfulFrames)
	})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("hook accounting pump did not stop after cancellation")
	}

	if stats.TotalBytes != 100 || stats.TotalFrames != 3 {
		t.Fatalf("hook stats = %d bytes/%d frames, want only committed 100 bytes/3 frames", stats.TotalBytes, stats.TotalFrames)
	}
	failedSingle, failedBatch, failedHandled := failedClient.snapshot()
	if failedSingle != 0 || failedBatch != 1 || len(failedHandled) != 0 {
		t.Fatalf("failed destination writes = single:%d batch:%d handled:%d", failedSingle, failedBatch, len(failedHandled))
	}
	successSingle, successBatch, successHandled := successfulClient.snapshot()
	if successSingle != 1 || successBatch != 1 || len(successHandled) != 3 {
		t.Fatalf("successful destination writes = single:%d batch:%d handled:%d, want threshold frame isolated", successSingle, successBatch, len(successHandled))
	}
}

func TestPumpRelayToClientsCompletesRouteOnlyAfterAckWriteSucceeds(t *testing.T) {
	relay := newRelayBatchTestEndpoint("relay", "")
	client := newRelayBatchTestEndpoint("client", "conn-ack")
	client.writeStarted = make(chan struct{})
	release := make(chan struct{})
	client.writeRelease = release
	routes := newFrameRouteRegistry()
	pair, ok := routes.bindPair(
		91,
		&frameRouteEntry{dest: client, dstID: 501},
		clientRouteKey{connectionID: client.ConnectionId(), messageID: 501},
		&frameRouteEntry{dest: relay, dstID: 91},
		3,
	)
	if !ok {
		t.Fatal("failed to bind ACK route")
	}
	ack, err := network.BuildAckFrame(91, 3, network.FullAckRange(3))
	if err != nil {
		t.Fatal(err)
	}
	ack.ConnectionId = client.ConnectionId()
	relay.batches <- []*network.Frame{ack}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pumpRelayToClients(ctx, relay, func(string) FrameRelayEndpoint { return client }, routes, nil, "relay", nil)
		close(done)
	}()
	select {
	case <-client.writeStarted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("ACK write did not start")
	}
	routes.mu.Lock()
	completedBeforeWrite := pair.completed
	routes.mu.Unlock()
	if completedBeforeWrite {
		close(release)
		cancel()
		t.Fatal("route completed before the destination accepted the ACK")
	}

	close(release)
	waitRelayBatchCondition(t, func() bool {
		routes.mu.Lock()
		defer routes.mu.Unlock()
		return pair.completed
	})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ACK pump did not stop after cancellation")
	}
	_, _, handled := client.snapshot()
	if len(handled) != 1 || handled[0].MessageId != 501 {
		t.Fatalf("forwarded ACK did not use the client route: %#v", handled)
	}
}

func TestPumpRelayToClientsDoesNotCompleteRouteAfterAckWriteFailure(t *testing.T) {
	relay := newRelayBatchTestEndpoint("relay", "")
	client := newRelayBatchTestEndpoint("client", "conn-ack-fail")
	client.writeErr = errors.New("injected ACK write failure")
	routes := newFrameRouteRegistry()
	pair, ok := routes.bindPair(
		92,
		&frameRouteEntry{dest: client, dstID: 502},
		clientRouteKey{connectionID: client.ConnectionId(), messageID: 502},
		&frameRouteEntry{dest: relay, dstID: 92},
		2,
	)
	if !ok {
		t.Fatal("failed to bind ACK route")
	}
	ack, err := network.BuildAckFrame(92, 2, network.FullAckRange(2))
	if err != nil {
		t.Fatal(err)
	}
	ack.ConnectionId = client.ConnectionId()
	relay.batches <- []*network.Frame{ack}
	failure := make(chan struct{}, 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pumpRelayToClients(ctx, relay, func(string) FrameRelayEndpoint { return client }, routes, nil, "relay", func(string, FrameRelayEndpoint) {
			failure <- struct{}{}
		})
		close(done)
	}()
	select {
	case <-failure:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("failed ACK write did not report the destination failure")
	}
	routes.mu.Lock()
	completed := pair.completed
	routes.mu.Unlock()
	if completed {
		cancel()
		t.Fatal("failed ACK write completed the route")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed ACK pump did not stop after cancellation")
	}
	singleCalls, batchCalls, handled := client.snapshot()
	if singleCalls != 1 || batchCalls != 0 || len(handled) != 0 {
		t.Fatalf("failed ACK write accounting = single:%d batch:%d handled:%d", singleCalls, batchCalls, len(handled))
	}
}

type relayBatchScriptedConn struct {
	mu      sync.Mutex
	writes  int
	closes  int
	data    []byte
	writeFn func(int) (int, error)
}

func (connection *relayBatchScriptedConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (connection *relayBatchScriptedConn) Write(payload []byte) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.writes++
	written, err := len(payload), error(nil)
	if connection.writeFn != nil {
		written, err = connection.writeFn(len(payload))
	}
	if written < 0 {
		written = 0
	}
	if written > len(payload) {
		written = len(payload)
	}
	connection.data = append(connection.data, payload[:written]...)
	return written, err
}

func (connection *relayBatchScriptedConn) Close() error {
	connection.mu.Lock()
	connection.closes++
	connection.mu.Unlock()
	return nil
}

func (connection *relayBatchScriptedConn) LocalAddr() net.Addr              { return nil }
func (connection *relayBatchScriptedConn) RemoteAddr() net.Addr             { return nil }
func (connection *relayBatchScriptedConn) SetDeadline(time.Time) error      { return nil }
func (connection *relayBatchScriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *relayBatchScriptedConn) SetWriteDeadline(time.Time) error { return nil }

func (connection *relayBatchScriptedConn) snapshot() (writes, closes int, data []byte) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.writes, connection.closes, append([]byte(nil), connection.data...)
}

func TestTcpStreamHandleFrameBatchWritesOneOrderedBuffer(t *testing.T) {
	connection := &relayBatchScriptedConn{}
	stream := newTcpStream("peer", "conn-wire", connection)
	defer stream.Close()
	stream.frameSizeAdaptor = nil
	frames := relayBatchFrames(4, 33, 121, "conn-wire")

	if err := stream.HandleFrameBatch(context.Background(), frames); err != nil {
		t.Fatalf("HandleFrameBatch: %v", err)
	}
	writes, _, data := connection.snapshot()
	if writes != 1 {
		t.Fatalf("physical Write calls = %d, want 1", writes)
	}
	reader := bytes.NewReader(data)
	for index, expected := range frames {
		got, err := network.ReadFrame(reader)
		if err != nil {
			t.Fatalf("read encoded frame %d: %v", index, err)
		}
		if got.MessageId != expected.MessageId || got.SeqId != expected.SeqId || got.ConnectionId != expected.ConnectionId || !bytes.Equal(got.Payload, expected.Payload) {
			t.Fatalf("encoded frame %d changed: %#v", index, got)
		}
	}
	if reader.Len() != 0 {
		t.Fatalf("batch buffer retained %d trailing bytes", reader.Len())
	}
}

func TestTcpStreamHandleFrameBatchTreatsShortWritesAsFatal(t *testing.T) {
	injected := errors.New("injected short write error")
	tests := []struct {
		name     string
		writeErr error
		wantErr  error
	}{
		{name: "short write without error", wantErr: io.ErrShortWrite},
		{name: "short write with error", writeErr: injected, wantErr: injected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := &relayBatchScriptedConn{
				writeFn: func(size int) (int, error) {
					return size - 1, test.writeErr
				},
			}
			stream := newTcpStream("peer", "conn-short-write", connection)
			stream.frameSizeAdaptor = nil
			frames := relayBatchFrames(2, 16, 131, "conn-short-write")

			err := stream.HandleFrameBatch(context.Background(), frames)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("HandleFrameBatch error = %v, want %v", err, test.wantErr)
			}
			if !errors.Is(stream.fatal(), test.wantErr) {
				t.Fatalf("fatal error = %v, want %v", stream.fatal(), test.wantErr)
			}
			select {
			case <-stream.streamCtx.Done():
			default:
				t.Fatal("short write did not cancel the stream")
			}
			writes, closes, _ := connection.snapshot()
			if writes != 1 || closes != 1 {
				t.Fatalf("short write lifecycle = writes:%d closes:%d, want 1/1", writes, closes)
			}
			if err := stream.HandleFrameBatch(context.Background(), frames); !errors.Is(err, test.wantErr) {
				t.Fatalf("write after fatal error = %v, want %v", err, test.wantErr)
			}
			writesAfterFatal, _, _ := connection.snapshot()
			if writesAfterFatal != 1 {
				t.Fatalf("fatal stream issued another physical Write: %d", writesAfterFatal)
			}
		})
	}
}

type relayBatchCountingConn struct {
	net.Conn
	writes atomic.Int64
}

func (connection *relayBatchCountingConn) Write(payload []byte) (int, error) {
	connection.writes.Add(1)
	return connection.Conn.Write(payload)
}

func BenchmarkTcpStreamCompletedFrameWrites(b *testing.B) {
	for _, benchmark := range []struct {
		name  string
		batch bool
	}{
		{name: "serial_32x800B", batch: false},
		{name: "batch_32x800B", batch: true},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			frames := relayBatchFrames(32, 800, 141, "conn-benchmark")
			bytesPerOperation := 0
			for _, frame := range frames {
				size, err := frame.WireSize()
				if err != nil {
					b.Fatal(err)
				}
				bytesPerOperation += size
			}

			writer, reader := net.Pipe()
			connection := &relayBatchCountingConn{Conn: writer}
			stream := newTcpStream("peer", "conn-benchmark", connection)
			stream.frameSizeAdaptor = nil
			receiveDone := make(chan error, 1)
			totalBytes := int64(bytesPerOperation) * int64(b.N)
			go func() {
				received, err := io.CopyN(io.Discard, reader, totalBytes)
				if err == nil && received != totalBytes {
					err = io.ErrUnexpectedEOF
				}
				receiveDone <- err
			}()

			ctx := context.Background()
			b.ReportAllocs()
			b.SetBytes(int64(bytesPerOperation))
			b.ResetTimer()
			var writeErr error
			for operation := 0; operation < b.N && writeErr == nil; operation++ {
				if benchmark.batch {
					writeErr = stream.HandleFrameBatch(ctx, frames)
					continue
				}
				for _, frame := range frames {
					if writeErr = stream.HandleFrame(ctx, frame); writeErr != nil {
						break
					}
				}
			}
			if writeErr != nil {
				_ = stream.Close()
			}
			receiveErr := <-receiveDone
			b.StopTimer()
			writes := connection.writes.Load()
			_ = stream.Close()
			_ = reader.Close()
			if writeErr != nil {
				b.Fatalf("write failed: %v", writeErr)
			}
			if receiveErr != nil {
				b.Fatalf("receiver did not consume all bytes: %v", receiveErr)
			}
			b.ReportMetric(float64(writes)/float64(b.N), "writes/op")
			b.ReportMetric(float64(len(frames)), "frames/op")
		})
	}
}
