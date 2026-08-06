package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func holdbackTestE2ERecord(plaintextBytes int, marker byte) []byte {
	return holdbackTestE2ERecordForSession(plaintextBytes, marker, 0xa5)
}

func holdbackTestE2ERecordForSession(plaintextBytes int, marker, sessionMarker byte) []byte {
	record := make([]byte, 64+plaintextBytes+16)
	copy(record[:8], "BNFSE2E2")
	record[8] = 2
	record[9] = 1
	record[10] = marker & 1
	binary.BigEndian.PutUint32(record[12:16], 1)
	binary.BigEndian.PutUint64(record[16:24], uint64(marker)+1)
	for index := 24; index < 56; index++ {
		record[index] = sessionMarker
	}
	binary.BigEndian.PutUint64(record[56:64], uint64(plaintextBytes))
	for index := 64; index < len(record); index++ {
		record[index] = marker
	}
	return record
}

func holdbackTestFrames(t *testing.T, messageID uint64, connectionID, route string, payload []byte, billable bool, maxPayload int) []*network.Frame {
	return holdbackTestSequenceFrames(t, messageID, messageID, connectionID, route, payload, billable, maxPayload)
}

func holdbackTestSequenceFrames(t *testing.T, messageID, billingSequence uint64, connectionID, route string, payload []byte, billable bool, maxPayload int) []*network.Frame {
	t.Helper()
	header := &network.Header{
		RouteName: route, NodeId: "holdback-test-node", NodeIdVersion: 1, ConnectionId: connectionID,
	}
	if billable {
		header.BillingSessionID[0] = 1
		header.BillingSequence = billingSequence
		header.BillingBytes = binary.BigEndian.Uint64(payload[56:64])
	}
	frames, err := (&network.Message{Header: header, Payload: payload}).SplitToFrames(messageID, maxPayload)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		frame.ConnectionId = connectionID
	}
	return frames
}

func holdbackTestConfig(hook func(context.Context, *BillableRecord) error) *ForwardHookConfig {
	return &ForwardHookConfig{
		BillableRoute:      "/p2p/message",
		BillableRecordHook: hook,
		BillableRecordRequired: func(_, direction string) bool {
			return direction == "relay_to_clients"
		},
	}
}

func holdbackTestForwardMessage(state *forwardHookState, frames []*network.Frame) ([]*network.Frame, error) {
	var ready []*network.Frame
	for _, frame := range frames {
		forwarded, err := state.framesForForward(context.Background(), frame, "relay_to_clients")
		if err != nil {
			return nil, err
		}
		if len(forwarded) != 0 {
			ready = forwarded
		}
	}
	return ready, nil
}

func TestPumpRelayToClientsHoldsAllFramesUntilBillingApproval(t *testing.T) {
	relay := newRelayBatchTestEndpoint("relay", "")
	client := newRelayBatchTestEndpoint("client", "conn-holdback")
	record := holdbackTestE2ERecord(512, 1)
	frames := holdbackTestFrames(t, 41, client.ConnectionId(), "/p2p/message", record, true, 96)
	if len(frames) < 3 {
		t.Fatal("test message must span several frames")
	}
	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	config := holdbackTestConfig(func(ctx context.Context, _ *BillableRecord) error {
		close(hookStarted)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-hookRelease:
			return nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pumpRelayToClients(ctx, relay, func(string) FrameRelayEndpoint { return client }, newFrameRouteRegistry(), config, "server-holdback", nil)
		close(done)
	}()
	relay.batches <- frames[:len(frames)-1]
	time.Sleep(20 * time.Millisecond)
	if _, _, handled := client.snapshot(); len(handled) != 0 {
		cancel()
		t.Fatal("partial billable message escaped the holdback")
	}
	relay.batches <- frames[len(frames)-1:]
	select {
	case <-hookStarted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("complete message did not reach the billing hook")
	}
	if _, _, handled := client.snapshot(); len(handled) != 0 {
		cancel()
		t.Fatal("frames were forwarded before the billing hook approved the message")
	}
	close(hookRelease)
	waitRelayBatchCondition(t, func() bool {
		_, _, handled := client.snapshot()
		return len(handled) == len(frames)
	})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("holdback pump did not stop")
	}
}

func TestPumpRelayToClientsRetainsDeferredMessageUntilPredecessorArrives(t *testing.T) {
	relay := newRelayBatchTestEndpoint("relay", "")
	client := newRelayBatchTestEndpoint("client", "conn-deferred-retransmit")
	futureFrames := holdbackTestSequenceFrames(
		t, 42, 2, client.ConnectionId(), "/p2p/message", holdbackTestE2ERecord(512, 2), true, 96,
	)
	firstFrames := holdbackTestSequenceFrames(
		t, 41, 1, client.ConnectionId(), "/p2p/message", holdbackTestE2ERecord(512, 1), true, 96,
	)
	var hookCalls atomic.Int32
	var nextSequence atomic.Uint64
	nextSequence.Store(1)
	config := holdbackTestConfig(func(_ context.Context, record *BillableRecord) error {
		hookCalls.Add(1)
		if record.Sequence != nextSequence.Load() {
			return ErrBillableRecordDeferred
		}
		nextSequence.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pumpRelayToClients(ctx, relay, func(string) FrameRelayEndpoint { return client }, newFrameRouteRegistry(), config, "server-deferred", nil)
		close(done)
	}()
	relay.batches <- futureFrames
	waitRelayBatchCondition(t, func() bool { return hookCalls.Load() == 1 })
	if _, _, handled := client.snapshot(); len(handled) != 0 {
		cancel()
		t.Fatal("deferred billing record was written before its predecessor")
	}
	select {
	case <-done:
		t.Fatal("retryable billing deferral stopped the frame pump")
	default:
	}

	relay.batches <- firstFrames
	waitRelayBatchCondition(t, func() bool {
		_, _, handled := client.snapshot()
		return len(handled) == len(firstFrames)+len(futureFrames)
	})
	if hookCalls.Load() != 3 {
		cancel()
		t.Fatalf("billing hook calls = %d, want 3", hookCalls.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deferred retransmit pump did not stop")
	}
}

func TestPumpRelayToClientsBillingViolationClosesOnlyItsConnection(t *testing.T) {
	relay := newRelayBatchTestEndpoint("relay", "")
	badClient := newRelayBatchTestEndpoint("bad-client", "conn-bad-billing")
	goodClient := newRelayBatchTestEndpoint("good-client", "conn-good-billing")
	badFrames := holdbackTestFrames(t, 51, badClient.ConnectionId(), "/p2p/message", holdbackTestE2ERecord(32, 2), false, 128)
	goodFrames := holdbackTestFrames(t, 52, goodClient.ConnectionId(), "/p2p/message", holdbackTestE2ERecord(48, 3), true, 128)
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil })
	failures := make(chan string, 1)
	lookup := func(connectionID string) FrameRelayEndpoint {
		switch connectionID {
		case badClient.ConnectionId():
			return badClient
		case goodClient.ConnectionId():
			return goodClient
		default:
			return nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pumpRelayToClients(ctx, relay, lookup, newFrameRouteRegistry(), config, "server-isolation", func(connectionID string, endpoint FrameRelayEndpoint) {
			_ = endpoint.Close()
			failures <- connectionID
		})
		close(done)
	}()
	relay.batches <- badFrames
	relay.batches <- goodFrames
	select {
	case connectionID := <-failures:
		if connectionID != badClient.ConnectionId() {
			cancel()
			t.Fatalf("closed connection = %q, want bad connection", connectionID)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("billing violation did not close its connection")
	}
	waitRelayBatchCondition(t, func() bool {
		_, _, handled := goodClient.snapshot()
		return len(handled) == len(goodFrames)
	})
	if _, _, handled := badClient.snapshot(); len(handled) != 0 {
		cancel()
		t.Fatal("invalid connection forwarded data before being closed")
	}
	select {
	case <-goodClient.closed:
		cancel()
		t.Fatal("a billing violation closed an unrelated connection")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("isolation pump did not stop")
	}
}

func TestBillingHoldbackRejectsConflictingFramesAndCachesApproval(t *testing.T) {
	var hookCalls atomic.Int32
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error {
		hookCalls.Add(1)
		return nil
	})
	state := newForwardHookState(config, "server-conflict")
	frames := holdbackTestFrames(t, 61, "conn-conflict", "/p2p/message", holdbackTestE2ERecord(128, 4), true, 128)
	if len(frames) < 2 {
		t.Fatal("test message must span multiple frames")
	}
	if ready, err := state.framesForForward(context.Background(), frames[0], "relay_to_clients"); err != nil || len(ready) != 0 {
		t.Fatalf("first partial frame = (%d, %v), want held", len(ready), err)
	}
	conflict := cloneFrame(frames[0])
	conflict.Payload[len(conflict.Payload)-1] ^= 0xff
	if _, err := state.framesForForward(context.Background(), conflict, "relay_to_clients"); err == nil || !strings.Contains(err.Error(), "conflicting content") {
		t.Fatalf("conflicting duplicate error = %v", err)
	}
	config.forgetHeldConnection("server-conflict", "conn-conflict")

	for index, frame := range frames {
		ready, err := state.framesForForward(context.Background(), frame, "relay_to_clients")
		if err != nil {
			t.Fatal(err)
		}
		if index < len(frames)-1 && len(ready) != 0 {
			t.Fatal("incomplete retry escaped holdback")
		}
		if index == len(frames)-1 && len(ready) != len(frames) {
			t.Fatalf("approved frame count = %d, want %d", len(ready), len(frames))
		}
	}
	if hookCalls.Load() != 1 {
		t.Fatalf("billing hook calls = %d, want 1", hookCalls.Load())
	}
	retransmit := cloneFrame(frames[0])
	retransmit.FrameType = network.FrameTypeRetransmit
	ready, err := state.framesForForward(context.Background(), retransmit, "relay_to_clients")
	if err != nil || len(ready) != 1 {
		t.Fatalf("approved retransmit = (%d, %v), want immediate pass", len(ready), err)
	}
	if hookCalls.Load() != 1 {
		t.Fatal("approved retransmit invoked the billing hook again")
	}
	forged := cloneFrame(retransmit)
	forged.Payload[0] ^= 0xff
	if _, err := state.framesForForward(context.Background(), forged, "relay_to_clients"); err == nil {
		t.Fatal("forged retransmit was accepted")
	}
}

func TestBillingHoldbackPreludeWhitelistAndPhase(t *testing.T) {
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil })
	state := newForwardHookState(config, "server-prelude")
	noiseHello := make([]byte, 8+1+65)
	copy(noiseHello, "BNFSN2H1")
	noiseHello[8] = 2
	noiseFrames := holdbackTestFrames(t, 71, "conn-prelude", "", noiseHello, false, 512)
	if ready, err := state.framesForForward(context.Background(), noiseFrames[0], "relay_to_clients"); err != nil || len(ready) != 1 {
		t.Fatalf("Noise hello = (%d, %v), want allowed", len(ready), err)
	}
	handshakeFrames := holdbackTestFrames(t, 72, "conn-prelude", billingHandshakeInfoRoute, holdbackTestE2ERecord(32, 5), false, 512)
	if ready, err := state.framesForForward(context.Background(), handshakeFrames[0], "relay_to_clients"); err != nil || len(ready) != 1 {
		t.Fatalf("handshake metadata = (%d, %v), want allowed", len(ready), err)
	}
	repeatedHandshake := holdbackTestFrames(t, 73, "conn-prelude", billingHandshakeInfoRoute, holdbackTestE2ERecord(32, 6), false, 512)
	if _, err := state.framesForForward(context.Background(), repeatedHandshake[0], "relay_to_clients"); err == nil {
		t.Fatal("repeated handshake metadata was accepted")
	}

	billingFrames := holdbackTestFrames(t, 74, "conn-established", "/p2p/message", holdbackTestE2ERecord(64, 7), true, 512)
	if ready, err := state.framesForForward(context.Background(), billingFrames[0], "relay_to_clients"); err != nil || len(ready) != 1 {
		t.Fatalf("billable message = (%d, %v), want allowed", len(ready), err)
	}
	lateNoise := holdbackTestFrames(t, 75, "conn-established", "", noiseHello, false, 512)
	if _, err := state.framesForForward(context.Background(), lateNoise[0], "relay_to_clients"); err == nil {
		t.Fatal("free Noise prelude was accepted after billable data")
	}

	missingBilling := holdbackTestFrames(t, 76, "conn-missing", "/p2p/message", holdbackTestE2ERecord(16, 8), false, 512)
	if _, err := state.framesForForward(context.Background(), missingBilling[0], "relay_to_clients"); err == nil {
		t.Fatal("authenticated data without billing metadata was accepted")
	}
	invalidPrelude := holdbackTestFrames(t, 77, "conn-invalid-prelude", "", []byte("not-noise"), false, 512)
	if _, err := state.framesForForward(context.Background(), invalidPrelude[0], "relay_to_clients"); err == nil {
		t.Fatal("arbitrary empty-route data was accepted as Noise")
	}
	partial := &network.Message{
		Header:  &network.Header{RouteName: "/p2p/message", ConnectionId: "conn-partial", PayLoadLength: 1, BillingSequence: 1},
		Payload: []byte{1},
	}
	if _, err := state.validateHeldMessage(context.Background(), partial, "conn-partial", "relay_to_clients", messageHoldbackPhase{}); err == nil || !strings.Contains(err.Error(), "partial billing metadata") {
		t.Fatalf("partial billing metadata error = %v", err)
	}

	ack := &network.Frame{FrameType: network.FrameTypeAck, ConnectionId: "conn-established", MessageId: 74, TotalFrames: 1}
	ready, err := state.framesForForward(context.Background(), ack, "relay_to_clients")
	if err != nil || len(ready) != 1 || ready[0] != ack {
		t.Fatalf("ACK bypass = (%d, %v)", len(ready), err)
	}
}

func TestBillingHoldbackAllowsOnlyEmptyE2EKeepAliveAfterHandshake(t *testing.T) {
	approveHandshake := func(t *testing.T, state *forwardHookState, connectionID string, messageID uint64) {
		t.Helper()
		frames := holdbackTestFrames(t, messageID, connectionID, billingHandshakeInfoRoute, holdbackTestE2ERecord(32, byte(messageID)), false, 512)
		ready, err := holdbackTestForwardMessage(state, frames)
		if err != nil || len(ready) != len(frames) {
			t.Fatalf("handshake metadata = (%d, %v), want %d allowed frames", len(ready), err, len(frames))
		}
	}

	t.Run("before handshake", func(t *testing.T) {
		state := newForwardHookState(holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil }), "server-ping-before")
		frames := holdbackTestFrames(t, 81, "conn-ping-before", KeepAliveRoute, holdbackTestE2ERecord(0, 11), false, 512)
		if _, err := holdbackTestForwardMessage(state, frames); err == nil || !strings.Contains(err.Error(), "current phase") {
			t.Fatalf("pre-handshake keepalive error = %v", err)
		}
	})

	t.Run("malformed or nonempty record", func(t *testing.T) {
		config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil })
		state := newForwardHookState(config, "server-ping-invalid")
		approveHandshake(t, state, "conn-ping-invalid", 82)

		malformed := holdbackTestFrames(t, 83, "conn-ping-invalid", KeepAliveRoute, []byte("not-an-e2e-record"), false, 512)
		if _, err := holdbackTestForwardMessage(state, malformed); err == nil || !strings.Contains(err.Error(), "not an E2E record") {
			t.Fatalf("malformed keepalive error = %v", err)
		}

		nonempty := holdbackTestFrames(t, 84, "conn-ping-invalid", KeepAliveRoute, holdbackTestE2ERecord(1, 12), false, 512)
		if _, err := holdbackTestForwardMessage(state, nonempty); err == nil || !strings.Contains(err.Error(), "plaintext is not empty") {
			t.Fatalf("nonempty keepalive error = %v", err)
		}
	})

	t.Run("billing metadata", func(t *testing.T) {
		config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil })
		state := newForwardHookState(config, "server-ping-billed")
		approveHandshake(t, state, "conn-ping-billed", 85)

		payload := holdbackTestE2ERecord(0, 13)
		header := &network.Header{
			RouteName: KeepAliveRoute, NodeId: "holdback-test-node", NodeIdVersion: 1,
			ConnectionId: "conn-ping-billed", BillingSequence: 1, BillingBytes: 1,
		}
		header.BillingSessionID[0] = 1
		frames, err := (&network.Message{Header: header, Payload: payload}).SplitToFrames(86, 512)
		if err != nil {
			t.Fatal(err)
		}
		for _, frame := range frames {
			frame.ConnectionId = header.ConnectionId
		}
		if _, err := holdbackTestForwardMessage(state, frames); err == nil || !strings.Contains(err.Error(), "current phase") {
			t.Fatalf("billed keepalive error = %v", err)
		}
	})

	t.Run("preserves billing phase", func(t *testing.T) {
		var hookCalls atomic.Int32
		config := holdbackTestConfig(func(context.Context, *BillableRecord) error {
			hookCalls.Add(1)
			return nil
		})
		state := newForwardHookState(config, "server-ping-valid")
		connectionID := "conn-ping-valid"
		approveHandshake(t, state, connectionID, 87)

		ping := holdbackTestFrames(t, 88, connectionID, KeepAliveRoute, holdbackTestE2ERecord(0, 14), false, 512)
		if ready, err := holdbackTestForwardMessage(state, ping); err != nil || len(ready) != len(ping) {
			t.Fatalf("post-handshake keepalive = (%d, %v), want %d allowed frames", len(ready), err, len(ping))
		}

		holdback := config.ensureMessageHoldback()
		connectionKey := messageHoldbackConnectionKey{nodeID: "server-ping-valid", connectionID: connectionID}
		holdback.mu.Lock()
		connection := holdback.connections[connectionKey]
		if connection == nil || !connection.handshakeInfoSeen || connection.billingEstablished {
			holdback.mu.Unlock()
			t.Fatalf("phase after keepalive = %#v, want handshake=true billing=false", connection)
		}
		holdback.mu.Unlock()

		billable := holdbackTestFrames(t, 89, connectionID, "/p2p/message", holdbackTestE2ERecord(64, 15), true, 512)
		if ready, err := holdbackTestForwardMessage(state, billable); err != nil || len(ready) != len(billable) {
			t.Fatalf("billable message after keepalive = (%d, %v), want %d allowed frames", len(ready), err, len(billable))
		}
		if hookCalls.Load() != 1 {
			t.Fatalf("billing hook calls = %d, want 1", hookCalls.Load())
		}

		secondPing := holdbackTestFrames(t, 90, connectionID, KeepAliveRoute, holdbackTestE2ERecord(0, 16), false, 512)
		if ready, err := holdbackTestForwardMessage(state, secondPing); err != nil || len(ready) != len(secondPing) {
			t.Fatalf("established keepalive = (%d, %v), want %d allowed frames", len(ready), err, len(secondPing))
		}
		holdback.mu.Lock()
		connection = holdback.connections[connectionKey]
		if connection == nil || !connection.handshakeInfoSeen || !connection.billingEstablished {
			holdback.mu.Unlock()
			t.Fatalf("phase after billing keepalive = %#v, want handshake=true billing=true", connection)
		}
		holdback.mu.Unlock()
	})
}

func TestBillingHoldbackAllowsKeepAliveAfterValidatedMigrationRecord(t *testing.T) {
	var hookCalls atomic.Int32
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error {
		hookCalls.Add(1)
		return nil
	})
	state := newForwardHookState(config, "server-migrated", "registration-new-relay")
	connectionID := "conn-migrated"

	billable := holdbackTestFrames(
		t, 91, connectionID, "/p2p/message",
		holdbackTestE2ERecordForSession(64, 17, 0x51), true, 512,
	)
	if ready, err := holdbackTestForwardMessage(state, billable); err != nil || len(ready) != len(billable) {
		t.Fatalf("first migrated billable record = (%d, %v), want %d allowed frames", len(ready), err, len(billable))
	}
	if hookCalls.Load() != 1 {
		t.Fatalf("billing hook calls=%d, want 1", hookCalls.Load())
	}

	keepAlive := holdbackTestFrames(
		t, 92, connectionID, KeepAliveRoute,
		holdbackTestE2ERecordForSession(0, 18, 0x51), false, 512,
	)
	if ready, err := holdbackTestForwardMessage(state, keepAlive); err != nil || len(ready) != len(keepAlive) {
		t.Fatalf("migrated keepalive = (%d, %v), want %d allowed frames", len(ready), err, len(keepAlive))
	}

	foreignKeepAlive := holdbackTestFrames(
		t, 93, connectionID, KeepAliveRoute,
		holdbackTestE2ERecordForSession(0, 19, 0x52), false, 512,
	)
	if _, err := holdbackTestForwardMessage(state, foreignKeepAlive); err == nil ||
		!strings.Contains(err.Error(), "another E2E session") {
		t.Fatalf("foreign migrated keepalive error=%v", err)
	}
}

func TestBillingHoldbackRetriesTemporaryValidationWithoutReleasingFrames(t *testing.T) {
	tests := []struct {
		name       string
		firstError error
	}{
		{name: "retryable billing control failure", firstError: ErrBillableRecordRetryable},
		{name: "child validation deadline", firstError: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var hookCalls atomic.Int32
			config := holdbackTestConfig(func(context.Context, *BillableRecord) error {
				if hookCalls.Add(1) == 1 {
					return test.firstError
				}
				return nil
			})
			state := newForwardHookState(config, "server-temporary")
			frames := holdbackTestFrames(
				t, 401, "conn-temporary", "/p2p/message", holdbackTestE2ERecord(64, 41), true, 128,
			)
			ready, err := holdbackTestForwardMessage(state, frames)
			if err != nil || len(ready) != 0 {
				t.Fatalf("temporary failure result = (%d, %v), want held without error", len(ready), err)
			}
			snapshot := config.ensureMessageHoldback().snapshot()
			if snapshot.PendingMessages != 1 || snapshot.PendingFrames != len(frames) {
				t.Fatalf("deferred holdback state = %+v", snapshot)
			}

			retransmit := cloneFrame(frames[len(frames)-1])
			retransmit.FrameType = network.FrameTypeRetransmit
			if ready, err = state.framesForForward(context.Background(), retransmit, "relay_to_clients"); err != nil || len(ready) != 0 {
				t.Fatalf("early retransmit result = (%d, %v), want still held", len(ready), err)
			}
			if hookCalls.Load() != 1 {
				t.Fatalf("early retransmit invoked validation %d times, want 1", hookCalls.Load())
			}

			time.Sleep(2 * holdbackRetryInitialDelay)
			ready, err = state.framesForForward(context.Background(), retransmit, "relay_to_clients")
			if err != nil || len(ready) != len(frames) {
				t.Fatalf("retry result = (%d, %v), want %d released frames", len(ready), err, len(frames))
			}
			if hookCalls.Load() != 2 {
				t.Fatalf("validation calls = %d, want 2", hookCalls.Load())
			}
		})
	}
}

func TestBillingHoldbackResumeRequiresOriginalE2ESession(t *testing.T) {
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil })
	state := newForwardHookState(config, "server-resume", "registration-a")
	connectionID := "conn-resume-session"
	handshake := holdbackTestFrames(
		t, 411, connectionID, billingHandshakeInfoRoute,
		holdbackTestE2ERecordForSession(32, 42, 0x11), false, 512,
	)
	if ready, err := holdbackTestForwardMessage(state, handshake); err != nil || len(ready) != len(handshake) {
		t.Fatalf("initial handshake = (%d, %v), want %d frames", len(ready), err, len(handshake))
	}
	state.resetHeldConnection(connectionID)

	foreignKeepAlive := holdbackTestFrames(
		t, 412, connectionID, KeepAliveRoute,
		holdbackTestE2ERecordForSession(0, 43, 0x22), false, 512,
	)
	if _, err := holdbackTestForwardMessage(state, foreignKeepAlive); err == nil ||
		!strings.Contains(err.Error(), "another E2E session") {
		t.Fatalf("foreign resumed session error = %v", err)
	}

	originalKeepAlive := holdbackTestFrames(
		t, 413, connectionID, KeepAliveRoute,
		holdbackTestE2ERecordForSession(0, 44, 0x11), false, 512,
	)
	if ready, err := holdbackTestForwardMessage(state, originalKeepAlive); err != nil || len(ready) != len(originalKeepAlive) {
		t.Fatalf("original resumed session = (%d, %v), want %d frames", len(ready), err, len(originalKeepAlive))
	}
}

func TestBillingHoldbackRegistrationGenerationsAreIsolated(t *testing.T) {
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil })
	oldState := newForwardHookState(config, "server-generation", "registration-old")
	newState := newForwardHookState(config, "server-generation", "registration-new")
	connectionID := "conn-generation"

	for index, fixture := range []struct {
		state         *forwardHookState
		sessionMarker byte
	}{
		{state: oldState, sessionMarker: 0x31},
		{state: newState, sessionMarker: 0x32},
	} {
		frames := holdbackTestFrames(
			t, uint64(421+index), connectionID, billingHandshakeInfoRoute,
			holdbackTestE2ERecordForSession(32, byte(45+index), fixture.sessionMarker), false, 512,
		)
		if ready, err := holdbackTestForwardMessage(fixture.state, frames); err != nil || len(ready) != len(frames) {
			t.Fatalf("generation %d handshake = (%d, %v), want %d frames", index, len(ready), err, len(frames))
		}
	}
	if snapshot := config.ensureMessageHoldback().snapshot(); snapshot.Connections != 2 {
		t.Fatalf("generation-scoped connections = %d, want 2", snapshot.Connections)
	}

	oldState.forgetHeldConnection(connectionID)
	keepAlive := holdbackTestFrames(
		t, 423, connectionID, KeepAliveRoute,
		holdbackTestE2ERecordForSession(0, 47, 0x32), false, 512,
	)
	if ready, err := holdbackTestForwardMessage(newState, keepAlive); err != nil || len(ready) != len(keepAlive) {
		t.Fatalf("new generation after old cleanup = (%d, %v), want %d frames", len(ready), err, len(keepAlive))
	}
}

func TestBillingHoldbackRecoveryStateExpires(t *testing.T) {
	limits := defaultMessageHoldbackLimits()
	limits.recoveryTTL = 15 * time.Millisecond
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil })
	config.holdbackLimits = &limits
	state := newForwardHookState(config, "server-recovery-ttl", "registration-a")
	connectionID := "conn-recovery-ttl"
	handshake := holdbackTestFrames(
		t, 431, connectionID, billingHandshakeInfoRoute,
		holdbackTestE2ERecordForSession(32, 48, 0x41), false, 512,
	)
	if _, err := holdbackTestForwardMessage(state, handshake); err != nil {
		t.Fatal(err)
	}
	state.resetHeldConnection(connectionID)
	if snapshot := config.ensureMessageHoldback().snapshot(); snapshot.Connections != 1 {
		t.Fatalf("recoverable connections = %d, want 1", snapshot.Connections)
	}
	waitRelayBatchCondition(t, func() bool {
		return config.ensureMessageHoldback().snapshot().Connections == 0
	})
}

func TestBillingHoldbackValidationLockIsCollectedAfterAcknowledgement(t *testing.T) {
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return nil })
	state := newForwardHookState(config, "server-validation-lock", "registration-a")
	frames := holdbackTestFrames(
		t, 441, "conn-validation-lock", "/p2p/message", holdbackTestE2ERecord(64, 49), true, 128,
	)
	if ready, err := holdbackTestForwardMessage(state, frames); err != nil || len(ready) != len(frames) {
		t.Fatalf("approved message = (%d, %v), want %d frames", len(ready), err, len(frames))
	}
	holdback := config.ensureMessageHoldback()
	holdback.mu.Lock()
	locksBeforeAck := len(holdback.validationLocks)
	entryCountsBeforeAck := len(holdback.entriesByNode)
	holdback.mu.Unlock()
	if locksBeforeAck != 1 || entryCountsBeforeAck != 1 {
		t.Fatalf("approved validation state = (%d locks, %d counts), want (1, 1)", locksBeforeAck, entryCountsBeforeAck)
	}

	state.acknowledgeHeldMessage("conn-validation-lock", frames[0].MessageId)
	holdback.mu.Lock()
	locksAfterAck := len(holdback.validationLocks)
	entryCountsAfterAck := len(holdback.entriesByNode)
	holdback.mu.Unlock()
	if locksAfterAck != 0 || entryCountsAfterAck != 0 {
		t.Fatalf("acknowledged validation state = (%d locks, %d counts), want (0, 0)", locksAfterAck, entryCountsAfterAck)
	}
}

func TestMessageHoldbackResourceLimitsAndTimeout(t *testing.T) {
	frame := func(connectionID string, messageID uint64, payloadBytes int) *network.Frame {
		return &network.Frame{
			FrameType: network.FrameTypeData, ConnectionId: connectionID, MessageId: messageID,
			SeqId: 0, TotalFrames: 2, Payload: make([]byte, payloadBytes),
		}
	}

	t.Run("message bytes and frames", func(t *testing.T) {
		limits := defaultMessageHoldbackLimits()
		limits.maxMessageBytes = 4
		holdback := newMessageHoldback(limits)
		if _, err := holdback.add("server", frame("conn", 1, 5)); err == nil {
			t.Fatal("per-message byte limit was not enforced")
		}
		oversizedFrames := frame("conn", 2, 1)
		oversizedFrames.TotalFrames = limits.maxMessageFrames + 1
		if _, err := holdback.add("server", oversizedFrames); err == nil {
			t.Fatal("per-message frame limit was not enforced")
		}
	})

	t.Run("connection bytes and messages", func(t *testing.T) {
		limits := defaultMessageHoldbackLimits()
		limits.maxConnectionBytes = 6
		limits.maxConnectionMessages = 2
		holdback := newMessageHoldback(limits)
		if _, err := holdback.add("server", frame("conn", 1, 4)); err != nil {
			t.Fatal(err)
		}
		if _, err := holdback.add("server", frame("conn", 2, 3)); err == nil {
			t.Fatal("per-connection byte limit was not enforced")
		}
		secondFrame := frame("other", 3, 6)
		if _, err := holdback.add("server", secondFrame); err != nil {
			t.Fatal("a different connection should use its own byte budget")
		}
		holdback.forgetConnection("server", "conn")
		holdback.forgetConnection("server", "other")

		limits.maxConnectionBytes = defaultMessageHoldbackLimits().maxConnectionBytes
		limits.maxConnectionMessages = 1
		holdback = newMessageHoldback(limits)
		if _, err := holdback.add("server", frame("conn", 4, 1)); err != nil {
			t.Fatal(err)
		}
		if _, err := holdback.add("server", frame("conn", 5, 1)); err == nil {
			t.Fatal("per-connection message limit was not enforced")
		}
		holdback.forgetConnection("server", "conn")
	})

	t.Run("global bytes and messages", func(t *testing.T) {
		limits := defaultMessageHoldbackLimits()
		limits.maxGlobalBytes = 6
		limits.maxGlobalMessages = 2
		holdback := newMessageHoldback(limits)
		if _, err := holdback.add("server", frame("conn-a", 1, 4)); err != nil {
			t.Fatal(err)
		}
		if _, err := holdback.add("server", frame("conn-b", 2, 3)); err == nil {
			t.Fatal("global byte limit was not enforced")
		}
		holdback.forgetConnection("server", "conn-a")

		limits.maxGlobalBytes = defaultMessageHoldbackLimits().maxGlobalBytes
		limits.maxGlobalMessages = 1
		holdback = newMessageHoldback(limits)
		if _, err := holdback.add("server", frame("conn-a", 3, 1)); err != nil {
			t.Fatal(err)
		}
		if _, err := holdback.add("server", frame("conn-b", 4, 1)); err == nil {
			t.Fatal("global message limit was not enforced")
		}
		holdback.forgetConnection("server", "conn-a")
	})

	t.Run("connection and global frames", func(t *testing.T) {
		limits := defaultMessageHoldbackLimits()
		limits.maxConnectionFrames = 1
		holdback := newMessageHoldback(limits)
		if _, err := holdback.add("server", frame("conn", 1, 0)); err != nil {
			t.Fatal(err)
		}
		if _, err := holdback.add("server", frame("conn", 2, 0)); err == nil {
			t.Fatal("per-connection frame limit was not enforced")
		}
		holdback.forgetConnection("server", "conn")

		limits.maxConnectionFrames = defaultMessageHoldbackLimits().maxConnectionFrames
		limits.maxGlobalFrames = 1
		holdback = newMessageHoldback(limits)
		if _, err := holdback.add("server", frame("conn-a", 3, 0)); err != nil {
			t.Fatal(err)
		}
		if _, err := holdback.add("server", frame("conn-b", 4, 0)); err == nil {
			t.Fatal("global frame limit was not enforced")
		}
		holdback.forgetConnection("server", "conn-a")
	})

	t.Run("idle timeout", func(t *testing.T) {
		limits := defaultMessageHoldbackLimits()
		limits.pendingTTL = 15 * time.Millisecond
		holdback := newMessageHoldback(limits)
		if _, err := holdback.add("server", frame("conn-timeout", 1, 4)); err != nil {
			t.Fatal(err)
		}
		waitRelayBatchCondition(t, func() bool {
			snapshot := holdback.snapshot()
			return snapshot.PendingBytes == 0 && snapshot.PendingMessages == 0 && snapshot.PendingFrames == 0 && snapshot.Connections == 0
		})
	})
}

func TestMessageHoldbackDefaultsCoverTunnelSendWindows(t *testing.T) {
	limits := defaultMessageHoldbackLimits()
	const (
		tunnelSendWindow = 32
		serviceSessions  = 500
	)
	if limits.maxConnectionMessages < 2*tunnelSendWindow {
		t.Fatalf("per-connection message limit=%d, want at least %d",
			limits.maxConnectionMessages, 2*tunnelSendWindow)
	}
	if limits.maxGlobalMessages < 2*tunnelSendWindow*serviceSessions {
		t.Fatalf("global message limit=%d, want at least %d",
			limits.maxGlobalMessages, 2*tunnelSendWindow*serviceSessions)
	}

	// Message-count headroom must not weaken the actual retained-memory
	// boundaries. Tiny partial frames fill the configured message windows;
	// payload-heavy frames remain constrained independently by byte limits.
	holdback := newMessageHoldback(limits)
	for index := 0; index < 2*tunnelSendWindow; index++ {
		frame := &network.Frame{
			FrameType: network.FrameTypeData, ConnectionId: "pipeline",
			MessageId: uint64(index + 1), SeqId: 0, TotalFrames: 2,
			Payload: []byte{byte(index)},
		}
		if _, err := holdback.add("server", frame); err != nil {
			t.Fatalf("partial tunnel message %d: %v", index, err)
		}
	}
	snapshot := holdback.snapshot()
	if snapshot.PendingMessages != 2*tunnelSendWindow {
		t.Fatalf("pending messages=%d, want %d", snapshot.PendingMessages, 2*tunnelSendWindow)
	}

	byteLimits := limits
	byteLimits.maxConnectionBytes = 4
	byteLimited := newMessageHoldback(byteLimits)
	first := &network.Frame{
		FrameType: network.FrameTypeData, ConnectionId: "bytes",
		MessageId: 1, SeqId: 0, TotalFrames: 2, Payload: make([]byte, 4),
	}
	if _, err := byteLimited.add("server", first); err != nil {
		t.Fatalf("first byte-limited frame: %v", err)
	}
	second := &network.Frame{
		FrameType: network.FrameTypeData, ConnectionId: "bytes",
		MessageId: 2, SeqId: 0, TotalFrames: 2, Payload: []byte{1},
	}
	if _, err := byteLimited.add("server", second); err == nil ||
		!strings.Contains(err.Error(), "per-connection byte limit") {
		t.Fatalf("byte limit error=%v, want per-connection byte limit", err)
	}
}

func TestBillingHoldbackHookFailureReleasesNoFrames(t *testing.T) {
	wantErr := errors.New("billing rejected")
	config := holdbackTestConfig(func(context.Context, *BillableRecord) error { return wantErr })
	state := newForwardHookState(config, "server-reject")
	frames := holdbackTestFrames(t, 81, "conn-reject", "/p2p/message", holdbackTestE2ERecord(64, 9), true, 128)
	for index, frame := range frames {
		ready, err := state.framesForForward(context.Background(), frame, "relay_to_clients")
		if index < len(frames)-1 {
			if err != nil || len(ready) != 0 {
				t.Fatalf("partial frame %d = (%d, %v)", index, len(ready), err)
			}
			continue
		}
		if !errors.Is(err, wantErr) || len(ready) != 0 {
			t.Fatalf("rejected completion = (%d, %v), want no frames and hook error", len(ready), err)
		}
	}
}

func TestBillingHoldbackDrainsReverseSendWindowInSequence(t *testing.T) {
	var calls atomic.Int32
	var nextSequence atomic.Uint64
	nextSequence.Store(1)
	config := holdbackTestConfig(func(_ context.Context, record *BillableRecord) error {
		calls.Add(1)
		if record.Sequence != nextSequence.Load() {
			return ErrBillableRecordDeferred
		}
		nextSequence.Add(1)
		return nil
	})
	state := newForwardHookState(config, "server-reverse-window")
	const window = uint64(8)
	frameCounts := make(map[uint64]int)
	var finalReady []*network.Frame
	for sequence := window; sequence > 0; sequence-- {
		messageID := uint64(100) + sequence
		frames := holdbackTestSequenceFrames(
			t, messageID, sequence, "conn-reverse-window", "/p2p/message",
			holdbackTestE2ERecord(64, byte(sequence)), true, 128,
		)
		frameCounts[messageID] = len(frames)
		ready, err := holdbackTestForwardMessage(state, frames)
		if err != nil {
			t.Fatalf("sequence %d: %v", sequence, err)
		}
		if sequence > 1 && len(ready) != 0 {
			t.Fatalf("future sequence %d escaped holdback", sequence)
		}
		if sequence == 1 {
			finalReady = ready
		}
	}
	snapshot := config.ensureMessageHoldback().snapshot()
	if snapshot.PendingBytes != 0 || snapshot.PendingMessages != 0 || snapshot.PendingFrames != 0 ||
		snapshot.ApprovedMessages != int(window) {
		t.Fatalf("reverse-window holdback state = %+v", snapshot)
	}
	var forwardedSequences []uint64
	for index := 0; index < len(finalReady); {
		messageID := finalReady[index].MessageId
		forwardedSequences = append(forwardedSequences, messageID-100)
		index += frameCounts[messageID]
	}
	if len(forwardedSequences) != int(window) {
		t.Fatalf("forwarded sequences = %v, want 1..%d", forwardedSequences, window)
	}
	for index, sequence := range forwardedSequences {
		if sequence != uint64(index+1) {
			t.Fatalf("forwarded sequences = %v, want ascending order", forwardedSequences)
		}
	}
	if calls.Load() != int32(window*2-1) {
		t.Fatalf("billing hook calls = %d, want %d", calls.Load(), window*2-1)
	}
}

func TestBillingHoldbackDrainsDeferredSequenceAcrossConnections(t *testing.T) {
	var calls atomic.Int32
	var nextSequence atomic.Uint64
	nextSequence.Store(1)
	config := holdbackTestConfig(func(_ context.Context, record *BillableRecord) error {
		calls.Add(1)
		if record.Sequence != nextSequence.Load() {
			return ErrBillableRecordDeferred
		}
		nextSequence.Add(1)
		return nil
	})
	state := newForwardHookState(config, "server-cross-connection")
	future := holdbackTestSequenceFrames(
		t, 302, 2, "conn-b", "/p2p/message", holdbackTestE2ERecord(64, 32), true, 128,
	)
	if ready, err := holdbackTestForwardMessage(state, future); err != nil || len(ready) != 0 {
		t.Fatalf("future delivery = (%d, %v)", len(ready), err)
	}
	first := holdbackTestSequenceFrames(
		t, 301, 1, "conn-a", "/p2p/message", holdbackTestE2ERecord(64, 31), true, 128,
	)
	ready, err := holdbackTestForwardMessage(state, first)
	if err != nil || len(ready) != len(first)+len(future) {
		t.Fatalf("cross-connection drain = (%d, %v), want %d frames", len(ready), err, len(first)+len(future))
	}
	if calls.Load() != 3 {
		t.Fatalf("billing hook calls = %d, want 3", calls.Load())
	}
}

func TestBillingHoldbackDeduplicatesDeferredRetransmit(t *testing.T) {
	var calls atomic.Int32
	var nextSequence atomic.Uint64
	nextSequence.Store(1)
	config := holdbackTestConfig(func(_ context.Context, record *BillableRecord) error {
		calls.Add(1)
		if record.Sequence != nextSequence.Load() {
			return ErrBillableRecordDeferred
		}
		nextSequence.Add(1)
		return nil
	})
	state := newForwardHookState(config, "server-deferred-duplicate")
	future := holdbackTestSequenceFrames(
		t, 202, 2, "conn-deferred-duplicate", "/p2p/message", holdbackTestE2ERecord(64, 22), true, 128,
	)
	if ready, err := holdbackTestForwardMessage(state, future); err != nil || len(ready) != 0 {
		t.Fatalf("future delivery = (%d, %v)", len(ready), err)
	}
	retransmit := make([]*network.Frame, len(future))
	for index, frame := range future {
		retransmit[index] = cloneFrame(frame)
		retransmit[index].FrameType = network.FrameTypeRetransmit
	}
	if ready, err := holdbackTestForwardMessage(state, retransmit); err != nil || len(ready) != 0 {
		t.Fatalf("future retransmit = (%d, %v)", len(ready), err)
	}
	if calls.Load() != 1 {
		t.Fatalf("deferred duplicate invoked billing hook %d times, want 1", calls.Load())
	}
	first := holdbackTestSequenceFrames(
		t, 201, 1, "conn-deferred-duplicate", "/p2p/message", holdbackTestE2ERecord(64, 21), true, 128,
	)
	ready, err := holdbackTestForwardMessage(state, first)
	if err != nil || len(ready) != len(first)+len(future) {
		t.Fatalf("drained delivery = (%d, %v), want %d frames", len(ready), err, len(first)+len(future))
	}
	if calls.Load() != 3 {
		t.Fatalf("billing hook calls = %d, want 3", calls.Load())
	}
}
