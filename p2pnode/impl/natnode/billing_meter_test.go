package natnode

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
)

func TestBillingSessionColdRestartRequestsSafeRotation(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessionID := billingvoucher.Identifier{1, 2, 3}
	relayAddress := "relay-a:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())

	firstMeter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	status, err := firstMeter.activateRelaySession(relayAddress, sessionID.String(), relayPublicKey)
	if err != nil || status.preexisting {
		t.Fatalf("initial activation = (%+v, %v), want new session", status, err)
	}
	firstMeter.mu.Lock()
	firstSession := firstMeter.sessions[sessionID]
	firstSession.cumulative = 1234
	firstSession.lastRecord = billingvoucher.Identifier{9}
	firstSession.nextAdvance = 8
	firstSession.recordSet = billingvoucher.Digest{7}
	firstMeter.mu.Unlock()
	status, err = firstMeter.activateRelaySession(relayAddress, sessionID.String(), relayPublicKey)
	if err != nil || !status.preexisting || status.cumulative != 1234 || status.lastRecordSequence != 7 {
		t.Fatalf("live reconnect watermark = (%+v, %v)", status, err)
	}

	restartedMeter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayState := natBillingSessionSnapshot(firstSession)
	status, err = restartedMeter.activateRelaySessionWithState(
		relayAddress, sessionID.String(), relayPublicKey, &relayState,
	)
	if err != nil {
		t.Fatal(err)
	}
	if status.preexisting || !status.resetRequired || status.cumulative != 0 || status.lastRecordSequence != 0 {
		t.Fatalf("cold restart status = %+v, want a signed request for safe Relay rotation", status)
	}
	if len(restartedMeter.sessions) != 0 || len(restartedMeter.relaySessions) != 0 {
		t.Fatal("cold restart retained unverified Relay session state")
	}

	rotatedSessionID := billingvoucher.Identifier{4, 5, 6}
	emptyRelayState := natBillingSnapshot{}
	status, err = restartedMeter.activateRelaySessionWithState(
		relayAddress, rotatedSessionID.String(), relayPublicKey, &emptyRelayState,
	)
	if err != nil {
		t.Fatal(err)
	}
	if status.preexisting || status.resetRequired || restartedMeter.relaySessions[relayAddress] != rotatedSessionID {
		t.Fatalf("rotated fresh session was not activated: %+v", status)
	}
	if restartedMeter.sessions[rotatedSessionID] == nil {
		t.Fatal("rotated fresh session state is unavailable")
	}
}

func TestBillingSessionRotationRejectsUncoveredPreviousState(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := "relay-rotation:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	previousID := billingvoucher.Identifier{31}
	replacementID := billingvoucher.Identifier{32}
	tests := []struct {
		name   string
		mutate func(*natBillingMeter, *natBillingSession)
	}{
		{
			name: "unsigned sub-window tail",
			mutate: func(_ *natBillingMeter, session *natBillingSession) {
				session.nextAssigned = 2
				session.nextAdvance = 2
				session.cumulative = billingvoucher.CumulativeWindowBytes - 1
				session.lastRecord = billingvoucher.Identifier{41}
				session.recordSet = billingvoucher.Digest{42}
			},
		},
		{
			name: "tail after voucher",
			mutate: func(meter *natBillingMeter, session *natBillingSession) {
				setFullyCoveredNatBillingSession(meter, previousID)
				session.nextAssigned = 3
				session.nextAdvance = 3
				session.cumulative++
				session.lastRecord = billingvoucher.Identifier{43}
				session.recordSet = billingvoucher.Digest{44}
			},
		},
		{
			name: "pending record",
			mutate: func(_ *natBillingMeter, session *natBillingSession) {
				session.pending[2] = natBillingRecord{bytes: 256, recordID: billingvoucher.Identifier{45}}
			},
		},
		{
			name: "assigned record not observed",
			mutate: func(_ *natBillingMeter, session *natBillingSession) {
				session.nextAssigned = 2
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			meter, err := newNatBillingMeter(payerKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := meter.activateRelaySession(relayAddress, previousID.String(), relayPublicKey); err != nil {
				t.Fatal(err)
			}
			test.mutate(meter, meter.sessions[previousID])

			if _, err := meter.activateRelaySession(relayAddress, replacementID.String(), relayPublicKey); err == nil {
				t.Fatal("uncovered previous billing session was replaced")
			}
			if meter.relaySessions[relayAddress] != previousID {
				t.Fatal("failed replacement changed the active billing session")
			}
			if _, created := meter.sessions[replacementID]; created {
				t.Fatal("failed replacement retained the proposed billing session")
			}
			if _, invalid := meter.invalidSessions[previousID]; invalid {
				t.Fatal("failed replacement invalidated the active billing session")
			}
		})
	}
}

func TestBillingSessionRotationAllowsFullyVoucherCoveredState(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := "relay-covered:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	previousID := billingvoucher.Identifier{51}
	replacementID := billingvoucher.Identifier{52}
	if _, err := meter.activateRelaySession(relayAddress, previousID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}
	setFullyCoveredNatBillingSession(meter, previousID)

	status, err := meter.activateRelaySession(relayAddress, replacementID.String(), relayPublicKey)
	if err != nil {
		t.Fatalf("replace fully covered billing session: %v", err)
	}
	if status.preexisting || status.resetRequired {
		t.Fatalf("replacement session status = %+v, want fresh session", status)
	}
	if meter.relaySessions[relayAddress] != replacementID || meter.sessions[replacementID] == nil {
		t.Fatal("replacement billing session was not installed")
	}
	if _, invalid := meter.invalidSessions[previousID]; !invalid {
		t.Fatal("replaced billing session was not retired")
	}
	status, err = meter.activateRelaySession(relayAddress, previousID.String(), relayPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !status.resetRequired || status.preexisting {
		t.Fatalf("retired session status = %+v, want reset required", status)
	}
	if meter.relaySessions[relayAddress] != replacementID {
		t.Fatal("retired session displaced the active replacement")
	}
}

func setFullyCoveredNatBillingSession(meter *natBillingMeter, sessionID billingvoucher.Identifier) {
	session := meter.sessions[sessionID]
	session.nextAssigned = 2
	session.nextAdvance = 2
	session.cumulative = billingvoucher.CumulativeWindowBytes
	session.lastRecord = billingvoucher.Identifier{61}
	session.recordSet = billingvoucher.Digest{62}
	body := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: sessionID,
		PayerNatID: meter.payerID, PayeeRelayID: session.relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: 1,
		CumulativeUniqueBytes: session.cumulative, LastRecordID: session.lastRecord,
		LastRecordSequence: 1, RecordSetDigest: session.recordSet,
		PolicyDigest:           billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	meter.channels[sessionID.String()+"|"+session.relayID.String()] = &natVoucherChannel{
		last: billingvoucher.MutualVoucher{Body: body}, has: true,
	}
	session.cosignedRecordSequence = body.LastRecordSequence
}

func TestBillingSendFailureInvalidatesAmbiguousSession(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	sessionID := billingvoucher.Identifier{4, 5, 6}
	relayAddress := "relay-failure:9000"
	if _, err := meter.activateRelaySession(relayAddress, sessionID.String(), crypoto.GetPubKeyStr(relayKey.PublicKey())); err != nil {
		t.Fatal(err)
	}
	stream := &failingBillingStream{}
	reset := false
	connection := newNATConnection(
		p2pnode.PeerInfo{ID: p2pnode.NodeID("peer")}, stream, nil, meter,
		func() string { return relayAddress }, func(string) { reset = true },
	)
	err = connection.Send(context.Background(), &p2pnode.Message{Payload: []byte("billable")})
	if err == nil {
		t.Fatal("expected transport failure")
	}
	if !reset {
		t.Fatal("transport failure did not reset the billing control")
	}
	meter.mu.Lock()
	activeAfterFailure, stillBound := meter.relaySessions[relayAddress]
	_, invalid := meter.invalidSessions[sessionID]
	meter.mu.Unlock()
	if !stillBound || activeAfterFailure != sessionID || !invalid {
		t.Fatalf("ambiguous session state: bound=%v active=%v invalid=%v", stillBound, activeAfterFailure, invalid)
	}
	status, err := meter.activateRelaySession(relayAddress, sessionID.String(), crypoto.GetPubKeyStr(relayKey.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if status.preexisting {
		t.Fatal("invalidated session must force Relay-side rotation")
	}
	if !status.resetRequired {
		t.Fatal("invalidated session did not explicitly request Relay-side rotation")
	}
	meter.mu.Lock()
	active := meter.relaySessions[relayAddress]
	meter.mu.Unlock()
	if active != sessionID {
		t.Fatal("invalidated session binding was discarded before watermark reconciliation")
	}
	emptyRelayState := natBillingSnapshot{}
	status, err = meter.activateRelaySessionWithState(
		relayAddress, sessionID.String(), crypoto.GetPubKeyStr(relayKey.PublicKey()), &emptyRelayState,
	)
	if err != nil {
		t.Fatalf("request rotation for ambiguous session: %v", err)
	}
	if status.preexisting || !status.resetRequired {
		t.Fatalf("ambiguous session = %+v, want mandatory rotation", status)
	}
	meter.mu.Lock()
	active = meter.relaySessions[relayAddress]
	_, invalid = meter.invalidSessions[sessionID]
	ambiguous := meter.sessions[sessionID]
	meter.mu.Unlock()
	if active != sessionID || !invalid || ambiguous.nextAssigned != 2 || ambiguous.nextAdvance != 1 {
		t.Fatal("ambiguous assigned Record was rewound before session rotation")
	}
	rotatedSessionID := billingvoucher.Identifier{17, 18, 19}
	status, err = meter.activateRelaySessionWithState(
		relayAddress, rotatedSessionID.String(), crypoto.GetPubKeyStr(relayKey.PublicKey()), &emptyRelayState,
	)
	if err != nil || status.resetRequired {
		t.Fatalf("activate rotated empty session = (%+v, %v)", status, err)
	}
	meter.mu.Lock()
	active = meter.relaySessions[relayAddress]
	meter.mu.Unlock()
	if active != rotatedSessionID {
		t.Fatal("fresh billing session was not installed after empty-session rotation")
	}
}

func TestBillingSendOrderReleasesAfterInitialWrite(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	sessionID := billingvoucher.Identifier{14, 15, 16}
	relayAddress := "relay-ordered-send:9000"
	if _, err := meter.activateRelaySession(
		relayAddress,
		sessionID.String(),
		crypoto.GetPubKeyStr(relayKey.PublicKey()),
	); err != nil {
		t.Fatal(err)
	}

	stream := newOrderedBillingStream()
	connection := newNATConnection(
		p2pnode.PeerInfo{ID: p2pnode.NodeID("peer")},
		stream,
		nil,
		meter,
		func() string { return relayAddress },
		nil,
	)
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- connection.Send(context.Background(), &p2pnode.Message{Payload: []byte("first")})
	}()
	if sequence := waitOrderedBillingInitial(t, stream.initial, firstDone); sequence != 1 {
		t.Fatalf("first initial sequence=%d, want 1", sequence)
	}
	select {
	case err := <-firstDone:
		t.Fatalf("first send returned before its ACK gate: %v", err)
	default:
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- connection.Send(context.Background(), &p2pnode.Message{Payload: []byte("second")})
	}()
	if sequence := waitOrderedBillingInitial(t, stream.initial, secondDone); sequence != 2 {
		t.Fatalf("second initial sequence=%d, want 2", sequence)
	}
	select {
	case err := <-firstDone:
		t.Fatalf("first send returned before the second initial write: %v", err)
	default:
	}

	stream.release <- struct{}{}
	stream.release <- struct{}{}
	for index, done := range []<-chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("send %d: %v", index+1, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("send %d did not finish", index+1)
		}
	}
}

func TestBillingSendOrderWaitersAreFIFO(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	sessionID := billingvoucher.Identifier{31, 32, 33}
	relayAddress := "relay-fifo-send:9000"
	if _, err := meter.activateRelaySession(
		relayAddress,
		sessionID.String(),
		crypoto.GetPubKeyStr(relayKey.PublicKey()),
	); err != nil {
		t.Fatal(err)
	}

	firstLease, err := meter.acquireSendOrder(context.Background(), relayAddress, "first")
	if err != nil {
		t.Fatal(err)
	}
	type acquiredLease struct {
		index int
		lease *natBillingSendLease
		err   error
	}
	acquired := make(chan acquiredLease, 3)
	for index := 0; index < 3; index++ {
		go func(index int) {
			lease, acquireErr := meter.acquireSendOrder(
				context.Background(),
				relayAddress,
				fmt.Sprintf("queued-%d", index),
			)
			acquired <- acquiredLease{index: index, lease: lease, err: acquireErr}
		}(index)
		waitForNatBillingDiagnostics(t, meter, relayAddress, func(diagnostics natBillingRelayDiagnostics) bool {
			return diagnostics.sendOrderWaiters == index+1
		}, fmt.Sprintf("%d FIFO waiters", index+1))
	}

	firstLease.Release()
	for expected := 0; expected < 3; expected++ {
		select {
		case result := <-acquired:
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.index != expected {
				t.Fatalf("acquisition index=%d, want FIFO index=%d", result.index, expected)
			}
			result.lease.Release()
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for FIFO acquisition %d", expected)
		}
	}
}

func TestBillingPrioritySendOrderPreemptsBulkWithoutStarvingIt(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	relayAddress := "relay-priority-send:9000"
	sessionID := billingvoucher.Identifier{41, 42, 43}
	if _, err := meter.activateRelaySession(relayAddress, sessionID.String(), crypoto.GetPubKeyStr(relayKey.PublicKey())); err != nil {
		t.Fatal(err)
	}
	first, err := meter.acquireSendOrder(context.Background(), relayAddress, "first")
	if err != nil {
		t.Fatal(err)
	}
	bulkReady := make(chan *natBillingSendLease, 1)
	go func() {
		lease, acquireErr := meter.acquireSendOrder(context.Background(), relayAddress, "bulk")
		if acquireErr == nil {
			bulkReady <- lease
		}
	}()
	waitForNatBillingDiagnostics(t, meter, relayAddress, func(diagnostics natBillingRelayDiagnostics) bool {
		return diagnostics.sendOrderWaiters == 1
	}, "bulk waiter")
	priorityReady := make(chan *natBillingSendLease, 1)
	go func() {
		lease, acquireErr := meter.acquireSendOrderWithPriority(context.Background(), relayAddress, "close", true)
		if acquireErr == nil {
			priorityReady <- lease
		}
	}()
	waitForNatBillingDiagnostics(t, meter, relayAddress, func(diagnostics natBillingRelayDiagnostics) bool {
		return diagnostics.sendOrderWaiters == 2
	}, "priority waiter")
	first.Release()
	select {
	case priority := <-priorityReady:
		priority.Release()
	case <-bulkReady:
		t.Fatal("bulk waiter bypassed priority control message")
	case <-time.After(time.Second):
		t.Fatal("priority waiter did not acquire")
	}
	select {
	case bulk := <-bulkReady:
		bulk.Release()
	case <-time.After(time.Second):
		t.Fatal("bulk waiter did not acquire after priority message")
	}
}

func TestBillingWaitQueuesAreBounded(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	sessionID := billingvoucher.Identifier{34, 35, 36}
	relayAddress := "relay-bounded-wait:9000"
	if _, err := meter.activateRelaySession(
		relayAddress,
		sessionID.String(),
		crypoto.GetPubKeyStr(relayKey.PublicKey()),
	); err != nil {
		t.Fatal(err)
	}

	meter.mu.Lock()
	meter.sendOrderWaiters[sessionID] = maximumNatBillingSendOrderWaiters
	meter.mu.Unlock()
	if _, err := meter.acquireSendOrder(context.Background(), relayAddress, "over-limit"); !errors.Is(err, ErrBillingSendQueueFull) {
		t.Fatalf("send queue error=%v, want %v", err, ErrBillingSendQueueFull)
	}

	meter.invalidateRelaySession(relayAddress)
	meter.mu.Lock()
	delete(meter.sendOrderWaiters, sessionID)
	meter.relaySessionWaiters[relayAddress] = maximumNatBillingRelaySessionWaiters
	meter.mu.Unlock()
	if err := meter.waitRelaySession(context.Background(), relayAddress, "over-limit"); !errors.Is(err, ErrBillingRelayWaitQueueFull) {
		t.Fatalf("Relay wait queue error=%v, want %v", err, ErrBillingRelayWaitQueueFull)
	}
}

func TestNATConnectionBillingSendSlotsAreBounded(t *testing.T) {
	stream := &billingCascadeReproStream{connectionID: "bounded-connection"}
	meter := &natBillingMeter{enabled: true}
	connection := newNATConnection(
		p2pnode.PeerInfo{ID: "peer"},
		stream,
		nil,
		meter,
		nil,
		nil,
	)
	for index := 0; index < maximumPendingBillingSendsPerConnection; index++ {
		connection.billingSends <- struct{}{}
	}
	err := connection.Send(context.Background(), &p2pnode.Message{Payload: []byte("over-limit")})
	if !errors.Is(err, ErrBillingSendQueueFull) {
		t.Fatalf("send error=%v, want %v", err, ErrBillingSendQueueFull)
	}
	if !isRecoverableServiceSendError(err) {
		t.Fatal("per-connection backpressure was not classified as recoverable")
	}
	if calls := stream.sendCalls.Load(); calls != 0 {
		t.Fatalf("transport calls=%d, want 0", calls)
	}
}

func TestRepeatedBillingInvalidationPreservesExistingWaiters(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	sessionID := billingvoucher.Identifier{37, 38, 39}
	relayAddress := "relay-repeated-invalidation:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	if _, err := meter.activateRelaySession(relayAddress, sessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}

	meter.invalidateRelaySessionWithCause(relayAddress, "first", "connection-1")
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- meter.waitRelaySession(context.Background(), relayAddress, "waiting-connection")
	}()
	waitForNatBillingDiagnostics(t, meter, relayAddress, func(diagnostics natBillingRelayDiagnostics) bool {
		return diagnostics.relaySessionWaiters == 1
	}, "one Relay session waiter")

	meter.mu.Lock()
	firstReady := meter.relayReady[relayAddress]
	meter.mu.Unlock()
	meter.invalidateRelaySessionWithCause(relayAddress, "repeated", "connection-2")
	meter.mu.Lock()
	secondReady := meter.relayReady[relayAddress]
	invalidationGeneration := meter.relayInvalidation[relayAddress]
	meter.mu.Unlock()
	if firstReady != secondReady {
		t.Fatal("repeated invalidation replaced relayReady and stranded existing waiters")
	}
	if invalidationGeneration != 1 {
		t.Fatalf("repeated invalidation advanced generation to %d, want 1", invalidationGeneration)
	}

	emptyRelayState := natBillingSnapshot{}
	if _, err := meter.activateRelaySessionWithState(
		relayAddress,
		sessionID.String(),
		relayPublicKey,
		&emptyRelayState,
	); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("existing waiter did not resume after reconciliation")
	}
}

func TestStaleBillingFailureDoesNotInvalidateRotatedSession(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	relayAddress := "relay-stale-invalidation:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	oldSessionID := billingvoucher.Identifier{44, 45, 46}
	newSessionID := billingvoucher.Identifier{47, 48, 49}
	if _, err := meter.activateRelaySession(relayAddress, oldSessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}
	meter.invalidateRelaySessionForSession(relayAddress, oldSessionID, "transport_send_error", "first")
	if _, err := meter.activateRelaySessionWithState(
		relayAddress, newSessionID.String(), relayPublicKey, &natBillingSnapshot{},
	); err != nil {
		t.Fatal(err)
	}

	meter.invalidateRelaySessionForSession(relayAddress, oldSessionID, "late_transport_send_error", "late")
	diagnostics := meter.relayDiagnostics(relayAddress)
	if diagnostics.sessionID != newSessionID || diagnostics.invalid || diagnostics.invalidationGeneration != 1 {
		t.Fatalf("late old-session failure changed rotated session: %+v", diagnostics)
	}
}

func waitForNatBillingDiagnostics(
	t *testing.T,
	meter *natBillingMeter,
	relayAddress string,
	condition func(natBillingRelayDiagnostics) bool,
	description string,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		diagnostics := meter.relayDiagnostics(relayAddress)
		if condition(diagnostics) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %+v", description, diagnostics)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBillingCallerTimeoutAfterInitialWriteRetainsSharedSession(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	sessionID := billingvoucher.Identifier{17, 18, 19}
	relayAddress := "relay-soft-timeout:9000"
	if _, err := meter.activateRelaySession(
		relayAddress,
		sessionID.String(),
		crypoto.GetPubKeyStr(relayKey.PublicKey()),
	); err != nil {
		t.Fatal(err)
	}

	stream := newOrderedBillingStream()
	reset := make(chan struct{}, 1)
	connection := newNATConnection(
		p2pnode.PeerInfo{ID: p2pnode.NodeID("peer")},
		stream,
		nil,
		meter,
		func() string { return relayAddress },
		func(string) { reset <- struct{}{} },
	)
	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- connection.Send(firstCtx, &p2pnode.Message{Payload: []byte("first")})
	}()
	if sequence := waitOrderedBillingInitial(t, stream.initial, firstDone); sequence != 1 {
		t.Fatalf("first initial sequence=%d, want 1", sequence)
	}
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("first send error=%v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first send did not observe its caller deadline")
	}

	meter.mu.Lock()
	_, invalid := meter.invalidSessions[sessionID]
	meter.mu.Unlock()
	if invalid {
		t.Fatal("caller timeout froze the shared billing session immediately")
	}
	select {
	case <-reset:
		t.Fatal("caller timeout reset the shared billing control")
	default:
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- connection.Send(context.Background(), &p2pnode.Message{Payload: []byte("second")})
	}()
	if sequence := waitOrderedBillingInitial(t, stream.initial, secondDone); sequence != 2 {
		t.Fatalf("second initial sequence=%d, want 2", sequence)
	}
	stream.release <- struct{}{}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second send remained frozen behind the timed-out stream")
	}

	time.Sleep(50 * time.Millisecond)
	meter.mu.Lock()
	_, invalid = meter.invalidSessions[sessionID]
	meter.mu.Unlock()
	if invalid {
		t.Fatal("caller timeout invalidated the shared billing session asynchronously")
	}
	select {
	case <-reset:
		t.Fatal("caller timeout asynchronously reset the shared billing control")
	default:
	}
}

func waitOrderedBillingInitial(t *testing.T, initial <-chan uint64, done <-chan error) uint64 {
	t.Helper()
	select {
	case sequence := <-initial:
		return sequence
	case err := <-done:
		t.Fatalf("send returned before its ordered initial write: %v", err)
		return 0
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ordered initial write")
		return 0
	}
}

func TestBillingConfirmAdvancesOnlyAcrossContiguousPrefix(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := billingvoucher.Identifier{70, 71, 72}
	session := newNatBillingSession()
	session.cumulative = 300
	session.nextAssigned = 4
	session.nextAdvance = 4
	meter.sessions[sessionID] = session
	meter.relaySessions["relay-confirm-prefix:9000"] = sessionID

	if err := meter.confirm(natBillingConfirmationMessage(sessionID, 3)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := meter.privateSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if session.confirmedSequence != 0 || len(session.confirmedOutOfOrder) != 1 ||
		len(snapshot.Sessions) != 1 || snapshot.Sessions[0].ConfirmedSequence != 0 {
		t.Fatalf("sequence 3 crossed a missing confirmation gap: session=%+v snapshot=%+v", session, snapshot)
	}

	if err := meter.confirm(natBillingConfirmationMessage(sessionID, 1)); err != nil {
		t.Fatal(err)
	}
	if session.confirmedSequence != 1 || len(session.confirmedOutOfOrder) != 1 {
		t.Fatalf("confirmation prefix after 3,1 = %d pending=%v", session.confirmedSequence, session.confirmedOutOfOrder)
	}
	if err := meter.confirm(natBillingConfirmationMessage(sessionID, 3)); err != nil {
		t.Fatal(err)
	}
	if session.confirmedSequence != 1 || len(session.confirmedOutOfOrder) != 1 {
		t.Fatal("duplicate out-of-order confirmation changed the contiguous watermark")
	}

	if err := meter.confirm(natBillingConfirmationMessage(sessionID, 2)); err != nil {
		t.Fatal(err)
	}
	if session.confirmedSequence != 3 || len(session.confirmedOutOfOrder) != 0 {
		t.Fatalf("confirmation prefix after 3,1,2 = %d pending=%v, want 3 and empty", session.confirmedSequence, session.confirmedOutOfOrder)
	}
	if err := meter.confirm(natBillingConfirmationMessage(sessionID, 2)); err != nil {
		t.Fatalf("duplicate contiguous confirmation was not idempotent: %v", err)
	}
}

func TestBillingOutOfOrderConfirmationsAreBounded(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := billingvoucher.Identifier{73, 74, 75}
	session := newNatBillingSession()
	lastSequence := uint64(maximumNatBillingEvidenceEntries + 2)
	session.nextAssigned = lastSequence + 1
	session.nextAdvance = lastSequence + 1
	meter.sessions[sessionID] = session

	for sequence := uint64(2); sequence < lastSequence; sequence++ {
		if err := meter.confirm(natBillingConfirmationMessage(sessionID, sequence)); err != nil {
			t.Fatalf("store out-of-order confirmation %d: %v", sequence, err)
		}
	}
	if len(session.confirmedOutOfOrder) != maximumNatBillingEvidenceEntries {
		t.Fatalf("out-of-order confirmation count = %d, want %d", len(session.confirmedOutOfOrder), maximumNatBillingEvidenceEntries)
	}
	if err := meter.confirm(natBillingConfirmationMessage(sessionID, lastSequence)); err == nil {
		t.Fatal("out-of-order confirmation set exceeded its evidence limit")
	}
	if err := meter.confirm(natBillingConfirmationMessage(sessionID, 1)); err != nil {
		t.Fatalf("close bounded confirmation gap: %v", err)
	}
	if session.confirmedSequence != lastSequence-1 || len(session.confirmedOutOfOrder) != 0 {
		t.Fatalf("bounded confirmation prefix did not drain: sequence=%d pending=%d", session.confirmedSequence, len(session.confirmedOutOfOrder))
	}
	if err := meter.confirm(natBillingConfirmationMessage(sessionID, lastSequence)); err != nil {
		t.Fatalf("confirm next contiguous sequence after drain: %v", err)
	}
}

func TestBillingReconcileProtectsAndClearsOutOfOrderConfirmations(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := billingvoucher.Identifier{76, 77, 78}
	second := natBillingSnapshot{
		cumulative: 200, lastRecord: billingvoucher.Identifier{79},
		lastRecordSequence: 2, recordSet: billingvoucher.Digest{80},
	}
	third := natBillingSnapshot{
		cumulative: 300, lastRecord: billingvoucher.Identifier{81},
		lastRecordSequence: 3, recordSet: billingvoucher.Digest{82},
	}
	session := newNatBillingSession()
	session.relayID = billingvoucher.Identifier{83}
	session.cumulative = third.cumulative
	session.lastRecord = third.lastRecord
	session.recordSet = third.recordSet
	session.nextAssigned = 4
	session.nextAdvance = 4
	session.snapshots[second.cumulative] = second
	session.snapshots[third.cumulative] = third
	meter.sessions[sessionID] = session
	if err := meter.confirm(natBillingConfirmationMessage(sessionID, 3)); err != nil {
		t.Fatal(err)
	}

	meter.mu.Lock()
	_, rollbackErr := meter.reconcileRelaySessionLocked(sessionID, session, second)
	if rollbackErr == nil {
		meter.mu.Unlock()
		t.Fatal("reconciliation rolled back an out-of-order transport confirmation")
	}
	if session.confirmedSequence != 0 || len(session.confirmedOutOfOrder) != 1 {
		meter.mu.Unlock()
		t.Fatal("failed reconciliation changed confirmation state")
	}
	_, err = meter.reconcileRelaySessionLocked(sessionID, session, third)
	confirmed := session.confirmedSequence
	pendingConfirmations := len(session.confirmedOutOfOrder)
	meter.mu.Unlock()
	if err != nil {
		t.Fatalf("reconcile watermark covering all transport confirmations: %v", err)
	}
	if confirmed != 3 || pendingConfirmations != 0 {
		t.Fatalf("reconciled confirmation state = sequence %d pending %d, want 3 and 0", confirmed, pendingConfirmations)
	}
}

func TestBillingConcurrentConfirmationsConvergeToContiguousPrefix(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := billingvoucher.Identifier{84, 85, 86}
	const confirmations = 256
	session := newNatBillingSession()
	session.nextAssigned = confirmations + 1
	session.nextAdvance = confirmations + 1
	meter.sessions[sessionID] = session

	var wait sync.WaitGroup
	errorsFound := make(chan error, confirmations)
	for sequence := uint64(1); sequence <= confirmations; sequence++ {
		wait.Add(1)
		go func(sequence uint64) {
			defer wait.Done()
			if err := meter.confirm(natBillingConfirmationMessage(sessionID, sequence)); err != nil {
				errorsFound <- err
			}
		}(sequence)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent confirmation failed: %v", err)
	}
	if session.confirmedSequence != confirmations || len(session.confirmedOutOfOrder) != 0 {
		t.Fatalf("concurrent confirmations converged to %d with %d pending", session.confirmedSequence, len(session.confirmedOutOfOrder))
	}
}

func natBillingConfirmationMessage(sessionID billingvoucher.Identifier, sequence uint64) *network.Message {
	return &network.Message{Header: &network.Header{
		BillingSessionID: [32]byte(sessionID),
		BillingSequence:  sequence,
	}}
}

func TestBillingEvidenceSnapshotsRollWithinHardLimit(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.enabled = true
	relayAddress := "relay-tiny-records:9000"
	sessionID := billingvoucher.Identifier{10, 11, 12}
	if _, err := meter.activateRelaySession(
		relayAddress, sessionID.String(), crypoto.GetPubKeyStr(relayKey.PublicKey()),
	); err != nil {
		t.Fatal(err)
	}

	recordCount := uint64(maximumNatBillingReconciliationSnapshots + 257)
	for sequence := uint64(1); sequence <= recordCount; sequence++ {
		message := &network.Message{
			Header:  &network.Header{ConnectionId: "tiny-record-evidence"},
			Payload: []byte{byte(sequence)},
		}
		if err := meter.prepare(message, relayAddress); err != nil {
			t.Fatalf("prepare tiny record %d: %v", sequence, err)
		}
		message.Payload = natBillingTestE2ERecord(1, sequence)
		metadata, err := crypoto.InspectE2ERecord(message.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := meter.observe(message, metadata.MessageID); err != nil {
			t.Fatalf("observe tiny record %d: %v", sequence, err)
		}
	}

	session := meter.sessions[sessionID]
	if len(session.snapshots) != maximumNatBillingReconciliationSnapshots {
		t.Fatalf("snapshot count = %d, want %d", len(session.snapshots), maximumNatBillingReconciliationSnapshots)
	}
	if len(session.pending) != 0 {
		t.Fatalf("rejected contiguous record left %d pending entries", len(session.pending))
	}
	if session.cumulative != recordCount || session.nextAdvance != recordCount+1 {
		t.Fatalf("rolling evidence lost progress: cumulative=%d next=%d", session.cumulative, session.nextAdvance)
	}
	if _, retained := session.snapshots[recordCount]; !retained {
		t.Fatal("latest billing evidence snapshot was evicted")
	}
	if len(session.snapshotOrder) > 2*maximumNatBillingReconciliationSnapshots {
		t.Fatalf("snapshot order index grew beyond its compacted bound: %d", len(session.snapshotOrder))
	}
}

func TestBillingReconciliationRetainsHighConcurrencyEvidenceWindow(t *testing.T) {
	session := newNatBillingSession()
	recordCount := uint64(4 * maximumNatBillingEvidenceEntries)
	for sequence := uint64(1); sequence <= recordCount; sequence++ {
		snapshot := natBillingSnapshot{
			cumulative: sequence, lastRecord: billingvoucher.Identifier{byte(sequence), 1},
			lastRecordSequence: sequence, recordSet: billingvoucher.Digest{byte(sequence >> 8), 1},
		}
		session.snapshots[sequence] = snapshot
		session.snapshotOrder = append(session.snapshotOrder, sequence)
		trimNatBillingSnapshots(session)
	}
	if _, retained := session.snapshots[1]; !retained {
		t.Fatal("high-concurrency reconciliation evidence was evicted at the pending-record safety limit")
	}
	if len(session.snapshots) != int(recordCount) {
		t.Fatalf("retained snapshots = %d, want %d", len(session.snapshots), recordCount)
	}
	current := session.snapshots[recordCount]
	session.cumulative = current.cumulative
	session.lastRecord = current.lastRecord
	session.recordSet = current.recordSet
	session.nextAssigned = recordCount + 1
	session.nextAdvance = recordCount + 1
	target := session.snapshots[1]
	meter := &natBillingMeter{channels: make(map[string]*natVoucherChannel)}
	result, err := meter.reconcileRelaySessionStateLocked(billingvoucher.Identifier{1}, session, target)
	if err != nil {
		t.Fatalf("reconcile retained high-concurrency watermark: %v", err)
	}
	if !result.rotationRequired || result.target != target {
		t.Fatalf("reconciliation result = %+v, want rotation to retained watermark", result)
	}
	if session.cumulative != current.cumulative || session.nextAdvance != current.lastRecordSequence+1 {
		t.Fatalf("ambiguous session was rewound: cumulative %d next %d", session.cumulative, session.nextAdvance)
	}
}

func TestBillingReconcileAcceptsOneRelayConfirmedLocalAssignment(t *testing.T) {
	sessionID := billingvoucher.Identifier{91, 92, 93}
	current := natBillingSnapshot{
		cumulative: 128, lastRecord: billingvoucher.Identifier{94},
		lastRecordSequence: 1, recordSet: billingvoucher.Digest{95},
	}
	relayState := natBillingSnapshot{
		cumulative: 192, lastRecord: billingvoucher.Identifier{96},
		lastRecordSequence: 2, recordSet: billingvoucher.Digest{97},
	}
	session := newNatBillingSession()
	session.relayID = billingvoucher.Identifier{98}
	session.cumulative = current.cumulative
	session.lastRecord = current.lastRecord
	session.recordSet = current.recordSet
	session.nextAdvance = 2
	session.nextAssigned = 3
	session.assignedBytes[2] = 64
	session.snapshots[current.cumulative] = current
	meter := &natBillingMeter{
		sessions: map[billingvoucher.Identifier]*natBillingSession{sessionID: session},
		channels: make(map[string]*natVoucherChannel),
	}

	if _, err := meter.reconcileRelaySessionLocked(sessionID, session, relayState); err != nil {
		t.Fatalf("reconcile Relay-confirmed local assignment: %v", err)
	}
	if got := natBillingSessionSnapshot(session); got != relayState {
		t.Fatalf("reconciled snapshot=%+v, want %+v", got, relayState)
	}
	if session.confirmedSequence != 2 || session.nextAdvance != 3 || session.nextAssigned != 3 ||
		len(session.assignedBytes) != 0 {
		t.Fatalf("reconciled assignment state=%+v", session)
	}
	if got, retained := session.snapshots[relayState.cumulative]; !retained || got != relayState {
		t.Fatalf("Relay-confirmed assignment snapshot=(%+v, %v)", got, retained)
	}

	inflated := relayState
	inflated.cumulative += 64
	inflated.lastRecordSequence++
	inflated.lastRecord = billingvoucher.Identifier{99}
	inflated.recordSet = billingvoucher.Digest{100}
	if _, err := meter.reconcileRelaySessionLocked(sessionID, session, inflated); err == nil {
		t.Fatal("Relay advanced again without another local assignment")
	}
}

func TestBillingReconcileRejectsAssignedRecordWithInflatedBytes(t *testing.T) {
	sessionID := billingvoucher.Identifier{101, 102, 103}
	current := natBillingSnapshot{
		cumulative: 256, lastRecord: billingvoucher.Identifier{104},
		lastRecordSequence: 4, recordSet: billingvoucher.Digest{105},
	}
	inflated := natBillingSnapshot{
		cumulative: 385, lastRecord: billingvoucher.Identifier{106},
		lastRecordSequence: 5, recordSet: billingvoucher.Digest{107},
	}
	session := newNatBillingSession()
	session.relayID = billingvoucher.Identifier{108}
	session.cumulative = current.cumulative
	session.lastRecord = current.lastRecord
	session.recordSet = current.recordSet
	session.nextAdvance = 5
	session.nextAssigned = 6
	session.assignedBytes[5] = 128
	session.snapshots[current.cumulative] = current
	meter := &natBillingMeter{channels: make(map[string]*natVoucherChannel)}

	if _, err := meter.reconcileRelaySessionLocked(sessionID, session, inflated); err == nil {
		t.Fatal("Relay watermark inflated a locally assigned record")
	}
	if got := natBillingSessionSnapshot(session); got != current {
		t.Fatalf("failed reconciliation changed snapshot=%+v, want %+v", got, current)
	}
	if session.assignedBytes[5] != 128 {
		t.Fatal("failed reconciliation discarded local assignment evidence")
	}
}

func TestAmbiguousBillingSessionRotatesInsteadOfReusingSequence(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := "relay-reconcile:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	sessionID := billingvoucher.Identifier{21, 22, 23}
	if _, err := meter.activateRelaySession(relayAddress, sessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}
	first := natBillingSnapshot{
		cumulative: 128, lastRecord: billingvoucher.Identifier{31},
		lastRecordSequence: 1, recordSet: billingvoucher.Digest{32},
	}
	second := natBillingSnapshot{
		cumulative: 256, lastRecord: billingvoucher.Identifier{33},
		lastRecordSequence: 2, recordSet: billingvoucher.Digest{34},
	}
	session := meter.sessions[sessionID]
	session.cumulative = second.cumulative
	session.lastRecord = second.lastRecord
	session.recordSet = second.recordSet
	session.nextAssigned = 3
	session.nextAdvance = 3
	session.snapshots[first.cumulative] = first
	session.snapshots[second.cumulative] = second
	meter.invalidateRelaySession(relayAddress)

	status, err := meter.activateRelaySessionWithState(relayAddress, sessionID.String(), relayPublicKey, &first)
	if err != nil {
		t.Fatalf("request rotation from signed prefix: %v", err)
	}
	if !status.resetRequired || status.preexisting || status.cumulative != first.cumulative ||
		status.lastRecordSequence != first.lastRecordSequence {
		t.Fatalf("rotation status=%+v", status)
	}
	if session.nextAssigned != 3 || session.nextAdvance != 3 {
		t.Fatalf("ambiguous sequence was rewound: assigned=%d advance=%d", session.nextAssigned, session.nextAdvance)
	}
	if _, retained := session.snapshots[second.cumulative]; !retained {
		t.Fatal("evidence beyond the Relay watermark was discarded before rotation")
	}

	meter.invalidateRelaySession(relayAddress)
	unknown := first
	unknown.cumulative++
	if _, err := meter.activateRelaySessionWithState(relayAddress, sessionID.String(), relayPublicKey, &unknown); err == nil {
		t.Fatal("Relay watermark without matching local evidence was accepted")
	}
}

func TestBillingRotationSettlementAllowsFreshSessionWithoutSequenceReuse(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := "relay-rotation-settlement:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	oldSessionID := billingvoucher.Identifier{111, 112, 113}
	if _, err := meter.activateRelaySession(relayAddress, oldSessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}
	settlement := natBillingSnapshot{
		cumulative: 128, lastRecord: billingvoucher.Identifier{114},
		lastRecordSequence: 1, recordSet: billingvoucher.Digest{115},
	}
	localHead := natBillingSnapshot{
		cumulative: 256, lastRecord: billingvoucher.Identifier{116},
		lastRecordSequence: 2, recordSet: billingvoucher.Digest{117},
	}
	session := meter.sessions[oldSessionID]
	session.cumulative = localHead.cumulative
	session.lastRecord = localHead.lastRecord
	session.recordSet = localHead.recordSet
	session.nextAssigned = 3
	session.nextAdvance = 3
	session.snapshots[settlement.cumulative] = settlement
	session.snapshots[localHead.cumulative] = localHead
	meter.invalidateRelaySession(relayAddress)

	status, err := meter.activateRelaySessionWithState(
		relayAddress, oldSessionID.String(), relayPublicKey, &settlement,
	)
	if err != nil || !status.resetRequired {
		t.Fatalf("rotation request = (%+v, %v)", status, err)
	}
	body := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: oldSessionID,
		PayerNatID: meter.payerID, PayeeRelayID: session.relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: 1,
		CumulativeUniqueBytes: settlement.cumulative, LastRecordID: settlement.lastRecord,
		LastRecordSequence: settlement.lastRecordSequence, RecordSetDigest: settlement.recordSet,
		PolicyDigest: billingvoucher.CurrentPolicyDigest(), AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	relaySignature, err := billingvoucher.SignRelay(body, relayKey)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, err := body.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := meter.cosign(bodyBytes, relaySignature, relayPublicKey); err != nil {
		t.Fatalf("cosign final rotation settlement: %v", err)
	}

	freshSessionID := billingvoucher.Identifier{118, 119, 120}
	empty := natBillingSnapshot{}
	status, err = meter.activateRelaySessionWithState(
		relayAddress, freshSessionID.String(), relayPublicKey, &empty,
	)
	if err != nil || status.resetRequired {
		t.Fatalf("activate fresh session = (%+v, %v)", status, err)
	}
	if meter.relaySessions[relayAddress] != freshSessionID ||
		meter.sessions[freshSessionID].nextAssigned != 1 || session.nextAssigned != 3 {
		t.Fatal("session rotation reused or rewound an ambiguous billing sequence")
	}
}

func TestBillingReconnectDrainsActiveSendBeforeReusingSequence(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := "relay-drain:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	sessionID := billingvoucher.Identifier{71, 72, 73}
	if _, err := meter.activateRelaySession(relayAddress, sessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}
	first := natBillingSnapshot{
		cumulative: 128, lastRecord: billingvoucher.Identifier{74},
		lastRecordSequence: 1, recordSet: billingvoucher.Digest{75},
	}
	second := natBillingSnapshot{
		cumulative: 256, lastRecord: billingvoucher.Identifier{76},
		lastRecordSequence: 2, recordSet: billingvoucher.Digest{77},
	}
	session := meter.sessions[sessionID]
	session.cumulative = second.cumulative
	session.lastRecord = second.lastRecord
	session.recordSet = second.recordSet
	session.nextAssigned = 3
	session.nextAdvance = 3
	session.confirmedSequence = 1
	session.activeSends[2] = struct{}{}
	session.snapshots[first.cumulative] = first
	session.snapshots[second.cumulative] = second
	meter.invalidateRelaySession(relayAddress)

	status, err := meter.activateRelaySessionWithState(
		relayAddress, sessionID.String(), relayPublicKey, &first,
	)
	if err != nil {
		t.Fatalf("start active-send reconciliation drain: %v", err)
	}
	if !status.draining || status.cumulative != first.cumulative ||
		status.lastRecordSequence != first.lastRecordSequence {
		t.Fatalf("draining status = %+v", status)
	}
	if got := natBillingSessionSnapshot(session); got != second {
		t.Fatalf("active send was rewound to %+v, want %+v", got, second)
	}
	if session.nextAssigned != 3 {
		t.Fatalf("next assigned sequence = %d, want 3", session.nextAssigned)
	}
	if _, invalid := meter.invalidSessions[sessionID]; !invalid {
		t.Fatal("draining reconciliation prematurely unblocked new sends")
	}

	message := natBillingConfirmationMessage(sessionID, 2)
	if !meter.completeSend(message) {
		t.Fatal("last active send did not request a final control reconciliation")
	}
	if len(session.activeSends) != 0 {
		t.Fatalf("active sends after completion = %d", len(session.activeSends))
	}

	status, err = meter.activateRelaySessionWithState(
		relayAddress, sessionID.String(), relayPublicKey, &second,
	)
	if err != nil {
		t.Fatalf("finish active-send reconciliation: %v", err)
	}
	if status.draining || status.cumulative != second.cumulative ||
		status.lastRecordSequence != second.lastRecordSequence {
		t.Fatalf("final status = %+v", status)
	}
	if _, invalid := meter.invalidSessions[sessionID]; invalid {
		t.Fatal("final exact reconciliation did not unblock the session")
	}
	if session.nextAssigned != 3 || session.nextAdvance != 3 {
		t.Fatalf("reconciled sequence state = assigned %d advance %d", session.nextAssigned, session.nextAdvance)
	}
}

func TestBillingInvalidationWaitsForAllActiveSendsBeforeControlReset(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := "relay-deferred-reset:9000"
	sessionID := billingvoucher.Identifier{81, 82, 83}
	if _, err := meter.activateRelaySession(
		relayAddress,
		sessionID.String(),
		crypoto.GetPubKeyStr(relayKey.PublicKey()),
	); err != nil {
		t.Fatal(err)
	}
	session := meter.sessions[sessionID]
	session.nextAssigned = 3
	session.activeSends[1] = struct{}{}
	session.activeSends[2] = struct{}{}
	meter.invalidateRelaySession(relayAddress)

	if meter.completeSend(natBillingConfirmationMessage(sessionID, 1)) {
		t.Fatal("first completed send reset billing control while another send was active")
	}
	if !meter.completeSend(natBillingConfirmationMessage(sessionID, 2)) {
		t.Fatal("last active send did not request billing control reconciliation")
	}
	if len(session.activeSends) != 0 {
		t.Fatalf("active sends after drain = %d, want 0", len(session.activeSends))
	}
}

func TestReconcileCannotRollbackTransportConfirmedRecord(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := "relay-confirmed:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	sessionID := billingvoucher.Identifier{24, 25, 26}
	if _, err := meter.activateRelaySession(relayAddress, sessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}
	first := natBillingSnapshot{
		cumulative: 128, lastRecord: billingvoucher.Identifier{35},
		lastRecordSequence: 1, recordSet: billingvoucher.Digest{36},
	}
	second := natBillingSnapshot{
		cumulative: 256, lastRecord: billingvoucher.Identifier{37},
		lastRecordSequence: 2, recordSet: billingvoucher.Digest{38},
	}
	session := meter.sessions[sessionID]
	session.cumulative = second.cumulative
	session.lastRecord = second.lastRecord
	session.recordSet = second.recordSet
	session.nextAssigned = 3
	session.nextAdvance = 3
	session.confirmedSequence = 2
	session.snapshots[first.cumulative] = first
	session.snapshots[second.cumulative] = second
	meter.invalidateRelaySession(relayAddress)

	if _, err := meter.activateRelaySessionWithState(
		relayAddress, sessionID.String(), relayPublicKey, &first,
	); err == nil {
		t.Fatal("transport-confirmed usage was rolled back to an older Relay watermark")
	}
	status, err := meter.activateRelaySessionWithState(
		relayAddress, sessionID.String(), relayPublicKey, &second,
	)
	if err != nil || status.cumulative != second.cumulative {
		t.Fatalf("exact confirmed watermark recovery = (%+v, %v)", status, err)
	}
}

func TestExistingSessionNewAddressRequiresExactSignedState(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	firstAddress := "relay-old-address:9000"
	secondAddress := "relay-new-address:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	sessionID := billingvoucher.Identifier{27, 28, 29}
	if _, err := meter.activateRelaySession(firstAddress, sessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}
	snapshot := natBillingSnapshot{
		cumulative: 512, lastRecord: billingvoucher.Identifier{39},
		lastRecordSequence: 1, recordSet: billingvoucher.Digest{40},
	}
	session := meter.sessions[sessionID]
	session.cumulative = snapshot.cumulative
	session.lastRecord = snapshot.lastRecord
	session.recordSet = snapshot.recordSet
	session.nextAssigned = 2
	session.nextAdvance = 2
	session.snapshots[snapshot.cumulative] = snapshot
	empty := natBillingSnapshot{}
	if _, err := meter.activateRelaySessionWithState(
		secondAddress, sessionID.String(), relayPublicKey, &empty,
	); err == nil {
		t.Fatal("preexisting session disclosed its local watermark to a new address")
	}
	if _, bound := meter.relaySessions[secondAddress]; bound {
		t.Fatal("new Relay address was bound after a mismatched signed watermark")
	}
	status, err := meter.activateRelaySessionWithState(
		secondAddress, sessionID.String(), relayPublicKey, &snapshot,
	)
	if err != nil || !status.preexisting || status.cumulative != snapshot.cumulative {
		t.Fatalf("exact preexisting watermark = (%+v, %v)", status, err)
	}
}

func TestReconcileReturnsLastCosignedVoucherInsteadOfRollingItBack(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := "relay-recovery-voucher:9000"
	relayPublicKey := crypoto.GetPubKeyStr(relayKey.PublicKey())
	sessionID := billingvoucher.Identifier{41, 42, 43}
	if _, err := meter.activateRelaySession(relayAddress, sessionID.String(), relayPublicKey); err != nil {
		t.Fatal(err)
	}
	session := meter.sessions[sessionID]
	prefix := natBillingSnapshot{
		cumulative: billingvoucher.CumulativeWindowBytes / 2,
		lastRecord: billingvoucher.Identifier{44}, lastRecordSequence: 1,
		recordSet: billingvoucher.Digest{45},
	}
	covered := natBillingSnapshot{
		cumulative: billingvoucher.CumulativeWindowBytes,
		lastRecord: billingvoucher.Identifier{46}, lastRecordSequence: 2,
		recordSet: billingvoucher.Digest{47},
	}
	session.cumulative = covered.cumulative
	session.lastRecord = covered.lastRecord
	session.recordSet = covered.recordSet
	session.nextAssigned = 3
	session.nextAdvance = 3
	session.confirmedSequence = 2
	session.snapshots[prefix.cumulative] = prefix
	session.snapshots[covered.cumulative] = covered
	appendNatClaimableSnapshot(session, covered)
	body := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: sessionID,
		PayerNatID: meter.payerID, PayeeRelayID: session.relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: 1,
		CumulativeUniqueBytes: covered.cumulative, LastRecordID: covered.lastRecord,
		LastRecordSequence: covered.lastRecordSequence, RecordSetDigest: covered.recordSet,
		PolicyDigest: billingvoucher.CurrentPolicyDigest(), AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	relaySignature, _ := billingvoucher.SignRelay(body, relayKey)
	bodyBytes, _ := body.CanonicalBytes()
	expected, err := meter.cosign(bodyBytes, relaySignature, relayPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	meter.invalidateRelaySession(relayAddress)
	status, err := meter.activateRelaySessionWithState(
		relayAddress, sessionID.String(), relayPublicKey, &prefix,
	)
	if err != nil {
		t.Fatalf("recover lost cosigned response: %v", err)
	}
	if status.recoveryVoucher == nil || status.cumulative != covered.cumulative ||
		status.lastRecordSequence != covered.lastRecordSequence {
		t.Fatalf("recovery status = %+v", status)
	}
	expectedID, _ := expected.ID()
	recoveredID, _ := status.recoveryVoucher.ID()
	if recoveredID != expectedID {
		t.Fatal("recovery returned a different mutual voucher")
	}
}

func natBillingTestE2ERecord(plaintextBytes, sequence uint64) []byte {
	record := make([]byte, 64+int(plaintextBytes)+16)
	copy(record[:8], "BNFSE2E2")
	record[8] = 2
	record[9] = 1
	binary.BigEndian.PutUint32(record[12:16], 1)
	binary.BigEndian.PutUint64(record[16:24], sequence)
	record[24] = 1
	binary.BigEndian.PutUint64(record[56:64], plaintextBytes)
	return record
}

func TestBillingCosignChecksLastRecordSequence(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payerKey.PublicKey())
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relayKey.PublicKey())
	sessionID := billingvoucher.Identifier{11}
	lastRecord := billingvoucher.Identifier{12}
	recordSet := billingvoucher.Digest{13}
	meter.sessions[sessionID] = &natBillingSession{
		relayID: relayID, nextAssigned: 8, nextAdvance: 8,
		pending: make(map[uint64]natBillingRecord),
		snapshots: map[uint64]natBillingSnapshot{
			1024: {cumulative: 1024, lastRecord: lastRecord, lastRecordSequence: 7, recordSet: recordSet},
		},
		cumulative: 1024, lastRecord: lastRecord, recordSet: recordSet,
	}
	appendNatClaimableSnapshot(meter.sessions[sessionID], meter.sessions[sessionID].snapshots[1024])
	body := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: sessionID,
		PayerNatID: payerID, PayeeRelayID: relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: 1,
		CumulativeUniqueBytes: 1024, LastRecordID: lastRecord,
		LastRecordSequence: 6, RecordSetDigest: recordSet,
		PolicyDigest:           billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	relaySignature, err := billingvoucher.SignRelay(body, relayKey)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, _ := body.CanonicalBytes()
	if _, err := meter.cosign(bodyBytes, relaySignature, crypoto.GetPubKeyStr(relayKey.PublicKey())); err == nil {
		t.Fatal("Relay claim with a forged LastRecordSequence was cosigned")
	}
	body.LastRecordSequence = 7
	relaySignature, _ = billingvoucher.SignRelay(body, relayKey)
	bodyBytes, _ = body.CanonicalBytes()
	if _, err := meter.cosign(bodyBytes, relaySignature, crypoto.GetPubKeyStr(relayKey.PublicKey())); err != nil {
		t.Fatalf("matching LastRecordSequence should cosign: %v", err)
	}
}

func TestBillingCosignPrunesSnapshotsAtSignedWatermark(t *testing.T) {
	payerKey, _ := crypoto.MakeKeyPair()
	relayKey, _ := crypoto.MakeKeyPair()
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payerKey.PublicKey())
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relayKey.PublicKey())
	sessionID := billingvoucher.Identifier{21}
	session := &natBillingSession{
		relayID: relayID, nextAssigned: 101, nextAdvance: 101,
		pending: make(map[uint64]natBillingRecord), snapshots: make(map[uint64]natBillingSnapshot),
		cumulative: 100,
	}
	for cumulative := uint64(1); cumulative <= 100; cumulative++ {
		lastRecord := billingvoucher.Identifier{byte(cumulative), 1}
		recordSet := billingvoucher.Digest{byte(cumulative), 2}
		session.snapshots[cumulative] = natBillingSnapshot{
			cumulative: cumulative, lastRecord: lastRecord,
			lastRecordSequence: cumulative, recordSet: recordSet,
		}
		if cumulative == 100 {
			session.lastRecord = lastRecord
			session.recordSet = recordSet
		}
	}
	meter.sessions[sessionID] = session
	appendNatClaimableSnapshot(session, session.snapshots[50])
	appendNatClaimableSnapshot(session, session.snapshots[100])

	firstBody := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: sessionID,
		PayerNatID: payerID, PayeeRelayID: relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: 1,
		CumulativeUniqueBytes: 50, LastRecordID: session.snapshots[50].lastRecord,
		LastRecordSequence: 50, RecordSetDigest: session.snapshots[50].recordSet,
		PolicyDigest:           billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	firstSignature, _ := billingvoucher.SignRelay(firstBody, relayKey)
	firstBytes, _ := firstBody.CanonicalBytes()
	firstVoucher, err := meter.cosign(firstBytes, firstSignature, crypoto.GetPubKeyStr(relayKey.PublicKey()))
	if err != nil {
		t.Fatalf("cosign first watermark: %v", err)
	}
	if len(session.snapshots) != 51 {
		t.Fatalf("snapshots after first watermark = %d, want 51", len(session.snapshots))
	}
	if _, retained := session.snapshots[50]; !retained {
		t.Fatal("last signed watermark snapshot was not retained")
	}
	delete(session.snapshots, 50)
	replayed, err := meter.cosign(firstBytes, firstSignature, crypoto.GetPubKeyStr(relayKey.PublicKey()))
	if err != nil {
		t.Fatalf("same-sequence retry should use channel.last: %v", err)
	}
	firstID, _ := firstVoucher.ID()
	replayedID, _ := replayed.ID()
	if replayedID != firstID {
		t.Fatal("same-sequence retry returned a different voucher")
	}

	secondBody := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: sessionID,
		PayerNatID: payerID, PayeeRelayID: relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: 2,
		PreviousMutualVoucherID: firstID,
		CumulativeUniqueBytes:   100, LastRecordID: session.snapshots[100].lastRecord,
		LastRecordSequence: 100, RecordSetDigest: session.snapshots[100].recordSet,
		PolicyDigest:           billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	secondSignature, _ := billingvoucher.SignRelay(secondBody, relayKey)
	secondBytes, _ := secondBody.CanonicalBytes()
	if _, err := meter.cosign(secondBytes, secondSignature, crypoto.GetPubKeyStr(relayKey.PublicKey())); err != nil {
		t.Fatalf("cosign second watermark: %v", err)
	}
	if len(session.snapshots) != 1 {
		t.Fatalf("snapshots after second watermark = %d, want 1", len(session.snapshots))
	}
	if _, retained := session.snapshots[100]; !retained {
		t.Fatal("latest signed watermark snapshot was not retained")
	}
}

type failingBillingStream struct{}

func (*failingBillingStream) Close() error { return nil }
func (*failingBillingStream) NextMessage(context.Context) (*network.Message, error) {
	return nil, errors.New("unused")
}
func (*failingBillingStream) SendMessage(context.Context, *network.Message) error {
	return errors.New("simulated ambiguous send failure")
}
func (*failingBillingStream) SendMessageAsync(context.Context, *network.Message, network.MessageResultCallback) error {
	return errors.New("unused")
}
func (*failingBillingStream) NodeId() string                                           { return "peer" }
func (*failingBillingStream) ConnectionId() string                                     { return "connection" }
func (*failingBillingStream) SetCryptoSuite(network.EncrypSuite)                       {}
func (*failingBillingStream) SetOutboundRecordObserver(network.OutboundRecordObserver) {}

type orderedBillingStream struct {
	mu       sync.Mutex
	observer network.OutboundRecordObserver
	initial  chan uint64
	release  chan struct{}
}

func newOrderedBillingStream() *orderedBillingStream {
	return &orderedBillingStream{
		initial: make(chan uint64, 2),
		release: make(chan struct{}, 2),
	}
}

func (*orderedBillingStream) Close() error { return nil }
func (*orderedBillingStream) NextMessage(context.Context) (*network.Message, error) {
	return nil, errors.New("unused")
}
func (stream *orderedBillingStream) SendMessage(ctx context.Context, message *network.Message) error {
	return stream.SendMessageWithInitialWrite(ctx, message, nil)
}
func (stream *orderedBillingStream) SendMessageWithInitialWrite(
	ctx context.Context,
	message *network.Message,
	onInitialWrite func(),
) error {
	record := natBillingTestE2ERecord(message.Header.BillingBytes, message.Header.BillingSequence)
	sealed := *message
	header := *message.Header
	sealed.Header = &header
	sealed.Payload = record

	stream.mu.Lock()
	observer := stream.observer
	stream.mu.Unlock()
	if observer != nil {
		metadata, err := crypoto.InspectE2ERecord(record)
		if err != nil {
			return err
		}
		if err := observer(&sealed, metadata.MessageID); err != nil {
			return err
		}
	}
	if onInitialWrite != nil {
		onInitialWrite()
	}
	stream.initial <- message.Header.BillingSequence
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stream.release:
		return nil
	}
}
func (*orderedBillingStream) SendMessageAsync(context.Context, *network.Message, network.MessageResultCallback) error {
	return errors.New("unused")
}
func (*orderedBillingStream) NodeId() string       { return "peer" }
func (*orderedBillingStream) ConnectionId() string { return "connection" }
func (*orderedBillingStream) SetCryptoSuite(network.EncrypSuite) {
}
func (stream *orderedBillingStream) SetOutboundRecordObserver(observer network.OutboundRecordObserver) {
	stream.mu.Lock()
	stream.observer = observer
	stream.mu.Unlock()
}
