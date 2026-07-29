package natnode

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingrecord"
	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
)

const (
	maximumNatBillingEvidenceEntries         = 4096
	maximumNatBillingReconciliationSnapshots = 65536
)

type natBillingRecord struct {
	bytes    uint64
	recordID billingvoucher.Identifier
}

type natBillingSnapshot struct {
	cumulative         uint64
	lastRecord         billingvoucher.Identifier
	lastRecordSequence uint64
	recordSet          billingvoucher.Digest
}

type natBillingSession struct {
	relayID                billingvoucher.Identifier
	nextAssigned           uint64
	nextAdvance            uint64
	confirmedSequence      uint64
	confirmedOutOfOrder    map[uint64]struct{}
	cosignedRecordSequence uint64
	assignedBytes          map[uint64]uint64
	activeSends            map[uint64]struct{}
	reconciliationDraining bool
	pending                map[uint64]natBillingRecord
	snapshots              map[uint64]natBillingSnapshot
	snapshotOrder          []uint64
	claimable              []natBillingSnapshot
	claimableCumulative    map[uint64]struct{}
	cumulative             uint64
	lastRecord             billingvoucher.Identifier
	recordSet              billingvoucher.Digest
}

type natVoucherChannel struct {
	last billingvoucher.MutualVoucher
	has  bool
}

type natBillingMeter struct {
	mu                    sync.Mutex
	privateKey            *ecdh.PrivateKey
	payerID               billingvoucher.Identifier
	sessions              map[billingvoucher.Identifier]*natBillingSession
	relaySessions         map[string]billingvoucher.Identifier
	relayReady            map[string]chan struct{}
	invalidSessions       map[billingvoucher.Identifier]struct{}
	sendOrder             map[billingvoucher.Identifier]chan struct{}
	channels              map[string]*natVoucherChannel
	cert                  *admission.SignedCert
	enabled               bool
	privateSnapshotWriter *natBillingPrivateSnapshotWriter
}

type natBillingSessionStatus struct {
	preexisting        bool
	resetRequired      bool
	draining           bool
	cumulative         uint64
	lastRecord         billingvoucher.Identifier
	lastRecordSequence uint64
	recordSet          billingvoucher.Digest
	recoveryVoucher    *billingvoucher.MutualVoucher
}

func newNatBillingMeter(privateKey *ecdh.PrivateKey) (*natBillingMeter, error) {
	payerID, err := billingvoucher.NodeIDFromPublicKey(privateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	meter := &natBillingMeter{
		privateKey: privateKey, payerID: payerID,
		sessions:        make(map[billingvoucher.Identifier]*natBillingSession),
		relaySessions:   make(map[string]billingvoucher.Identifier),
		relayReady:      make(map[string]chan struct{}),
		invalidSessions: make(map[billingvoucher.Identifier]struct{}),
		sendOrder:       make(map[billingvoucher.Identifier]chan struct{}),
		channels:        make(map[string]*natVoucherChannel),
	}
	return meter, nil
}

func (meter *natBillingMeter) acquireSendOrder(ctx context.Context, relayAddr string) (func(), error) {
	if meter == nil {
		return func() {}, nil
	}
	if ctx == nil {
		return nil, errors.New("natnode: nil context while acquiring billing send order")
	}
	meter.mu.Lock()
	if !meter.enabled {
		meter.mu.Unlock()
		return func() {}, nil
	}
	sessionID, exists := meter.relaySessions[relayAddr]
	if !exists {
		meter.mu.Unlock()
		return nil, errors.New("natnode: billing relay session is unavailable")
	}
	if _, invalid := meter.invalidSessions[sessionID]; invalid {
		meter.mu.Unlock()
		return nil, errors.New("natnode: billing relay session requires reconciliation")
	}
	gate := meter.sendOrder[sessionID]
	if gate == nil {
		gate = make(chan struct{}, 1)
		gate <- struct{}{}
		meter.sendOrder[sessionID] = gate
	}
	meter.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-gate:
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			gate <- struct{}{}
		})
	}, nil
}

func newNatBillingSession() *natBillingSession {
	return &natBillingSession{
		nextAssigned: 1, nextAdvance: 1,
		confirmedOutOfOrder: make(map[uint64]struct{}),
		assignedBytes:       make(map[uint64]uint64),
		activeSends:         make(map[uint64]struct{}),
		pending:             make(map[uint64]natBillingRecord),
		snapshots:           make(map[uint64]natBillingSnapshot),
		claimableCumulative: make(map[uint64]struct{}),
	}
}

func (meter *natBillingMeter) enable(cert *admission.SignedCert) error {
	if cert == nil || cert.Cert.Role != admission.RoleServer {
		return errors.New("natnode: secure billing requires a server certificate")
	}
	if cert.Cert.SubjectNodeID != meter.payerID.String() ||
		cert.Cert.SubjectPubKey != hex.EncodeToString(meter.privateKey.PublicKey().Bytes()) {
		return errors.New("natnode: billing certificate does not match node identity")
	}
	meter.mu.Lock()
	meter.cert = cert
	meter.enabled = true
	meter.notifyPrivateSnapshotLocked()
	meter.mu.Unlock()
	return nil
}

func (meter *natBillingMeter) activateRelaySession(relayAddr, sessionHex, relayPublicKeyHex string) (natBillingSessionStatus, error) {
	return meter.activateRelaySessionWithState(relayAddr, sessionHex, relayPublicKeyHex, nil)
}

func (meter *natBillingMeter) activateRelaySessionWithState(
	relayAddr, sessionHex, relayPublicKeyHex string,
	relayState *natBillingSnapshot,
) (natBillingSessionStatus, error) {
	if relayAddr == "" {
		return natBillingSessionStatus{}, errors.New("natnode: billing relay address is required")
	}
	sessionID, err := billingvoucher.ParseIdentifierHex(sessionHex)
	if err != nil {
		return natBillingSessionStatus{}, fmt.Errorf("natnode: invalid negotiated billing session: %w", err)
	}
	relayPublicBytes, err := hex.DecodeString(relayPublicKeyHex)
	if err != nil {
		return natBillingSessionStatus{}, errors.New("natnode: invalid negotiated Relay public key")
	}
	relayPublicKey, err := ecdh.P256().NewPublicKey(relayPublicBytes)
	if err != nil {
		return natBillingSessionStatus{}, errors.New("natnode: invalid negotiated Relay public key")
	}
	relayID, err := billingvoucher.NodeIDFromPublicKey(relayPublicKey)
	if err != nil {
		return natBillingSessionStatus{}, err
	}

	meter.mu.Lock()
	defer meter.mu.Unlock()
	defer meter.notifyPrivateSnapshotLocked()
	previousID, hasPrevious := meter.relaySessions[relayAddr]
	existing := meter.sessions[sessionID]
	if existing != nil && existing.relayID != relayID {
		return natBillingSessionStatus{}, errors.New("natnode: billing session is already bound to another Relay")
	}
	_, invalid := meter.invalidSessions[sessionID]
	if invalid && !meter.sessionBoundLocked(sessionID) {
		return natBillingSessionStatus{resetRequired: true}, nil
	}
	if hasPrevious && previousID != sessionID && !meter.sessionSafeToReplaceLocked(previousID) {
		return natBillingSessionStatus{}, errors.New("natnode: cannot replace billing session with state not covered by its last mutual voucher")
	}
	if existing != nil {
		if existing.nextAdvance == 0 {
			return natBillingSessionStatus{}, errors.New("natnode: active billing session state is unavailable")
		}
		if relayState == nil {
			if invalid {
				return natBillingSessionStatus{resetRequired: true}, nil
			}
			if !hasPrevious || previousID != sessionID {
				return natBillingSessionStatus{}, errors.New("natnode: preexisting billing session requires a signed Relay watermark")
			}
		} else if invalid {
			result, err := meter.reconcileRelaySessionStateLocked(sessionID, existing, *relayState)
			if err != nil {
				return natBillingSessionStatus{}, err
			}
			if result.draining {
				return natBillingSessionStatus{
					preexisting: true, draining: true,
					cumulative: result.target.cumulative, lastRecord: result.target.lastRecord,
					lastRecordSequence: result.target.lastRecordSequence, recordSet: result.target.recordSet,
					recoveryVoucher: result.recoveryVoucher,
				}, nil
			}
			delete(meter.invalidSessions, sessionID)
			if hasPrevious && previousID != sessionID {
				meter.invalidSessions[previousID] = struct{}{}
			}
			meter.relaySessions[relayAddr] = sessionID
			meter.markRelayReadyLocked(relayAddr)
			return natBillingSessionStatus{
				preexisting: true, cumulative: existing.cumulative, lastRecord: existing.lastRecord,
				lastRecordSequence: existing.nextAdvance - 1, recordSet: existing.recordSet,
				recoveryVoucher: result.recoveryVoucher,
			}, nil
		} else {
			current := natBillingSessionSnapshot(existing)
			if *relayState != current {
				return natBillingSessionStatus{}, errors.New("natnode: signed Relay watermark differs from the active billing session")
			}
		}
		if hasPrevious && previousID != sessionID {
			meter.invalidSessions[previousID] = struct{}{}
		}
		meter.relaySessions[relayAddr] = sessionID
		meter.markRelayReadyLocked(relayAddr)
		return natBillingSessionStatus{
			preexisting: true, cumulative: existing.cumulative, lastRecord: existing.lastRecord,
			lastRecordSequence: existing.nextAdvance - 1, recordSet: existing.recordSet,
		}, nil
	}
	if hasPrevious && previousID != sessionID {
		if !meter.sessionSafeToReplaceLocked(previousID) {
			return natBillingSessionStatus{}, errors.New("natnode: cannot replace billing session with state not covered by its last mutual voucher")
		}
	}
	if relayState != nil && !billingSnapshotEmpty(*relayState) {
		if !billingSnapshotConsistent(*relayState) {
			return natBillingSessionStatus{}, errors.New("natnode: fresh billing session advertised an inconsistent Relay watermark")
		}
		return natBillingSessionStatus{resetRequired: true}, nil
	}
	preexisting := existing != nil
	if existing == nil {
		session := newNatBillingSession()
		session.relayID = relayID
		meter.sessions[sessionID] = session
		existing = session
	}
	if hasPrevious {
		meter.invalidSessions[previousID] = struct{}{}
	}
	meter.relaySessions[relayAddr] = sessionID
	meter.markRelayReadyLocked(relayAddr)
	return natBillingSessionStatus{
		preexisting: preexisting, cumulative: existing.cumulative, lastRecord: existing.lastRecord,
		lastRecordSequence: existing.nextAdvance - 1, recordSet: existing.recordSet,
	}, nil
}

func (meter *natBillingMeter) sessionBoundLocked(sessionID billingvoucher.Identifier) bool {
	for _, activeSessionID := range meter.relaySessions {
		if activeSessionID == sessionID {
			return true
		}
	}
	return false
}

func (meter *natBillingMeter) markRelayReadyLocked(relayAddr string) {
	ready := meter.relayReady[relayAddr]
	if ready == nil {
		ready = make(chan struct{})
		meter.relayReady[relayAddr] = ready
	}
	select {
	case <-ready:
	default:
		close(ready)
	}
}

func (meter *natBillingMeter) reconcileRelaySessionLocked(
	sessionID billingvoucher.Identifier,
	session *natBillingSession,
	relayState natBillingSnapshot,
) (*billingvoucher.MutualVoucher, error) {
	result, err := meter.reconcileRelaySessionStateLocked(sessionID, session, relayState)
	return result.recoveryVoucher, err
}

type natBillingReconciliationResult struct {
	target          natBillingSnapshot
	recoveryVoucher *billingvoucher.MutualVoucher
	draining        bool
}

func (meter *natBillingMeter) reconcileRelaySessionStateLocked(
	sessionID billingvoucher.Identifier,
	session *natBillingSession,
	relayState natBillingSnapshot,
) (natBillingReconciliationResult, error) {
	if session == nil || session.nextAdvance == 0 {
		return natBillingReconciliationResult{}, errors.New("natnode: billing session state is unavailable for reconciliation")
	}
	if len(session.pending) != 0 {
		return natBillingReconciliationResult{}, errors.New("natnode: cannot reconcile a billing session with pending records")
	}
	if !billingSnapshotConsistent(relayState) {
		return natBillingReconciliationResult{}, errors.New("natnode: Relay advertised an inconsistent billing watermark")
	}
	current := natBillingSessionSnapshot(session)
	target := relayState
	var recoveryVoucher *billingvoucher.MutualVoucher
	assignedAdvance := false
	assignedAdvanceClaimable := false
	channel := meter.channels[sessionID.String()+"|"+session.relayID.String()]
	if channel != nil && channel.has {
		body := channel.last.Body
		beforeVoucher := relayState.lastRecordSequence < body.LastRecordSequence &&
			relayState.cumulative < body.CumulativeUniqueBytes
		atVoucher := relayState.lastRecordSequence == body.LastRecordSequence &&
			relayState.cumulative == body.CumulativeUniqueBytes && relayState.lastRecord == body.LastRecordID &&
			relayState.recordSet == body.RecordSetDigest
		afterVoucher := relayState.lastRecordSequence > body.LastRecordSequence &&
			relayState.cumulative > body.CumulativeUniqueBytes
		if beforeVoucher || atVoucher {
			recovered := channel.last
			recoveryVoucher = &recovered
			target = natBillingSnapshot{
				cumulative: body.CumulativeUniqueBytes, lastRecord: body.LastRecordID,
				lastRecordSequence: body.LastRecordSequence, recordSet: body.RecordSetDigest,
			}
		} else if !afterVoucher {
			return natBillingReconciliationResult{}, errors.New("natnode: Relay watermark conflicts with the last mutual voucher")
		}
	}
	if recoveryVoucher == nil && relayState != current && !billingSnapshotEmpty(relayState) {
		local, ok := session.snapshots[relayState.cumulative]
		if !ok || local != relayState {
			assignedAdvance, assignedAdvanceClaimable = locallyAssignedRelayAdvanceMatches(
				session, channel, current, relayState,
			)
		}
		if (!ok || local != relayState) && !assignedAdvance {
			oldestSequence, newestSequence := natBillingSnapshotSequenceRange(session)
			return natBillingReconciliationResult{}, fmt.Errorf(
				"natnode: signed Relay watermark does not match local record evidence: relay_sequence=%d relay_cumulative=%d local_sequence=%d local_cumulative=%d next_assigned=%d assigned_records=%d active_sends=%d retained_sequence=%d..%d retained_snapshots=%d exact_cumulative=%t",
				relayState.lastRecordSequence, relayState.cumulative,
				current.lastRecordSequence, current.cumulative, session.nextAssigned,
				len(session.assignedBytes), len(session.activeSends), oldestSequence, newestSequence,
				len(session.snapshots), ok,
			)
		}
	}
	if target.lastRecordSequence < highestNatBillingConfirmedSequence(session) {
		return natBillingReconciliationResult{}, errors.New("natnode: Relay watermark would roll back transport-confirmed usage")
	}
	if len(session.activeSends) != 0 {
		session.reconciliationDraining = true
		return natBillingReconciliationResult{
			target: target, recoveryVoucher: recoveryVoucher, draining: true,
		}, nil
	}
	if assignedAdvance {
		session.snapshots[target.cumulative] = target
		session.snapshotOrder = append(session.snapshotOrder, target.cumulative)
		if assignedAdvanceClaimable {
			appendNatClaimableSnapshot(session, target)
		}
	}
	if target != current {
		session.cumulative = target.cumulative
		session.lastRecord = target.lastRecord
		session.recordSet = target.recordSet
		session.nextAdvance = target.lastRecordSequence + 1
	}
	session.nextAssigned = session.nextAdvance
	session.confirmedSequence = target.lastRecordSequence
	clear(session.confirmedOutOfOrder)
	clear(session.assignedBytes)
	session.reconciliationDraining = false
	for cumulative := range session.snapshots {
		if cumulative > target.cumulative {
			delete(session.snapshots, cumulative)
		}
	}
	retainedClaimable := session.claimable[:0]
	for _, snapshot := range session.claimable {
		if snapshot.cumulative <= target.cumulative {
			retainedClaimable = append(retainedClaimable, snapshot)
			continue
		}
		delete(session.claimableCumulative, snapshot.cumulative)
	}
	session.claimable = retainedClaimable
	return natBillingReconciliationResult{target: target, recoveryVoucher: recoveryVoucher}, nil
}

func locallyAssignedRelayAdvanceMatches(
	session *natBillingSession,
	channel *natVoucherChannel,
	current, relayState natBillingSnapshot,
) (bool, bool) {
	if session == nil || relayState.lastRecordSequence != current.lastRecordSequence+1 ||
		relayState.lastRecordSequence < session.nextAdvance ||
		relayState.lastRecordSequence >= session.nextAssigned {
		return false, false
	}
	assignedBytes, ok := session.assignedBytes[relayState.lastRecordSequence]
	if !ok || current.cumulative > billingvoucher.MaxBillableBytes-assignedBytes ||
		current.cumulative+assignedBytes != relayState.cumulative {
		return false, false
	}
	windowBase := uint64(0)
	if channel != nil && channel.has {
		windowBase = channel.last.Body.CumulativeUniqueBytes
	}
	if len(session.claimable) != 0 {
		windowBase = session.claimable[len(session.claimable)-1].cumulative
	}
	if current.cumulative < windowBase {
		return false, false
	}
	windowBytes := current.cumulative - windowBase
	if windowBytes > billingvoucher.CumulativeWindowBytes ||
		assignedBytes > billingvoucher.CumulativeWindowBytes-windowBytes {
		return false, false
	}
	return true, windowBytes+assignedBytes == billingvoucher.CumulativeWindowBytes
}

func natBillingSessionSnapshot(session *natBillingSession) natBillingSnapshot {
	return natBillingSnapshot{
		cumulative: session.cumulative, lastRecord: session.lastRecord,
		lastRecordSequence: session.nextAdvance - 1, recordSet: session.recordSet,
	}
}

func billingSnapshotEmpty(snapshot natBillingSnapshot) bool {
	return snapshot == (natBillingSnapshot{})
}

func billingSnapshotConsistent(snapshot natBillingSnapshot) bool {
	if billingSnapshotEmpty(snapshot) {
		return true
	}
	return snapshot.cumulative > 0 && snapshot.lastRecordSequence > 0 &&
		snapshot.lastRecord != (billingvoucher.Identifier{}) && snapshot.recordSet != (billingvoucher.Digest{})
}

func natBillingSnapshotSequenceRange(session *natBillingSession) (uint64, uint64) {
	if session == nil || len(session.snapshots) == 0 {
		return 0, 0
	}
	oldest := uint64(^uint64(0))
	newest := uint64(0)
	for _, snapshot := range session.snapshots {
		if snapshot.lastRecordSequence < oldest {
			oldest = snapshot.lastRecordSequence
		}
		if snapshot.lastRecordSequence > newest {
			newest = snapshot.lastRecordSequence
		}
	}
	return oldest, newest
}

func (meter *natBillingMeter) sessionSafeToReplaceLocked(sessionID billingvoucher.Identifier) bool {
	session := meter.sessions[sessionID]
	if session == nil || session.nextAssigned == 0 || session.nextAdvance == 0 ||
		len(session.pending) != 0 || len(session.activeSends) != 0 ||
		session.reconciliationDraining || session.nextAssigned != session.nextAdvance {
		return false
	}
	lastRecordSequence := session.nextAdvance - 1
	channel := meter.channels[sessionID.String()+"|"+session.relayID.String()]
	if channel == nil || !channel.has {
		return session.cumulative == 0 && lastRecordSequence == 0 &&
			session.lastRecord == (billingvoucher.Identifier{}) && session.recordSet == (billingvoucher.Digest{})
	}
	body := channel.last.Body
	return body.SessionID == sessionID && body.PayerNatID == meter.payerID && body.PayeeRelayID == session.relayID &&
		body.CumulativeUniqueBytes == session.cumulative && body.LastRecordID == session.lastRecord &&
		body.LastRecordSequence == lastRecordSequence && body.RecordSetDigest == session.recordSet
}

func (meter *natBillingMeter) invalidateRelaySession(relayAddr string) {
	if meter == nil || relayAddr == "" {
		return
	}
	meter.mu.Lock()
	if sessionID, ok := meter.relaySessions[relayAddr]; ok {
		meter.invalidSessions[sessionID] = struct{}{}
	}
	meter.relayReady[relayAddr] = make(chan struct{})
	meter.notifyPrivateSnapshotLocked()
	meter.mu.Unlock()
}

func (meter *natBillingMeter) waitRelaySession(ctx context.Context, relayAddr string) error {
	if meter == nil {
		return nil
	}
	meter.mu.Lock()
	if !meter.enabled {
		meter.mu.Unlock()
		return nil
	}
	if sessionID, ok := meter.relaySessions[relayAddr]; ok {
		if _, invalid := meter.invalidSessions[sessionID]; !invalid {
			meter.mu.Unlock()
			return nil
		}
	}
	ready := meter.relayReady[relayAddr]
	if ready == nil {
		ready = make(chan struct{})
		meter.relayReady[relayAddr] = ready
	}
	meter.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ready:
		return nil
	}
}

func (meter *natBillingMeter) prepare(message *network.Message, relayAddr string) error {
	if meter == nil || message == nil || message.Header == nil {
		return nil
	}
	meter.mu.Lock()
	defer meter.mu.Unlock()
	if !meter.enabled {
		return nil
	}
	sessionID, ok := meter.relaySessions[relayAddr]
	if !ok {
		return fmt.Errorf("natnode: secure billing session is not ready for Relay %s", relayAddr)
	}
	if _, invalid := meter.invalidSessions[sessionID]; invalid {
		return fmt.Errorf("natnode: secure billing session for Relay %s requires reconciliation", relayAddr)
	}
	billableBytes := uint64(len(message.Payload))
	if billableBytes == 0 || billableBytes > billingvoucher.CumulativeWindowBytes {
		return fmt.Errorf("natnode: billable message size %d exceeds secure window", billableBytes)
	}
	session := meter.sessions[sessionID]
	if session == nil {
		return errors.New("natnode: negotiated billing session is unavailable")
	}
	sequence := session.nextAssigned
	if sequence == 0 || sequence > billingvoucher.MaxSequence {
		return errors.New("natnode: billing record sequence exhausted")
	}
	if sequence < session.nextAdvance || sequence-session.nextAdvance >= maximumNatBillingEvidenceEntries {
		return errors.New("natnode: assigned billing record gap exceeds evidence limit")
	}
	if session.assignedBytes == nil {
		session.assignedBytes = make(map[uint64]uint64)
	}
	if session.activeSends == nil {
		session.activeSends = make(map[uint64]struct{})
	}
	session.assignedBytes[sequence] = billableBytes
	session.activeSends[sequence] = struct{}{}
	session.nextAssigned++
	message.Header.BillingSessionID = [32]byte(sessionID)
	message.Header.BillingSequence = sequence
	message.Header.BillingBytes = billableBytes
	return nil
}

func (meter *natBillingMeter) completeSend(message *network.Message) bool {
	if meter == nil || message == nil || message.Header == nil || message.Header.BillingSequence == 0 {
		return false
	}
	sessionID := billingvoucher.Identifier(message.Header.BillingSessionID)
	sequence := message.Header.BillingSequence
	meter.mu.Lock()
	defer meter.mu.Unlock()
	session := meter.sessions[sessionID]
	if session == nil {
		return false
	}
	delete(session.activeSends, sequence)
	_, invalid := meter.invalidSessions[sessionID]
	return (invalid || session.reconciliationDraining) && len(session.activeSends) == 0
}

func (meter *natBillingMeter) confirm(message *network.Message) error {
	if meter == nil || message == nil || message.Header == nil || message.Header.BillingSequence == 0 {
		return nil
	}
	sessionID := billingvoucher.Identifier(message.Header.BillingSessionID)
	sequence := message.Header.BillingSequence
	meter.mu.Lock()
	defer meter.mu.Unlock()
	session := meter.sessions[sessionID]
	if session == nil || sequence >= session.nextAdvance || sequence >= session.nextAssigned {
		return errors.New("natnode: transport confirmed a billing record without local sealed evidence")
	}
	if sequence <= session.confirmedSequence {
		return nil
	}
	if sequence == session.confirmedSequence+1 {
		session.confirmedSequence = sequence
		for session.confirmedSequence < billingvoucher.MaxSequence {
			next := session.confirmedSequence + 1
			if _, confirmed := session.confirmedOutOfOrder[next]; !confirmed {
				break
			}
			delete(session.confirmedOutOfOrder, next)
			session.confirmedSequence = next
		}
		meter.notifyPrivateSnapshotLocked()
		return nil
	}
	if session.confirmedOutOfOrder == nil {
		session.confirmedOutOfOrder = make(map[uint64]struct{})
	}
	if _, duplicate := session.confirmedOutOfOrder[sequence]; duplicate {
		return nil
	}
	if len(session.confirmedOutOfOrder) >= maximumNatBillingEvidenceEntries {
		return errors.New("natnode: out-of-order transport confirmation count exceeds evidence limit")
	}
	session.confirmedOutOfOrder[sequence] = struct{}{}
	return nil
}

func highestNatBillingConfirmedSequence(session *natBillingSession) uint64 {
	if session == nil {
		return 0
	}
	highest := session.confirmedSequence
	for sequence := range session.confirmedOutOfOrder {
		if sequence > highest {
			highest = sequence
		}
	}
	return highest
}

func (meter *natBillingMeter) observe(message *network.Message, e2eRecordID []byte) error {
	if meter == nil || message == nil || message.Header == nil || message.Header.BillingSequence == 0 {
		return nil
	}
	metadata, err := crypoto.InspectE2ERecord(message.Payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(metadata.MessageID, e2eRecordID) || metadata.PlaintextBytes != message.Header.BillingBytes {
		return errors.New("natnode: sealed billing record metadata mismatch")
	}
	record := billingrecord.Record{
		SessionID: billingvoucher.Identifier(message.Header.BillingSessionID),
		Sequence:  message.Header.BillingSequence, Bytes: message.Header.BillingBytes,
		Connection: message.Header.ConnectionId, E2ERecordID: e2eRecordID, Ciphertext: message.Payload,
	}
	recordID, err := record.ID()
	if err != nil {
		return err
	}

	meter.mu.Lock()
	defer meter.mu.Unlock()
	defer meter.notifyPrivateSnapshotLocked()
	session := meter.sessions[record.SessionID]
	if session == nil {
		return errors.New("natnode: unknown billing session")
	}
	if existing, ok := session.pending[record.Sequence]; ok {
		if existing.bytes != record.Bytes || existing.recordID != recordID {
			return errors.New("natnode: conflicting billing record sequence")
		}
		return nil
	}
	if record.Sequence < session.nextAdvance {
		return nil
	}
	assignedBytes, assigned := session.assignedBytes[record.Sequence]
	if !assigned || assignedBytes != record.Bytes {
		return errors.New("natnode: sealed billing record does not match local assignment")
	}
	if record.Sequence > session.nextAdvance {
		if record.Sequence-session.nextAdvance > maximumNatBillingEvidenceEntries {
			return errors.New("natnode: pending billing record gap exceeds evidence limit")
		}
		if len(session.pending) >= maximumNatBillingEvidenceEntries {
			return errors.New("natnode: pending billing record count exceeds evidence limit")
		}
	}
	session.pending[record.Sequence] = natBillingRecord{bytes: record.Bytes, recordID: recordID}
	for {
		next, ok := session.pending[session.nextAdvance]
		if !ok {
			break
		}
		if session.cumulative > billingvoucher.MaxBillableBytes-next.bytes {
			return errors.New("natnode: cumulative billing bytes overflow")
		}
		windowBase := uint64(0)
		if channel := meter.channels[record.SessionID.String()+"|"+session.relayID.String()]; channel != nil && channel.has {
			windowBase = channel.last.Body.CumulativeUniqueBytes
		}
		if len(session.claimable) != 0 {
			windowBase = session.claimable[len(session.claimable)-1].cumulative
		}
		windowBytes := session.cumulative - windowBase
		if windowBytes > 0 && next.bytes > billingvoucher.CumulativeWindowBytes-windowBytes {
			appendNatClaimableSnapshot(session, natBillingSnapshot{
				cumulative: session.cumulative, lastRecord: session.lastRecord,
				lastRecordSequence: session.nextAdvance - 1, recordSet: session.recordSet,
			})
			windowBase = session.cumulative
		}
		session.cumulative += next.bytes
		session.lastRecord = next.recordID
		session.recordSet, err = billingrecord.Advance(session.recordSet, next.recordID, session.nextAdvance, next.bytes)
		if err != nil {
			return err
		}
		session.snapshots[session.cumulative] = natBillingSnapshot{
			cumulative: session.cumulative, lastRecord: session.lastRecord,
			lastRecordSequence: session.nextAdvance, recordSet: session.recordSet,
		}
		session.snapshotOrder = append(session.snapshotOrder, session.cumulative)
		if session.cumulative-windowBase == billingvoucher.CumulativeWindowBytes {
			appendNatClaimableSnapshot(session, session.snapshots[session.cumulative])
		}
		trimNatBillingSnapshots(session)
		delete(session.assignedBytes, session.nextAdvance)
		delete(session.pending, session.nextAdvance)
		session.nextAdvance++
	}
	return nil
}

func appendNatClaimableSnapshot(session *natBillingSession, snapshot natBillingSnapshot) {
	if billingSnapshotEmpty(snapshot) {
		return
	}
	if session.claimableCumulative == nil {
		session.claimableCumulative = make(map[uint64]struct{})
	}
	if _, exists := session.claimableCumulative[snapshot.cumulative]; exists {
		return
	}
	session.claimable = append(session.claimable, snapshot)
	session.claimableCumulative[snapshot.cumulative] = struct{}{}
}

func trimNatBillingSnapshots(session *natBillingSession) {
	attempts := 0
	for len(session.snapshots) > maximumNatBillingReconciliationSnapshots && len(session.snapshotOrder) > 0 {
		oldest := session.snapshotOrder[0]
		session.snapshotOrder = session.snapshotOrder[1:]
		snapshot, exists := session.snapshots[oldest]
		if !exists {
			continue
		}
		_, confirmedOutOfOrder := session.confirmedOutOfOrder[snapshot.lastRecordSequence]
		if snapshot.lastRecordSequence == session.confirmedSequence || confirmedOutOfOrder ||
			snapshot.lastRecordSequence == session.cosignedRecordSequence {
			session.snapshotOrder = append(session.snapshotOrder, oldest)
			attempts++
			if attempts > len(session.snapshotOrder) {
				break
			}
			continue
		}
		if _, claimable := session.claimableCumulative[oldest]; claimable {
			session.snapshotOrder = append(session.snapshotOrder, oldest)
			attempts++
			if attempts > len(session.snapshotOrder) {
				break
			}
			continue
		}
		delete(session.snapshots, oldest)
		attempts = 0
	}
	if len(session.snapshotOrder) <= 2*maximumNatBillingReconciliationSnapshots {
		return
	}
	compacted := make([]uint64, 0, len(session.snapshots))
	for _, cumulative := range session.snapshotOrder {
		if _, exists := session.snapshots[cumulative]; exists {
			compacted = append(compacted, cumulative)
		}
	}
	session.snapshotOrder = compacted
}

func (meter *natBillingMeter) cosign(bodyBytes, relaySignature []byte, relayPublicKeyHex string) (billingvoucher.MutualVoucher, error) {
	body, err := billingvoucher.ParseCanonicalBody(bodyBytes)
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	if body.PayerNatID != meter.payerID || body.Direction != billingvoucher.DirectionPayerOutbound ||
		body.AuthorizedThroughBytes != billingvoucher.MaxBillableBytes || body.PolicyDigest != billingvoucher.CurrentPolicyDigest() {
		return billingvoucher.MutualVoucher{}, errors.New("natnode: voucher channel binding or policy mismatch")
	}
	relayPublicBytes, err := hex.DecodeString(relayPublicKeyHex)
	if err != nil {
		return billingvoucher.MutualVoucher{}, errors.New("natnode: invalid Relay public key")
	}
	relayPublicKey, err := ecdh.P256().NewPublicKey(relayPublicBytes)
	if err != nil {
		return billingvoucher.MutualVoucher{}, errors.New("natnode: invalid Relay public key")
	}
	if err := billingvoucher.VerifyRelaySignature(body, relaySignature, relayPublicKey); err != nil {
		return billingvoucher.MutualVoucher{}, err
	}

	meter.mu.Lock()
	defer meter.mu.Unlock()
	defer meter.notifyPrivateSnapshotLocked()
	session := meter.sessions[body.SessionID]
	if session == nil {
		return billingvoucher.MutualVoucher{}, errors.New("natnode: voucher references an unknown billing session")
	}
	if session.relayID != body.PayeeRelayID {
		return billingvoucher.MutualVoucher{}, errors.New("natnode: billing session is bound to a different Relay")
	}
	channelKey := body.SessionID.String() + "|" + body.PayeeRelayID.String()
	channel := meter.channels[channelKey]
	if channel == nil {
		channel = &natVoucherChannel{}
		meter.channels[channelKey] = channel
	}
	if channel.has {
		lastBodyID, _ := channel.last.Body.BodyID()
		bodyID, _ := body.BodyID()
		if body.Sequence == channel.last.Body.Sequence {
			if bodyID != lastBodyID {
				return billingvoucher.MutualVoucher{}, errors.New("natnode: conflicting voucher body for an existing sequence")
			}
			return channel.last, nil
		}
		previousID, err := channel.last.ID()
		if err != nil || body.Sequence != channel.last.Body.Sequence+1 || body.PreviousMutualVoucherID != previousID {
			return billingvoucher.MutualVoucher{}, errors.New("natnode: voucher predecessor chain mismatch")
		}
	} else if body.Sequence != 1 || body.PreviousMutualVoucherID != (billingvoucher.Identifier{}) {
		return billingvoucher.MutualVoucher{}, errors.New("natnode: invalid first voucher")
	}
	snapshot, ok := session.snapshots[body.CumulativeUniqueBytes]
	if !ok || snapshot.lastRecord != body.LastRecordID || snapshot.lastRecordSequence != body.LastRecordSequence ||
		snapshot.recordSet != body.RecordSetDigest {
		return billingvoucher.MutualVoucher{}, errors.New("natnode: Relay usage does not match local E2E record evidence")
	}
	if len(session.claimable) == 0 || session.claimable[0] != snapshot {
		return billingvoucher.MutualVoucher{}, errors.New("natnode: Relay requested a voucher before the deterministic billing threshold")
	}
	payerSignature, err := billingvoucher.SignPayer(body, meter.privateKey)
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	if channel.has {
		if err := billingvoucher.ValidateSuccessor(channel.last, voucher); err != nil {
			return billingvoucher.MutualVoucher{}, err
		}
	}
	channel.last = voucher
	channel.has = true
	session.cosignedRecordSequence = body.LastRecordSequence
	delete(session.claimableCumulative, session.claimable[0].cumulative)
	session.claimable = session.claimable[1:]
	for cumulative := range session.snapshots {
		if cumulative < body.CumulativeUniqueBytes {
			delete(session.snapshots, cumulative)
		}
	}
	return voucher, nil
}

func (meter *natBillingMeter) certificate() *admission.SignedCert {
	meter.mu.Lock()
	defer meter.mu.Unlock()
	return meter.cert
}
