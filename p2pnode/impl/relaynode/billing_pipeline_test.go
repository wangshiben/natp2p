package relaynode

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingcontrol"
	"bnfs_p2p/billingqueue"
	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
)

type voucherDecisionServer struct {
	mu              sync.Mutex
	modes           map[string]string
	funded          map[string]bool
	calls           map[string]int
	payerCertExpiry map[string]int64
}

func newVoucherDecisionServer() *voucherDecisionServer {
	return &voucherDecisionServer{
		modes: make(map[string]string), funded: make(map[string]bool), calls: make(map[string]int),
		payerCertExpiry: make(map[string]int64),
	}
}

func (server *voucherDecisionServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var settlement admission.VoucherSettleRequest
	if json.NewDecoder(request.Body).Decode(&settlement) != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	voucher, err := billingvoucher.ParseCanonicalVoucher(settlement.CanonicalVoucher)
	if err != nil {
		http.Error(writer, "bad voucher", http.StatusBadRequest)
		return
	}
	voucherID, _ := voucher.ID()
	payerID := voucher.Body.PayerNatID.String()
	server.mu.Lock()
	mode := server.modes[payerID]
	funded := server.funded[payerID]
	server.calls[payerID]++
	call := server.calls[payerID]
	if settlement.PayerCert != nil {
		server.payerCertExpiry[payerID] = settlement.PayerCert.Cert.NotAfter
	}
	server.mu.Unlock()

	response := admission.VoucherSettleResponse{VoucherID: voucherID.String()}
	status := http.StatusOK
	switch mode {
	case "temporary-once":
		if call == 1 {
			response.Error = "CA transaction temporarily unavailable"
			response.ErrorCode = admission.VoucherErrorTemporarilyUnavailable
			response.Retryable = true
			status = http.StatusServiceUnavailable
		} else {
			response.Allow = true
			response.Delta = int64(voucher.Body.CumulativeUniqueBytes)
		}
	case "retryable":
		if funded {
			response.Allow = true
			response.Delta = int64(voucher.Body.CumulativeUniqueBytes)
		} else {
			response.Error = "insufficient funds"
			response.ErrorCode = admission.VoucherErrorInsufficientFunds
			response.Retryable = true
			status = http.StatusPaymentRequired
		}
	case "exact-zero":
		response.Allow = funded
		response.Replayed = call > 1
		if call == 1 {
			response.Delta = int64(voucher.Body.CumulativeUniqueBytes)
		}
	case "terminal":
		response.Error = "terminal policy rejection"
		response.Frozen = true
		status = http.StatusConflict
	case "mismatch":
		response.Allow = true
		mismatchedID := voucherID
		mismatchedID[0] ^= 0xff
		response.VoucherID = mismatchedID.String()
	default:
		response.Allow = true
		response.Delta = int64(voucher.Body.CumulativeUniqueBytes)
	}
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(response)
}

func TestSubmitPendingRetriesTemporaryCAFailureWithoutCutoff(t *testing.T) {
	decisionServer := newVoucherDecisionServer()
	httpServer := httptest.NewServer(decisionServer)
	defer httpServer.Close()
	pipeline := newSubmitTestPipeline(t, httpServer.URL)

	temporary := enqueueSubmitTestVoucher(t, pipeline, 41)
	decisionServer.modes[temporary.payerID.String()] = "temporary-once"
	pipeline.submitPending()
	if pipeline.queue.Len() != 1 {
		t.Fatalf("temporary CA failure removed durable voucher: waitSubmit=%d", pipeline.queue.Len())
	}
	if pipeline.node.accounts.isCutoff(temporary.payerID.String()) {
		t.Fatal("temporary CA failure cut off a funded payer")
	}
	if pipeline.sessionBlocked(temporary.sessionID) {
		t.Fatal("temporary CA failure permanently blocked the billing session")
	}

	pipeline.submitPending()
	if pipeline.queue.Len() != 0 {
		t.Fatal("durable voucher was not settled after CA recovery")
	}
	if decisionServer.callCount(temporary.payerID.String()) != 2 {
		t.Fatal("temporary voucher was not retried exactly once")
	}
}

func (server *voucherDecisionServer) setFunded(payerID string, funded bool) {
	server.mu.Lock()
	server.funded[payerID] = funded
	server.mu.Unlock()
}

func (server *voucherDecisionServer) callCount(payerID string) int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.calls[payerID]
}

func (server *voucherDecisionServer) submittedPayerCertExpiry(payerID string) int64 {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.payerCertExpiry[payerID]
}

func TestSubmitPendingSkipsRetryablePayerAndRecoversAfterCredit(t *testing.T) {
	decisionServer := newVoucherDecisionServer()
	httpServer := httptest.NewServer(decisionServer)
	defer httpServer.Close()
	pipeline := newSubmitTestPipeline(t, httpServer.URL)

	retryable := enqueueSubmitTestVoucher(t, pipeline, 1)
	healthy := enqueueSubmitTestVoucher(t, pipeline, 2)
	exactZero := enqueueSubmitTestVoucher(t, pipeline, 3)
	decisionServer.modes[retryable.payerID.String()] = "retryable"
	decisionServer.modes[healthy.payerID.String()] = "healthy"
	decisionServer.modes[exactZero.payerID.String()] = "exact-zero"

	pipeline.submitPending()
	if pipeline.queue.Len() != 2 {
		t.Fatalf("waitSubmit length after first pass = %d, want 2", pipeline.queue.Len())
	}
	if !pipeline.node.accounts.isCutoff(retryable.payerID.String()) {
		t.Fatal("insufficient-funds payer was not cut off")
	}
	if !pipeline.node.accounts.isCutoff(exactZero.payerID.String()) {
		t.Fatal("exact-zero payer was not cut off")
	}
	if pipeline.node.accounts.isCutoff(healthy.payerID.String()) {
		t.Fatal("healthy payer was incorrectly cut off")
	}
	if pipeline.sessionBlocked(retryable.sessionID) || pipeline.sessionBlocked(exactZero.sessionID) {
		t.Fatal("recoverable balance exhaustion permanently blocked a billing session")
	}
	if decisionServer.callCount(healthy.payerID.String()) != 1 {
		t.Fatal("retryable payer blocked an independent healthy payer")
	}

	decisionServer.setFunded(retryable.payerID.String(), true)
	decisionServer.setFunded(exactZero.payerID.String(), true)
	pipeline.submitPending()
	if pipeline.queue.Len() != 0 {
		t.Fatalf("waitSubmit length after credit = %d, want 0", pipeline.queue.Len())
	}
	if pipeline.node.accounts.isCutoff(retryable.payerID.String()) ||
		pipeline.node.accounts.isCutoff(exactZero.payerID.String()) {
		t.Fatal("credit did not clear payer cutoff after durable voucher retry")
	}
	if decisionServer.callCount(retryable.payerID.String()) != 2 ||
		decisionServer.callCount(exactZero.payerID.String()) != 2 {
		t.Fatal("durable recovery vouchers were not retried exactly once after credit")
	}
}

func TestSubmitPendingTerminalChannelBecomesDurableDeadLetterWithoutBlockingOthers(t *testing.T) {
	decisionServer := newVoucherDecisionServer()
	httpServer := httptest.NewServer(decisionServer)
	defer httpServer.Close()
	pipeline := newSubmitTestPipeline(t, httpServer.URL)

	terminal := enqueueSubmitTestVoucher(t, pipeline, 11)
	healthy := enqueueSubmitTestVoucher(t, pipeline, 12)
	decisionServer.modes[terminal.payerID.String()] = "terminal"
	decisionServer.modes[healthy.payerID.String()] = "healthy"
	pipeline.submitPending()
	if pipeline.queue.Len() != 1 {
		t.Fatalf("waitSubmit length = %d, want one durable terminal voucher", pipeline.queue.Len())
	}
	if !pipeline.sessionBlocked(terminal.sessionID) {
		t.Fatal("terminal channel was not frozen")
	}
	if decisionServer.callCount(healthy.payerID.String()) != 1 {
		t.Fatal("terminal channel blocked an independent healthy payer")
	}
	pipeline.submitPending()
	if decisionServer.callCount(terminal.payerID.String()) != 1 {
		t.Fatal("terminal dead-letter was resubmitted in a busy loop")
	}
	if pipeline.queue.Len() != 1 {
		t.Fatal("terminal evidence was removed from durable waitSubmit")
	}
}

func TestSubmitPendingSettlesDurableVoucherAfterSessionRotation(t *testing.T) {
	decisionServer := newVoucherDecisionServer()
	httpServer := httptest.NewServer(decisionServer)
	defer httpServer.Close()
	pipeline := newSubmitTestPipeline(t, httpServer.URL)

	retired := enqueueSubmitTestVoucher(t, pipeline, 14)
	pipeline.mu.Lock()
	previous := pipeline.sessions[retired.sessionID]
	pipeline.mu.Unlock()
	if _, err := pipeline.rotateSessionForPayer(retired.payerID, previous); err != nil {
		t.Fatalf("rotate voucher-covered session: %v", err)
	}
	if !pipeline.sessionBlocked(retired.sessionID) {
		t.Fatal("rotated session still accepts new records")
	}
	if pipeline.sessionSettlementBlocked(retired.sessionID) {
		t.Fatal("rotation incorrectly blocked durable settlement")
	}

	pipeline.submitPending()
	if pipeline.queue.Len() != 0 {
		t.Fatal("rotated session left its durable voucher in waitSubmit")
	}
	if decisionServer.callCount(retired.payerID.String()) != 1 {
		t.Fatal("rotated session voucher was not submitted exactly once")
	}
}

func TestSubmitPendingRotatedSessionTerminalDecisionBecomesDurableDeadLetter(t *testing.T) {
	for _, mode := range []string{"terminal", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			decisionServer := newVoucherDecisionServer()
			httpServer := httptest.NewServer(decisionServer)
			defer httpServer.Close()
			pipeline := newSubmitTestPipeline(t, httpServer.URL)

			retired := enqueueSubmitTestVoucher(t, pipeline, 15)
			pipeline.mu.Lock()
			previous := pipeline.sessions[retired.sessionID]
			pipeline.mu.Unlock()
			if _, err := pipeline.rotateSessionForPayer(retired.payerID, previous); err != nil {
				t.Fatalf("rotate voucher-covered session: %v", err)
			}
			decisionServer.modes[retired.payerID.String()] = mode

			pipeline.submitPending()
			if pipeline.queue.Len() != 1 {
				t.Fatal("terminal decision removed durable rotated-session evidence")
			}
			if !pipeline.sessionSettlementBlocked(retired.sessionID) {
				t.Fatal("terminal decision did not freeze rotated-session settlement")
			}
			previous.mu.Lock()
			blocked := previous.blocked
			previous.mu.Unlock()
			if blocked == nil || errors.Is(blocked, errBillingSessionRotated) {
				t.Fatalf("rotated marker was not promoted to terminal failure: %v", blocked)
			}

			pipeline.submitPending()
			if decisionServer.callCount(retired.payerID.String()) != 1 {
				t.Fatal("rotated-session terminal dead-letter was resubmitted")
			}
		})
	}
}

func TestSubmitPendingUsesRenewedSameKeyPayerCertificate(t *testing.T) {
	decisionServer := newVoucherDecisionServer()
	httpServer := httptest.NewServer(decisionServer)
	defer httpServer.Close()
	pipeline := newSubmitTestPipeline(t, httpServer.URL)
	enqueued := enqueueSubmitTestVoucher(t, pipeline, 13)
	queued, err := pipeline.queue.PeekEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	renewed := *queued.PayerCert
	renewed.Cert.NotAfter += int64((24 * time.Hour) / time.Second)
	pipeline.node.accounts.putCert(enqueued.payerID.String(), &renewed)
	pipeline.submitPending()
	if pipeline.queue.Len() != 0 {
		t.Fatal("voucher using renewed certificate was not settled")
	}
	if got := decisionServer.submittedPayerCertExpiry(enqueued.payerID.String()); got != renewed.Cert.NotAfter {
		t.Fatalf("submitted payer certificate expiry = %d, want renewed %d", got, renewed.Cert.NotAfter)
	}
}

func TestObserveRecordRejectsCutoffBeforeAcceptingMoreUsage(t *testing.T) {
	pipeline := newSubmitTestPipeline(t, "http://127.0.0.1:1")
	enqueued := enqueueSubmitTestVoucher(t, pipeline, 21)
	pipeline.node.accounts.setCutoff(enqueued.payerID.String(), true)
	err := pipeline.observeRecord(pipeline.node.ctx, &networkFrameWork.BillableRecord{
		NodeID: enqueued.payerID.String(), Direction: "relay_to_clients",
		SessionID: enqueued.sessionID, Sequence: 2, Bytes: 1,
		RecordID: billingvoucher.Identifier{1},
	})
	if err == nil {
		t.Fatal("cutoff payer usage was accepted")
	}
}

func TestObserveRecordDefersImmediatelyWhenBillingControlIsUnavailable(t *testing.T) {
	pipeline := newSubmitTestPipeline(t, "http://127.0.0.1:1")
	enqueued := enqueueSubmitTestVoucher(t, pipeline, 22)
	started := time.Now()
	err := pipeline.observeRecord(context.Background(), submitTestRecord(enqueued, 2, 100, 23))
	if !errors.Is(err, networkFrameWork.ErrBillableRecordRetryable) {
		t.Fatalf("missing billing control error = %v, want retryable", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("missing billing control took %v, want immediate deferral", elapsed)
	}
	session := pipeline.sessions[enqueued.sessionID]
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.nextRecordSequence != 2 || session.cumulative != billingvoucher.CumulativeWindowBytes {
		t.Fatalf("retryable control failure changed session: next=%d cumulative=%d",
			session.nextRecordSequence, session.cumulative)
	}
	if got := pipeline.node.AccountUplinkBytes(enqueued.payerID.String()); got != 0 {
		t.Fatalf("retryable control failure accounted %d bytes, want 0", got)
	}
}

func TestObserveRecordDefersOutOfOrderUntilRetransmit(t *testing.T) {
	pipeline := newSubmitTestPipeline(t, "http://127.0.0.1:1")
	enqueued := enqueueSubmitTestVoucher(t, pipeline, 31)
	pipeline.controls = map[billingvoucher.Identifier]*relayBillingControlPeer{
		enqueued.payerID: {payerID: enqueued.payerID, sessionID: enqueued.sessionID},
	}
	if err := pipeline.observeRecord(context.Background(), submitTestRecord(enqueued, 3, 100, 33)); !errors.Is(
		err, networkFrameWork.ErrBillableRecordDeferred,
	) {
		t.Fatalf("out-of-order record error = %v, want retryable deferral", err)
	}
	session := pipeline.sessions[enqueued.sessionID]
	session.mu.Lock()
	if len(session.pending) != 0 || session.pendingBytes != 0 || session.nextRecordSequence != 2 {
		t.Fatalf("deferred state = (%d records, %d bytes, next=%d)", len(session.pending), session.pendingBytes, session.nextRecordSequence)
	}
	session.mu.Unlock()
	if err := pipeline.observeRecord(context.Background(), submitTestRecord(enqueued, 2, 100, 32)); err != nil {
		t.Fatalf("fill billing sequence gap: %v", err)
	}
	if err := pipeline.observeRecord(context.Background(), submitTestRecord(enqueued, 3, 100, 33)); err != nil {
		t.Fatalf("accept retransmitted record after gap: %v", err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.pending) != 0 || session.pendingBytes != 0 || session.nextRecordSequence != 4 {
		t.Fatalf("final state = (%d records, %d bytes, next=%d)", len(session.pending), session.pendingBytes, session.nextRecordSequence)
	}
	if session.cumulative != billingvoucher.CumulativeWindowBytes+200 {
		t.Fatalf("cumulative bytes = %d, want %d", session.cumulative, billingvoucher.CumulativeWindowBytes+200)
	}
	if pipeline.node.AccountUplinkBytes(enqueued.payerID.String()) != 200 {
		t.Fatal("out-of-order records were not metered exactly once after draining")
	}
}

func TestObserveRecordDeferralDoesNotConsumeRiskWindow(t *testing.T) {
	pipeline := newSubmitTestPipeline(t, "http://127.0.0.1:1")
	enqueued := enqueueSubmitTestVoucher(t, pipeline, 41)
	pipeline.controls = map[billingvoucher.Identifier]*relayBillingControlPeer{
		enqueued.payerID: {payerID: enqueued.payerID, sessionID: enqueued.sessionID},
	}
	for _, record := range []*networkFrameWork.BillableRecord{
		submitTestRecord(enqueued, 3, billingvoucher.CumulativeWindowBytes, 43),
		submitTestRecord(enqueued, 4, billingvoucher.CumulativeWindowBytes, 44),
	} {
		if err := pipeline.observeRecord(context.Background(), record); !errors.Is(
			err, networkFrameWork.ErrBillableRecordDeferred,
		) {
			t.Fatalf("out-of-order record %d error = %v, want deferral", record.Sequence, err)
		}
	}
	if err := pipeline.observeRecord(context.Background(), submitTestRecord(
		enqueued, 2+maximumPendingRecordGap+1, 1, 46,
	)); err == nil {
		t.Fatal("pending sequence gap above the safety limit was accepted")
	}
	session := pipeline.sessions[enqueued.sessionID]
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.pending) != 0 || session.pendingBytes != 0 ||
		session.cumulative != billingvoucher.CumulativeWindowBytes || session.nextRecordSequence != 2 {
		t.Fatal("deferred records changed the signed window or pending risk state")
	}
}

func TestObserveRecordDefersWithoutChangingCurrentUnsignedWindow(t *testing.T) {
	pipeline := newSubmitTestPipeline(t, "http://127.0.0.1:1")
	enqueued := enqueueSubmitTestVoucher(t, pipeline, 51)
	pipeline.controls = map[billingvoucher.Identifier]*relayBillingControlPeer{
		enqueued.payerID: {payerID: enqueued.payerID, sessionID: enqueued.sessionID},
	}
	unsignedBytes := billingvoucher.CumulativeWindowBytes - 10
	if err := pipeline.observeRecord(context.Background(), submitTestRecord(enqueued, 2, unsignedBytes, 52)); err != nil {
		t.Fatalf("advance current unsigned window: %v", err)
	}
	if err := pipeline.observeRecord(context.Background(), submitTestRecord(
		enqueued, 4, billingvoucher.CumulativeWindowBytes, 54,
	)); !errors.Is(err, networkFrameWork.ErrBillableRecordDeferred) {
		t.Fatalf("out-of-order record error = %v, want deferral", err)
	}
	session := pipeline.sessions[enqueued.sessionID]
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.pendingBytes != 0 || len(session.pending) != 0 ||
		session.cumulative != billingvoucher.CumulativeWindowBytes+unsignedBytes ||
		session.nextRecordSequence != 3 {
		t.Fatal("deferred record changed current unsigned-window accounting")
	}
}

func TestRotateBillingSessionRejectsUncoveredState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*relayBillingSession)
	}{
		{
			name: "unsigned usage without voucher",
			mutate: func(session *relayBillingSession) {
				session.cumulative = 512
				session.lastRecord = billingvoucher.Identifier{11}
				session.lastRecordSequence = 1
				session.recordSet = billingvoucher.Digest{12}
			},
		},
		{
			name: "tail after voucher",
			mutate: func(session *relayBillingSession) {
				setRotateBillingSessionVoucher(session)
				session.cumulative++
				session.lastRecord = billingvoucher.Identifier{21}
				session.lastRecordSequence++
				session.recordSet = billingvoucher.Digest{22}
			},
		},
		{
			name: "pending-only tail",
			mutate: func(session *relayBillingSession) {
				session.pending[2] = relayBillingRecord{bytes: 256, recordID: billingvoucher.Identifier{31}}
				session.pendingBytes = 256
			},
		},
		{
			name: "blocked session",
			mutate: func(session *relayBillingSession) {
				session.blocked = errors.New("terminal billing failure")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pipeline, payerID, previous := newRotateBillingSessionTestPipeline()
			test.mutate(previous)
			rotated, err := pipeline.rotateSessionForPayer(payerID, previous)
			if err == nil {
				t.Fatal("unsafe billing session was rotated")
			}
			if rotated != nil {
				t.Fatal("unsafe rotation returned a replacement session")
			}
			if pipeline.currentByPayer[payerID] != previous || len(pipeline.sessions) != 1 {
				t.Fatal("failed rotation changed the current billing session")
			}
		})
	}
}

func TestRotateBillingSessionAllowsFullyVoucherCoveredState(t *testing.T) {
	pipeline, payerID, previous := newRotateBillingSessionTestPipeline()
	setRotateBillingSessionVoucher(previous)

	rotated, err := pipeline.rotateSessionForPayer(payerID, previous)
	if err != nil {
		t.Fatalf("rotate fully covered billing session: %v", err)
	}
	if rotated == nil || rotated == previous || rotated.sessionID == previous.sessionID {
		t.Fatal("rotation did not create a fresh billing session")
	}
	if pipeline.currentByPayer[payerID] != rotated || pipeline.sessions[rotated.sessionID] != rotated {
		t.Fatal("fresh billing session was not installed atomically")
	}
	previous.mu.Lock()
	blocked := previous.blocked
	previous.mu.Unlock()
	if !errors.Is(blocked, errBillingSessionRotated) {
		t.Fatalf("retired billing session block reason = %v", blocked)
	}
}

func TestRotationSettlementCoversUnsafeSessionBeforeRotation(t *testing.T) {
	pipeline := newSubmitTestPipeline(t, "http://127.0.0.1:1")
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payerKey.PublicKey())
	payerCertificate := submitTestCertificate(payerKey.PublicKey(), admission.RoleServer)
	pipeline.node.mu.Lock()
	pipeline.node.admission = &AdmissionConfig{Mode: AdmissionEnforce, Verifier: billingControlTestVerifier{}}
	pipeline.node.mu.Unlock()
	pipeline.node.accounts.putCert(payerID.String(), payerCertificate)
	sessionID := billingvoucher.Identifier{83, 84, 85}
	session := newRelayBillingSession(payerID, sessionID)
	snapshot := relayBillingSnapshot{
		cumulative: 512, lastRecord: billingvoucher.Identifier{86},
		lastRecordSequence: 7, recordSet: billingvoucher.Digest{87},
	}
	session.cumulative = snapshot.cumulative
	session.lastRecord = snapshot.lastRecord
	session.lastRecordSequence = snapshot.lastRecordSequence
	session.recordSet = snapshot.recordSet
	session.nextRecordSequence = snapshot.lastRecordSequence + 1
	pipeline.sessions[sessionID] = session
	pipeline.currentByPayer[payerID] = session

	voucher, err := pipeline.issueVoucherWithClaim(
		context.Background(), session, snapshot,
		func(_ context.Context, claim billingcontrol.Message) (billingcontrol.Message, error) {
			body, err := billingvoucher.ParseCanonicalBody(claim.Body)
			if err != nil {
				return billingcontrol.Message{}, err
			}
			payerSignature, err := billingvoucher.SignPayer(body, payerKey)
			if err != nil {
				return billingcontrol.Message{}, err
			}
			cosigned, err := billingvoucher.NewMutualVoucher(body, payerSignature, claim.RelaySignature)
			if err != nil {
				return billingcontrol.Message{}, err
			}
			encoded, err := cosigned.CanonicalBytes()
			if err != nil {
				return billingcontrol.Message{}, err
			}
			return billingcontrol.Message{
				Type: billingcontrol.TypeCosigned, Voucher: encoded,
				PayerPublicKey: crypoto.GetPubKeyStr(payerKey.PublicKey()), PayerCert: payerCertificate,
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("final rotation settlement: %v", err)
	}
	session.lastVoucher = voucher
	session.hasVoucher = true
	if !billingSessionSafeToRotate(session) {
		t.Fatal("final settlement did not make the old session safe to rotate")
	}
	rotated, err := pipeline.rotateSessionForPayer(payerID, session)
	if err != nil || rotated == nil || rotated == session {
		t.Fatalf("rotate settled session = (%v, %v)", rotated, err)
	}
	if pipeline.queue.Len() != 1 {
		t.Fatalf("durable settlement queue length = %d, want 1", pipeline.queue.Len())
	}
}

func TestResetRequiredRotatesBillingSessionBeforeControlInstall(t *testing.T) {
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewRelayNode(relayKey, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.cancel)
	node.mu.Lock()
	node.admission = &AdmissionConfig{Mode: AdmissionEnforce, Verifier: billingControlTestVerifier{}}
	node.mu.Unlock()
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relayKey.PublicKey())
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payerKey.PublicKey())
	payerPublicKey := crypoto.GetPubKeyStr(payerKey.PublicKey())
	node.accounts.putCert(payerID.String(), submitTestCertificate(payerKey.PublicKey(), admission.RoleServer))
	pipeline := &relayBillingPipeline{
		node: node, relayID: relayID,
		sessions:       make(map[billingvoucher.Identifier]*relayBillingSession),
		currentByPayer: make(map[billingvoucher.Identifier]*relayBillingSession),
		controls:       make(map[billingvoucher.Identifier]*relayBillingControlPeer),
	}
	stream := newBillingControlProofStream(payerKey, payerKey, payerID, relayID, "reset-required")
	firstMessage := &network.Message{
		Header: &network.Header{
			RouteName: billingcontrol.Route, NodeId: payerID.String(), NodeIdVersion: 1,
		},
		Payload: []byte(payerPublicKey),
	}
	result := make(chan error, 1)
	go func() {
		result <- pipeline.acceptControl(stream, firstMessage)
	}()
	select {
	case <-stream.waitingAfterReady:
	case err := <-result:
		t.Fatalf("reset-required control exited before install: %v", err)
	case <-time.After(time.Second):
		t.Fatal("reset-required control did not reach installed read loop")
	}

	sessionIDs := stream.negotiatedSessionIDs()
	if len(sessionIDs) != 2 || sessionIDs[0] == sessionIDs[1] {
		t.Fatalf("negotiated billing sessions = %v, want one fresh rotation", sessionIDs)
	}
	firstSessionID, err := billingvoucher.ParseIdentifierHex(sessionIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	pipeline.mu.Lock()
	retired := pipeline.sessions[firstSessionID]
	current := pipeline.currentByPayer[payerID]
	pipeline.mu.Unlock()
	if retired == nil || current == nil || current.sessionID.String() != sessionIDs[1] {
		t.Fatal("Relay did not install the rotated billing session")
	}
	retired.mu.Lock()
	blocked := retired.blocked
	retired.mu.Unlock()
	if !errors.Is(blocked, errBillingSessionRotated) {
		t.Fatalf("reset-required session was not retired: %v", blocked)
	}
	_ = stream.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("control did not exit after stream close")
	}
}

func newRotateBillingSessionTestPipeline() (
	*relayBillingPipeline,
	billingvoucher.Identifier,
	*relayBillingSession,
) {
	payerID := billingvoucher.Identifier{71}
	sessionID := billingvoucher.Identifier{72}
	session := newRelayBillingSession(payerID, sessionID)
	pipeline := &relayBillingPipeline{
		sessions:       map[billingvoucher.Identifier]*relayBillingSession{sessionID: session},
		currentByPayer: map[billingvoucher.Identifier]*relayBillingSession{payerID: session},
	}
	return pipeline, payerID, session
}

func setRotateBillingSessionVoucher(session *relayBillingSession) {
	body := billingvoucher.VoucherBody{
		SessionID: session.sessionID, PayerNatID: session.payerID,
		CumulativeUniqueBytes: billingvoucher.CumulativeWindowBytes,
		LastRecordID:          billingvoucher.Identifier{81}, LastRecordSequence: 8,
		RecordSetDigest: billingvoucher.Digest{82},
	}
	session.lastVoucher = billingvoucher.MutualVoucher{Body: body}
	session.hasVoucher = true
	session.cumulative = body.CumulativeUniqueBytes
	session.lastRecord = body.LastRecordID
	session.lastRecordSequence = body.LastRecordSequence
	session.recordSet = body.RecordSetDigest
	session.nextRecordSequence = body.LastRecordSequence + 1
}

func TestBillingControlRequiresCertificateKeyPossessionBeforeInstall(t *testing.T) {
	tests := []struct {
		name        string
		proofMode   string
		wantInstall bool
	}{
		{name: "valid proof", proofMode: "valid", wantInstall: true},
		{name: "valid proof with keepalive", proofMode: "keepalive", wantInstall: true},
		{name: "victim public key copy", proofMode: "attacker", wantInstall: false},
		{name: "old ready replay", proofMode: "old-challenge", wantInstall: false},
		{name: "wrong session", proofMode: "wrong-session", wantInstall: false},
		{name: "wrong Relay", proofMode: "wrong-relay", wantInstall: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relayKey, err := crypoto.MakeKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			payerKey, err := crypoto.MakeKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			attackerKey, err := crypoto.MakeKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			node, err := NewRelayNode(relayKey, "127.0.0.1:0", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(node.cancel)
			node.mu.Lock()
			node.admission = &AdmissionConfig{Mode: AdmissionEnforce, Verifier: billingControlTestVerifier{}}
			node.mu.Unlock()
			relayID, _ := billingvoucher.NodeIDFromPublicKey(relayKey.PublicKey())
			payerID, _ := billingvoucher.NodeIDFromPublicKey(payerKey.PublicKey())
			payerPublicKey := crypoto.GetPubKeyStr(payerKey.PublicKey())
			node.accounts.putCert(payerID.String(), submitTestCertificate(payerKey.PublicKey(), admission.RoleServer))
			pipeline := &relayBillingPipeline{
				node: node, relayID: relayID,
				sessions:       make(map[billingvoucher.Identifier]*relayBillingSession),
				currentByPayer: make(map[billingvoucher.Identifier]*relayBillingSession),
				controls:       make(map[billingvoucher.Identifier]*relayBillingControlPeer),
			}
			stream := newBillingControlProofStream(payerKey, attackerKey, payerID, relayID, test.proofMode)
			firstMessage := &network.Message{
				Header: &network.Header{
					RouteName: billingcontrol.Route, NodeId: payerID.String(), NodeIdVersion: 1,
				},
				Payload: []byte(payerPublicKey),
			}
			result := make(chan error, 1)
			go func() {
				result <- pipeline.acceptControl(stream, firstMessage)
			}()

			if test.wantInstall {
				select {
				case <-stream.waitingAfterReady:
				case err := <-result:
					t.Fatalf("valid control exited before install: %v", err)
				case <-time.After(time.Second):
					t.Fatal("valid control did not reach installed read loop")
				}
				pipeline.controlMu.Lock()
				installed := pipeline.controls[payerID]
				pipeline.controlMu.Unlock()
				if installed == nil {
					t.Fatal("valid private-key proof was not installed")
				}
				_ = stream.Close()
				select {
				case <-result:
				case <-time.After(time.Second):
					t.Fatal("control did not exit after stream close")
				}
				return
			}

			select {
			case err := <-result:
				if err == nil {
					t.Fatal("invalid possession proof returned success")
				}
			case <-time.After(time.Second):
				t.Fatal("invalid possession proof did not fail closed")
			}
			pipeline.controlMu.Lock()
			installed := pipeline.controls[payerID]
			pipeline.controlMu.Unlock()
			if installed != nil {
				t.Fatal("control was installed without a valid payer private-key proof")
			}
		})
	}
}

func TestIssueVoucherUsesIndependentBillingKeys(t *testing.T) {
	pipeline := newSubmitTestPipeline(t, "http://127.0.0.1:1")
	relayBillingKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.node.SetBillingPrivateKey(relayBillingKey); err != nil {
		t.Fatal(err)
	}
	pipeline.relayCert = submitTestBoundCertificate(
		pipeline.node.privKey.PublicKey(), relayBillingKey.PublicKey(), admission.RoleRelay,
	)

	payerIdentityKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payerBillingKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payerIdentityKey.PublicKey())
	payerCertificate := submitTestBoundCertificate(
		payerIdentityKey.PublicKey(), payerBillingKey.PublicKey(), admission.RoleServer,
	)
	pipeline.node.mu.Lock()
	pipeline.node.admission = &AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: pipeline.relayCert, Verifier: billingControlTestVerifier{},
	}
	pipeline.node.mu.Unlock()
	pipeline.node.accounts.putCert(payerID.String(), payerCertificate)

	sessionID := billingvoucher.Identifier{92, 1}
	session := newRelayBillingSession(payerID, sessionID)
	snapshot := relayBillingSnapshot{
		cumulative: 1024, lastRecord: billingvoucher.Identifier{92, 2},
		lastRecordSequence: 1, recordSet: billingvoucher.Digest{92, 3},
	}
	voucher, err := pipeline.issueVoucherWithClaim(
		context.Background(), session, snapshot,
		func(_ context.Context, claim billingcontrol.Message) (billingcontrol.Message, error) {
			body, parseErr := billingvoucher.ParseCanonicalBody(claim.Body)
			if parseErr != nil {
				return billingcontrol.Message{}, parseErr
			}
			if claim.RelayPublicKey != pipeline.node.pubKeyHex() ||
				claim.RelayBillingPublicKey != crypoto.GetPubKeyStr(relayBillingKey.PublicKey()) ||
				claim.RelayCert != pipeline.relayCert {
				t.Fatal("billing claim did not carry the separately bound Relay identity")
			}
			if verifyErr := billingvoucher.VerifyRelayBillingSignature(
				body, claim.RelaySignature, relayBillingKey.PublicKey(),
			); verifyErr != nil {
				t.Fatalf("verify independent Relay billing signature: %v", verifyErr)
			}
			if verifyErr := billingvoucher.VerifyRelaySignature(
				body, claim.RelaySignature, pipeline.node.privKey.PublicKey(),
			); verifyErr == nil {
				t.Fatal("independent Relay billing signature also verified as the node identity")
			}
			payerSignature, signErr := billingvoucher.SignPayerBilling(body, payerBillingKey)
			if signErr != nil {
				return billingcontrol.Message{}, signErr
			}
			cosigned, voucherErr := billingvoucher.NewMutualVoucher(body, payerSignature, claim.RelaySignature)
			if voucherErr != nil {
				return billingcontrol.Message{}, voucherErr
			}
			encoded, encodeErr := cosigned.CanonicalBytes()
			if encodeErr != nil {
				return billingcontrol.Message{}, encodeErr
			}
			return billingcontrol.Message{
				Type: billingcontrol.TypeCosigned, Voucher: encoded,
				PayerPublicKey:        crypoto.GetPubKeyStr(payerIdentityKey.PublicKey()),
				PayerBillingPublicKey: crypoto.GetPubKeyStr(payerBillingKey.PublicKey()),
				PayerCert:             payerCertificate,
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("issue voucher with independent billing keys: %v", err)
	}
	if err := voucher.VerifyBillingSignatures(
		payerBillingKey.PublicKey(), relayBillingKey.PublicKey(),
	); err != nil {
		t.Fatalf("verify issued billing voucher: %v", err)
	}
	envelopes, err := pipeline.queue.SnapshotEnvelopes()
	if err != nil || len(envelopes) != 1 ||
		envelopes[0].PayerBillingPublicKey != crypoto.GetPubKeyStr(payerBillingKey.PublicKey()) {
		t.Fatalf("durable independent payer identity = %+v, err=%v", envelopes, err)
	}
}

func TestInstallRecoveredVoucherPersistsBeforeAdvancingSession(t *testing.T) {
	pipeline := newSubmitTestPipeline(t, "http://127.0.0.1:1")
	relayBillingKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.node.SetBillingPrivateKey(relayBillingKey); err != nil {
		t.Fatal(err)
	}
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payerBillingKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payerKey.PublicKey())
	sessionID := billingvoucher.Identifier{93, 1}
	session := newRelayBillingSession(payerID, sessionID)
	advertised := relayBillingSnapshot{
		cumulative: billingvoucher.CumulativeWindowBytes / 2,
		lastRecord: billingvoucher.Identifier{93, 2}, lastRecordSequence: 1,
		recordSet: billingvoucher.Digest{93, 3},
	}
	session.cumulative = advertised.cumulative
	session.lastRecord = advertised.lastRecord
	session.lastRecordSequence = advertised.lastRecordSequence
	session.recordSet = advertised.recordSet
	session.nextRecordSequence = 2
	pipeline.sessions[sessionID] = session
	pipeline.currentByPayer[payerID] = session
	body := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: sessionID,
		PayerNatID: payerID, PayeeRelayID: pipeline.relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: 1,
		CumulativeUniqueBytes: billingvoucher.CumulativeWindowBytes,
		LastRecordID:          billingvoucher.Identifier{93, 4}, LastRecordSequence: 2,
		RecordSetDigest: billingvoucher.Digest{93, 5},
		PolicyDigest:    billingvoucher.CurrentPolicyDigest(), AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	payerSignature, _ := billingvoucher.SignPayerBilling(body, payerBillingKey)
	relaySignature, _ := billingvoucher.SignRelayBilling(body, relayBillingKey)
	voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		t.Fatal(err)
	}
	certificate := submitTestBoundCertificate(
		payerKey.PublicKey(), payerBillingKey.PublicKey(), admission.RoleServer,
	)
	if err := pipeline.installRecoveredVoucher(
		session, advertised, voucher, crypoto.GetPubKeyStr(payerKey.PublicKey()),
		crypoto.GetPubKeyStr(payerBillingKey.PublicKey()),
		crypoto.GetPubKeyStr(payerBillingKey.PublicKey()), certificate,
	); err != nil {
		t.Fatal(err)
	}
	if pipeline.queue.Len() != 1 || !session.hasVoucher || session.cumulative != body.CumulativeUniqueBytes ||
		session.nextRecordSequence != body.LastRecordSequence+1 {
		t.Fatal("recovered voucher was not durably installed before session advancement")
	}
	if got := pipeline.node.AccountUplinkBytes(payerID.String()); got != int64(body.CumulativeUniqueBytes-advertised.cumulative) {
		t.Fatalf("recovered usage accounting = %d", got)
	}
}

type billingControlTestVerifier struct{}

func (billingControlTestVerifier) Verify(certificate *admission.SignedCert, options admission.VerifyOptions) error {
	if certificate == nil || certificate.Cert.SubjectNodeID != options.ExpectNodeID || certificate.Cert.Role != options.ExpectRole {
		return errors.New("test certificate binding mismatch")
	}
	return nil
}

type billingControlProofStream struct {
	payerKey    *ecdh.PrivateKey
	attackerKey *ecdh.PrivateKey
	payerID     billingvoucher.Identifier
	relayID     billingvoucher.Identifier
	proofMode   string

	mu                sync.Mutex
	ready             *network.Message
	sessionIDs        []string
	waitingAfterReady chan struct{}
	release           chan struct{}
	waitingOnce       sync.Once
	closeOnce         sync.Once
	keepaliveBefore   bool
	keepaliveAfter    bool
}

func newBillingControlProofStream(
	payerKey *ecdh.PrivateKey,
	attackerKey *ecdh.PrivateKey,
	payerID billingvoucher.Identifier,
	relayID billingvoucher.Identifier,
	proofMode string,
) *billingControlProofStream {
	return &billingControlProofStream{
		payerKey: payerKey, attackerKey: attackerKey, payerID: payerID, relayID: relayID, proofMode: proofMode,
		waitingAfterReady: make(chan struct{}), release: make(chan struct{}),
	}
}

func (stream *billingControlProofStream) Close() error {
	stream.closeOnce.Do(func() { close(stream.release) })
	return nil
}

func (stream *billingControlProofStream) NextMessage(ctx context.Context) (*network.Message, error) {
	stream.mu.Lock()
	ready := stream.ready
	if ready != nil && stream.proofMode == "keepalive" && !stream.keepaliveBefore {
		stream.keepaliveBefore = true
		stream.mu.Unlock()
		return &network.Message{Header: &network.Header{RouteName: networkFrameWork.KeepAliveRoute}}, nil
	}
	if ready != nil {
		stream.ready = nil
	}
	if ready == nil && stream.proofMode == "keepalive" && !stream.keepaliveAfter {
		stream.keepaliveAfter = true
		stream.mu.Unlock()
		return &network.Message{Header: &network.Header{RouteName: networkFrameWork.KeepAliveRoute}}, nil
	}
	stream.mu.Unlock()
	if ready != nil {
		return ready, nil
	}
	stream.waitingOnce.Do(func() { close(stream.waitingAfterReady) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-stream.release:
		return nil, errors.New("billing control test stream closed")
	}
}

func (stream *billingControlProofStream) SendMessage(_ context.Context, message *network.Message) error {
	if message == nil {
		return errors.New("missing billing control message")
	}
	var session billingcontrol.Message
	if err := json.Unmarshal(message.Payload, &session); err != nil || session.Type != billingcontrol.TypeSession {
		return errors.New("invalid billing control session challenge")
	}
	stream.mu.Lock()
	stream.sessionIDs = append(stream.sessionIDs, session.SessionID)
	sessionAttempt := len(stream.sessionIDs)
	stream.mu.Unlock()
	binding := billingcontrol.ProofBinding{
		Challenge: session.Challenge, SessionID: session.SessionID,
		PayerID: stream.payerID.String(), RelayID: stream.relayID.String(),
	}
	signingKey := stream.payerKey
	switch stream.proofMode {
	case "attacker":
		attackerID, _ := billingvoucher.NodeIDFromPublicKey(stream.attackerKey.PublicKey())
		binding.PayerID = attackerID.String()
		signingKey = stream.attackerKey
	case "old-challenge":
		binding.Challenge = bytes.Clone(binding.Challenge)
		binding.Challenge[0] ^= 1
	case "wrong-session":
		binding.SessionID = (billingvoucher.Identifier{91}).String()
	case "wrong-relay":
		binding.RelayID = (billingvoucher.Identifier{92}).String()
	}
	resetRequired := stream.proofMode == "reset-required" && sessionAttempt == 1
	readyBinding := billingcontrol.ReadyStateProofBinding{
		RelayStateProofBinding: billingcontrol.RelayStateProofBinding{
			ProofBinding: binding, CumulativeBytes: session.CumulativeBytes,
			LastRecordID: session.LastRecordID, LastRecordSequence: session.LastRecordSequence,
			RecordSetDigest: session.RecordSetDigest,
		},
		SessionResetRequired: resetRequired,
	}
	proof, err := billingcontrol.SignReadyStateProof(signingKey, readyBinding)
	if err != nil {
		return err
	}
	ready := billingcontrol.Message{
		Type: billingcontrol.TypeReady, SessionID: session.SessionID,
		Challenge: bytes.Clone(session.Challenge), PayerProof: proof,
		SessionResetRequired: resetRequired,
	}
	payload, err := json.Marshal(ready)
	if err != nil {
		return err
	}
	stream.mu.Lock()
	stream.ready = &network.Message{Payload: payload}
	stream.mu.Unlock()
	return nil
}

func (stream *billingControlProofStream) negotiatedSessionIDs() []string {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return append([]string(nil), stream.sessionIDs...)
}

func (stream *billingControlProofStream) SendMessageAsync(
	ctx context.Context,
	message *network.Message,
	_ network.MessageResultCallback,
) error {
	return stream.SendMessage(ctx, message)
}

func (*billingControlProofStream) NodeId() string                     { return "billing-control-test" }
func (*billingControlProofStream) ConnectionId() string               { return "billing-control-proof" }
func (*billingControlProofStream) SetCryptoSuite(network.EncrypSuite) {}

type submitTestVoucher struct {
	payerID   billingvoucher.Identifier
	sessionID billingvoucher.Identifier
}

func submitTestRecord(
	enqueued submitTestVoucher,
	sequence uint64,
	bytes uint64,
	recordSeed byte,
) *networkFrameWork.BillableRecord {
	return &networkFrameWork.BillableRecord{
		NodeID: enqueued.payerID.String(), Direction: "relay_to_clients",
		SessionID: enqueued.sessionID, Sequence: sequence, Bytes: bytes,
		RecordID: billingvoucher.Identifier{recordSeed, 1},
	}
}

func newSubmitTestPipeline(t *testing.T, caURL string) *relayBillingPipeline {
	t.Helper()
	relayKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewRelayNode(relayKey, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.cancel)
	queue, err := billingqueue.Open(filepath.Join(t.TempDir(), "wait-submit.queue"), billingqueue.Limits{
		MaxItems: 64, MaxBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close() })
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relayKey.PublicKey())
	return &relayBillingPipeline{
		node: node, relayID: relayID, queue: queue,
		settler: admission.NewCAClient(caURL), relayCert: submitTestCertificate(relayKey.PublicKey(), admission.RoleRelay),
		sessions:       make(map[billingvoucher.Identifier]*relayBillingSession),
		currentByPayer: make(map[billingvoucher.Identifier]*relayBillingSession),
	}
}

func enqueueSubmitTestVoucher(t *testing.T, pipeline *relayBillingPipeline, seed byte) submitTestVoucher {
	t.Helper()
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payerKey.PublicKey())
	sessionID := billingvoucher.Identifier{seed, 1}
	body := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: sessionID,
		PayerNatID: payerID, PayeeRelayID: pipeline.relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: 1,
		CumulativeUniqueBytes: billingvoucher.CumulativeWindowBytes,
		LastRecordID:          billingvoucher.Identifier{seed, 2}, LastRecordSequence: 1,
		RecordSetDigest:        billingvoucher.Digest{seed, 3},
		PolicyDigest:           billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	payerSignature, _ := billingvoucher.SignPayer(body, payerKey)
	relaySignature, _ := billingvoucher.SignRelay(body, pipeline.node.privKey)
	voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.queue.EnqueueEnvelope(billingqueue.Envelope{
		Voucher: voucher, PayerPublicKey: crypoto.GetPubKeyStr(payerKey.PublicKey()),
		PayerCert: submitTestCertificate(payerKey.PublicKey(), admission.RoleServer),
	}); err != nil {
		t.Fatal(err)
	}
	session := newRelayBillingSession(payerID, sessionID)
	restoreSessionVoucher(session, voucher)
	pipeline.sessions[sessionID] = session
	pipeline.currentByPayer[payerID] = session
	pipeline.node.accounts.putRole(payerID.String(), admission.RoleServer)
	return submitTestVoucher{payerID: payerID, sessionID: sessionID}
}

func submitTestCertificate(publicKey *ecdh.PublicKey, role admission.Role) *admission.SignedCert {
	publicKeyHex := crypoto.GetPubKeyStr(publicKey)
	return &admission.SignedCert{Cert: admission.Cert{
		SubjectNodeID: admission.NodeIDFromPubKeyHex(publicKeyHex), SubjectPubKey: publicKeyHex,
		Role: role, NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix(),
		Nonce: "01", Issuer: "submit-test",
	}, Sig: "00"}
}

func submitTestBoundCertificate(
	identityPublicKey *ecdh.PublicKey,
	billingPublicKey *ecdh.PublicKey,
	role admission.Role,
) *admission.SignedCert {
	identityPublicKeyHex := crypoto.GetPubKeyStr(identityPublicKey)
	billingPublicKeyHex := crypoto.GetPubKeyStr(billingPublicKey)
	billingKeyID, _ := admission.BillingKeyIDFromPublicKeyHex(billingPublicKeyHex)
	nodeID := admission.NodeIDFromPubKeyHex(identityPublicKeyHex)
	return &admission.SignedCert{Cert: admission.Cert{
		SubjectNodeID: nodeID, SubjectPubKey: identityPublicKeyHex,
		Role: role, NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix(),
		Nonce: "01", Issuer: "submit-test",
		AuthorizationID: admission.NodeAuthorizationID(nodeID, billingKeyID),
		BillingKeyID:    billingKeyID, BillingPubKey: billingPublicKeyHex,
	}, Sig: "00"}
}
