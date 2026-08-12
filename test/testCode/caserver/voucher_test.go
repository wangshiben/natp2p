package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingvoucher"
)

type voucherTestIdentity struct {
	privateKey *ecdh.PrivateKey
	publicHex  string
	cert       *admission.SignedCert
}

type voucherTestFixture struct {
	testing      *testing.T
	caPrivateKey *ecdsa.PrivateKey
	payer        voucherTestIdentity
	relay        voucherTestIdentity
	sessionID    billingvoucher.Identifier
	ledger       *ledger
	handler      http.Handler
}

func TestVoucherSettlementIdempotentAcrossResponseLossAndRestart(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
	fixture := newVoucherTestFixture(t, ledgerPath)
	const initialBalance = int64(8 * billingvoucher.CumulativeWindowBytes)
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, initialBalance); err != nil {
		t.Fatalf("credit payer: %v", err)
	}

	firstVoucher := fixture.voucher(1, billingvoucher.CumulativeWindowBytes, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, fixture.relay)
	firstRequest := fixture.request(firstVoucher, fixture.payer, fixture.relay)
	server := httptest.NewServer(fixture.handler)
	client := admission.NewCAClient(server.URL)

	firstResponse, err := client.SettleVoucher(context.Background(), firstRequest)
	if err != nil {
		server.Close()
		t.Fatalf("settle first voucher: %v", err)
	}
	relayTotal, caTotal, err := billingvoucher.CurrentPolicyCumulativeTotals(billingvoucher.CumulativeWindowBytes)
	if err != nil {
		server.Close()
		t.Fatalf("policy totals: %v", err)
	}
	if firstResponse.Delta != int64(billingvoucher.CumulativeWindowBytes) || firstResponse.RelayCredit != int64(relayTotal) ||
		firstResponse.Balance != initialBalance-int64(billingvoucher.CumulativeWindowBytes) || !firstResponse.Allow {
		server.Close()
		t.Fatalf("unexpected first decision: %+v", firstResponse)
	}

	replayedResponse, err := client.SettleVoucher(context.Background(), firstRequest)
	if err != nil {
		server.Close()
		t.Fatalf("retry after response loss: %v", err)
	}
	if !replayedResponse.Replayed || replayedResponse.Stale || replayedResponse.Delta != 0 || replayedResponse.RelayCredit != 0 {
		server.Close()
		t.Fatalf("retry was not idempotent: %+v", replayedResponse)
	}
	server.Close()

	firstID, err := firstVoucher.ID()
	if err != nil {
		t.Fatalf("first voucher ID: %v", err)
	}
	secondVoucher := fixture.voucher(2, 2*billingvoucher.CumulativeWindowBytes, firstID, fixture.sessionID, fixture.payer, fixture.relay)
	secondResponse, status := postVoucher(t, fixture.handler, fixture.request(secondVoucher, fixture.payer, fixture.relay))
	if status != http.StatusOK || secondResponse.Delta != int64(billingvoucher.CumulativeWindowBytes) {
		t.Fatalf("second voucher rejected: status=%d response=%+v", status, secondResponse)
	}
	oldResponse, status := postVoucher(t, fixture.handler, firstRequest)
	if status != http.StatusOK || !oldResponse.Replayed || !oldResponse.Stale || oldResponse.Delta != 0 || oldResponse.RelayCredit != 0 {
		t.Fatalf("old watermark was not a zero-delta stale replay: status=%d response=%+v", status, oldResponse)
	}

	reloaded := newLedger(ledgerPath)
	if reloaded.loadErr != nil {
		t.Fatalf("reload ledger: %v", reloaded.loadErr)
	}
	pubPEM, err := admission.MarshalCAPublicKeyPEM(&fixture.ca().PublicKey)
	if err != nil {
		t.Fatalf("marshal CA public key: %v", err)
	}
	reloadedHandler := newCAHandler(fixture.ca(), pubPEM, "test-ca", 3600, reloaded)
	restartResponse, status := postVoucher(t, reloadedHandler, fixture.request(secondVoucher, fixture.payer, fixture.relay))
	if status != http.StatusOK || !restartResponse.Replayed || restartResponse.Delta != 0 || restartResponse.RelayCredit != 0 {
		t.Fatalf("restart replay was not idempotent: status=%d response=%+v", status, restartResponse)
	}
	secondRelayTotal, secondCATotal, err := billingvoucher.CurrentPolicyCumulativeTotals(2 * billingvoucher.CumulativeWindowBytes)
	if err != nil {
		t.Fatalf("second policy totals: %v", err)
	}
	if reloaded.balance(fixture.payer.cert.Cert.SubjectNodeID) != initialBalance-int64(2*billingvoucher.CumulativeWindowBytes) ||
		reloaded.balance(fixture.relay.cert.Cert.SubjectNodeID) != int64(secondRelayTotal) ||
		reloaded.relayIncomeTotal(fixture.relay.cert.Cert.SubjectNodeID) != int64(secondRelayTotal) ||
		reloaded.caRevenueTotal() != int64(secondCATotal) || caTotal == 0 {
		t.Fatalf("reloaded accounting mismatch: payer=%d relay=%d income=%d ca=%d",
			reloaded.balance(fixture.payer.cert.Cert.SubjectNodeID), reloaded.balance(fixture.relay.cert.Cert.SubjectNodeID),
			reloaded.relayIncomeTotal(fixture.relay.cert.Cert.SubjectNodeID), reloaded.caRevenueTotal())
	}
}

func TestVoucherSettlementConcurrentReplayDebitsOnce(t *testing.T) {
	fixture := newVoucherTestFixture(t, "")
	const initialBalance = int64(8 << 20)
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, initialBalance); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	voucher := fixture.voucher(1, billingvoucher.CumulativeWindowBytes, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, fixture.relay)
	request := fixture.request(voucher, fixture.payer, fixture.relay)
	server := httptest.NewServer(fixture.handler)
	defer server.Close()
	client := admission.NewCAClient(server.URL)

	const submitters = 24
	responses := make(chan *admission.VoucherSettleResponse, submitters)
	errorsFound := make(chan error, submitters)
	var waitGroup sync.WaitGroup
	for submitter := 0; submitter < submitters; submitter++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			response, err := client.SettleVoucher(context.Background(), request)
			if err != nil {
				errorsFound <- err
				return
			}
			responses <- response
		}()
	}
	waitGroup.Wait()
	close(responses)
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent settlement: %v", err)
	}
	newDebits := 0
	replays := 0
	for response := range responses {
		if response.Delta == int64(billingvoucher.CumulativeWindowBytes) && !response.Replayed {
			newDebits++
		}
		if response.Delta == 0 && response.Replayed {
			replays++
		}
	}
	if newDebits != 1 || replays != submitters-1 {
		t.Fatalf("concurrent idempotency mismatch: debits=%d replays=%d", newDebits, replays)
	}
	if fixture.ledger.balance(fixture.payer.cert.Cert.SubjectNodeID) != initialBalance-int64(billingvoucher.CumulativeWindowBytes) {
		t.Fatal("concurrent replay caused an extra payer debit")
	}
}

func TestVoucherSettlementInsufficientFundsIsAtomicAndRetryable(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
	fixture := newVoucherTestFixture(t, ledgerPath)
	const initialBalance = int64(billingvoucher.CumulativeWindowBytes - 1)
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, initialBalance); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	before, err := os.ReadFile(ledgerWALPath(ledgerPath))
	if err != nil {
		t.Fatalf("read ledger WAL before rejection: %v", err)
	}
	voucher := fixture.voucher(1, billingvoucher.CumulativeWindowBytes, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, fixture.relay)
	request := fixture.request(voucher, fixture.payer, fixture.relay)
	server := httptest.NewServer(fixture.handler)
	client := admission.NewCAClient(server.URL)

	const submitters = 16
	responses := make(chan *admission.VoucherSettleResponse, submitters)
	errorsFound := make(chan error, submitters)
	var waitGroup sync.WaitGroup
	for submitter := 0; submitter < submitters; submitter++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			response, settleErr := client.SettleVoucher(context.Background(), request)
			responses <- response
			errorsFound <- settleErr
		}()
	}
	waitGroup.Wait()
	close(responses)
	close(errorsFound)
	for response := range responses {
		if response == nil || response.Allow || response.ErrorCode != admission.VoucherErrorInsufficientFunds ||
			!response.Retryable || response.Delta != 0 || response.RelayCredit != 0 || response.Balance != initialBalance {
			t.Errorf("unexpected insufficient-funds response: %+v", response)
		}
	}
	for settleErr := range errorsFound {
		if settleErr == nil {
			t.Error("insufficient-funds settlement did not return an error")
		}
	}
	server.Close()

	after, err := os.ReadFile(ledgerWALPath(ledgerPath))
	if err != nil {
		t.Fatalf("read ledger WAL after rejection: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("retryable insufficient-funds rejection changed the durable ledger")
	}
	assertVoucherLedgerUnchanged(t, fixture.ledger, fixture, initialBalance)

	reloaded := newLedger(ledgerPath)
	if reloaded.loadErr != nil {
		t.Fatalf("reload ledger after rejection: %v", reloaded.loadErr)
	}
	reloadedHandler := newCAHandler(fixture.ca(), "", "test-ca", 3600, reloaded)
	retryResponse, status := postVoucher(t, reloadedHandler, request)
	if status != http.StatusPaymentRequired || retryResponse.ErrorCode != admission.VoucherErrorInsufficientFunds || !retryResponse.Retryable {
		t.Fatalf("restart did not preserve retryable rejection: status=%d response=%+v", status, retryResponse)
	}
	assertVoucherLedgerUnchanged(t, reloaded, fixture, initialBalance)

	if _, err := reloaded.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, 1); err != nil {
		t.Fatalf("credit payer for retry: %v", err)
	}
	server = httptest.NewServer(reloadedHandler)
	defer server.Close()
	client = admission.NewCAClient(server.URL)
	responses = make(chan *admission.VoucherSettleResponse, submitters)
	errorsFound = make(chan error, submitters)
	for submitter := 0; submitter < submitters; submitter++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			response, settleErr := client.SettleVoucher(context.Background(), request)
			if settleErr != nil {
				errorsFound <- settleErr
				return
			}
			responses <- response
		}()
	}
	waitGroup.Wait()
	close(responses)
	close(errorsFound)
	for settleErr := range errorsFound {
		t.Errorf("settlement after recharge: %v", settleErr)
	}
	newSettlements := 0
	replays := 0
	for response := range responses {
		if response == nil || response.Allow || response.Balance != 0 || response.ErrorCode != "" || response.Retryable {
			t.Errorf("unexpected post-recharge response: %+v", response)
			continue
		}
		if response.Delta == int64(billingvoucher.CumulativeWindowBytes) && !response.Replayed {
			newSettlements++
		}
		if response.Delta == 0 && response.Replayed {
			replays++
		}
	}
	if newSettlements != 1 || replays != submitters-1 {
		t.Fatalf("post-recharge idempotency mismatch: settlements=%d replays=%d", newSettlements, replays)
	}
	relayTotal, caTotal, err := billingvoucher.CurrentPolicyCumulativeTotals(billingvoucher.CumulativeWindowBytes)
	if err != nil {
		t.Fatalf("policy totals: %v", err)
	}
	if reloaded.balance(fixture.payer.cert.Cert.SubjectNodeID) != 0 ||
		reloaded.balance(fixture.relay.cert.Cert.SubjectNodeID) != int64(relayTotal) ||
		reloaded.relayIncomeTotal(fixture.relay.cert.Cert.SubjectNodeID) != int64(relayTotal) ||
		reloaded.caRevenueTotal() != int64(caTotal) || len(reloaded.channels) != 1 ||
		len(reloaded.decisions) != 1 || len(reloaded.evidence) != 1 {
		t.Fatalf("post-recharge accounting mismatch: payer=%d relay=%d income=%d ca=%d channels=%d decisions=%d evidence=%d",
			reloaded.balance(fixture.payer.cert.Cert.SubjectNodeID), reloaded.balance(fixture.relay.cert.Cert.SubjectNodeID),
			reloaded.relayIncomeTotal(fixture.relay.cert.Cert.SubjectNodeID), reloaded.caRevenueTotal(),
			len(reloaded.channels), len(reloaded.decisions), len(reloaded.evidence))
	}
	if _, err := reloaded.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, 1); err != nil {
		t.Fatalf("credit exact-zero payer for recovery: %v", err)
	}
	recoveryResponse, status := postVoucher(t, reloadedHandler, request)
	if status != http.StatusOK || !recoveryResponse.Allow || !recoveryResponse.Replayed || recoveryResponse.Stale ||
		recoveryResponse.Delta != 0 || recoveryResponse.RelayCredit != 0 || recoveryResponse.Balance != 1 {
		t.Fatalf("exact-zero voucher did not become a zero-delta recovery token: status=%d response=%+v", status, recoveryResponse)
	}
	if reloaded.balance(fixture.relay.cert.Cert.SubjectNodeID) != int64(relayTotal) ||
		reloaded.relayIncomeTotal(fixture.relay.cert.Cert.SubjectNodeID) != int64(relayTotal) ||
		reloaded.caRevenueTotal() != int64(caTotal) {
		t.Fatal("recovery replay changed Relay or CA accounting")
	}
}

func assertVoucherLedgerUnchanged(t *testing.T, ledger *ledger, fixture *voucherTestFixture, payerBalance int64) {
	t.Helper()
	if ledger.balance(fixture.payer.cert.Cert.SubjectNodeID) != payerBalance ||
		ledger.balance(fixture.relay.cert.Cert.SubjectNodeID) != 0 ||
		ledger.relayIncomeTotal(fixture.relay.cert.Cert.SubjectNodeID) != 0 || ledger.caRevenueTotal() != 0 ||
		len(ledger.channels) != 0 || len(ledger.sessionBindings) != 0 || len(ledger.acceptedSequences) != 0 ||
		len(ledger.decisions) != 0 || len(ledger.evidence) != 0 || len(ledger.decisionOrder) != 0 {
		t.Fatalf("retryable rejection mutated ledger: payer=%d relay=%d income=%d ca=%d channels=%d bindings=%d sequences=%d decisions=%d evidence=%d",
			ledger.balance(fixture.payer.cert.Cert.SubjectNodeID), ledger.balance(fixture.relay.cert.Cert.SubjectNodeID),
			ledger.relayIncomeTotal(fixture.relay.cert.Cert.SubjectNodeID), ledger.caRevenueTotal(), len(ledger.channels),
			len(ledger.sessionBindings), len(ledger.acceptedSequences), len(ledger.decisions), len(ledger.evidence))
	}
}

func TestVoucherSettlementRejectsTamperingAndStrictJSON(t *testing.T) {
	fixture := newVoucherTestFixture(t, "")
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, 4<<20); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	validVoucher := fixture.voucher(1, 512<<10, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, fixture.relay)
	validRequest := fixture.request(validVoucher, fixture.payer, fixture.relay)
	payerBefore := fixture.ledger.balance(fixture.payer.cert.Cert.SubjectNodeID)

	t.Run("signed body tampering", func(t *testing.T) {
		tampered := validVoucher
		tampered.Body.CumulativeUniqueBytes++
		encoded, err := tampered.CanonicalBytes()
		if err != nil {
			t.Fatalf("encode tampered voucher: %v", err)
		}
		request := validRequest
		request.CanonicalVoucher = encoded
		response, status := postVoucher(t, fixture.handler, request)
		if status != http.StatusBadRequest || response.Error == "" {
			t.Fatalf("tampered voucher accepted: status=%d response=%+v", status, response)
		}
	})

	t.Run("wrong certificate role", func(t *testing.T) {
		wrongRoleCert := issueTestCertificate(t, fixture.ca(), fixture.payer.publicHex, admission.RoleClient)
		request := validRequest
		request.PayerCert = wrongRoleCert
		response, status := postVoucher(t, fixture.handler, request)
		if status != http.StatusBadRequest || response.Error == "" {
			t.Fatalf("wrong role certificate accepted: status=%d response=%+v", status, response)
		}
	})

	t.Run("wrong policy", func(t *testing.T) {
		body := validVoucher.Body
		body.PolicyDigest[0] ^= 1
		wrongPolicyVoucher := signVoucher(t, body, fixture.payer.privateKey, fixture.relay.privateKey)
		response, status := postVoucher(t, fixture.handler, fixture.request(wrongPolicyVoucher, fixture.payer, fixture.relay))
		if status != http.StatusBadRequest || response.Error == "" {
			t.Fatalf("wrong policy accepted: status=%d response=%+v", status, response)
		}
	})

	t.Run("unsupported direction", func(t *testing.T) {
		body := validVoucher.Body
		body.Direction = billingvoucher.DirectionPayerInbound
		unsupported := signVoucher(t, body, fixture.payer.privateKey, fixture.relay.privateKey)
		response, status := postVoucher(t, fixture.handler, fixture.request(unsupported, fixture.payer, fixture.relay))
		if status != http.StatusBadRequest || !strings.Contains(response.Error, "direction") {
			t.Fatalf("unsupported direction accepted: status=%d response=%+v", status, response)
		}
	})

	t.Run("unsupported authorization", func(t *testing.T) {
		body := validVoucher.Body
		body.AuthorizedThroughBytes = billingvoucher.MaxBillableBytes - 1
		unsupported := signVoucher(t, body, fixture.payer.privateKey, fixture.relay.privateKey)
		response, status := postVoucher(t, fixture.handler, fixture.request(unsupported, fixture.payer, fixture.relay))
		if status != http.StatusBadRequest || !strings.Contains(response.Error, "authorized_through_bytes") {
			t.Fatalf("unsupported authorization accepted: status=%d response=%+v", status, response)
		}
	})

	encodedRequest, err := json.Marshal(validRequest)
	if err != nil {
		t.Fatalf("marshal valid request: %v", err)
	}
	t.Run("unknown JSON field", func(t *testing.T) {
		body := append(bytes.TrimSuffix(encodedRequest, []byte("}")), []byte(",\"unexpected\":true}")...)
		response, status := postRawVoucher(t, fixture.handler, body)
		if status != http.StatusBadRequest || response.Error == "" {
			t.Fatalf("unknown JSON field accepted: status=%d response=%+v", status, response)
		}
	})
	t.Run("trailing JSON", func(t *testing.T) {
		body := append(bytes.Clone(encodedRequest), []byte(" {}")...)
		response, status := postRawVoucher(t, fixture.handler, body)
		if status != http.StatusBadRequest || response.Error == "" {
			t.Fatalf("trailing JSON accepted: status=%d response=%+v", status, response)
		}
	})
	if fixture.ledger.balance(fixture.payer.cert.Cert.SubjectNodeID) != payerBefore ||
		fixture.ledger.balance(fixture.relay.cert.Cert.SubjectNodeID) != 0 || fixture.ledger.caRevenueTotal() != 0 {
		t.Fatal("rejected tampering changed accounting")
	}
}

func TestVoucherSettlementEnforcesChainAndFreezesFork(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
	fixture := newVoucherTestFixture(t, ledgerPath)
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, 8<<20); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	firstVoucher := fixture.voucher(1, 512<<10, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, fixture.relay)
	firstResponse, status := postVoucher(t, fixture.handler, fixture.request(firstVoucher, fixture.payer, fixture.relay))
	if status != http.StatusOK {
		t.Fatalf("first voucher: status=%d response=%+v", status, firstResponse)
	}
	firstID, err := firstVoucher.ID()
	if err != nil {
		t.Fatalf("first ID: %v", err)
	}

	gapVoucher := fixture.voucher(3, 1536<<10, firstID, fixture.sessionID, fixture.payer, fixture.relay)
	gapResponse, status := postVoucher(t, fixture.handler, fixture.request(gapVoucher, fixture.payer, fixture.relay))
	if status != http.StatusConflict || gapResponse.Frozen {
		t.Fatalf("sequence gap disposition: status=%d response=%+v", status, gapResponse)
	}
	wrongPrevious := testIdentifier("wrong-previous")
	wrongChainVoucher := fixture.voucher(2, 1024<<10, wrongPrevious, fixture.sessionID, fixture.payer, fixture.relay)
	wrongResponse, status := postVoucher(t, fixture.handler, fixture.request(wrongChainVoucher, fixture.payer, fixture.relay))
	if status != http.StatusConflict || wrongResponse.Frozen {
		t.Fatalf("wrong predecessor disposition: status=%d response=%+v", status, wrongResponse)
	}

	secondVoucher := fixture.voucher(2, 1024<<10, firstID, fixture.sessionID, fixture.payer, fixture.relay)
	secondResponse, status := postVoucher(t, fixture.handler, fixture.request(secondVoucher, fixture.payer, fixture.relay))
	if status != http.StatusOK {
		t.Fatalf("valid successor rejected after out-of-order attempts: status=%d response=%+v", status, secondResponse)
	}
	balanceBeforeFork := fixture.ledger.balance(fixture.payer.cert.Cert.SubjectNodeID)
	relayBeforeFork := fixture.ledger.balance(fixture.relay.cert.Cert.SubjectNodeID)
	conflictingSecond := fixture.voucher(2, 768<<10, firstID, fixture.sessionID, fixture.payer, fixture.relay)
	forkResponse, status := postVoucher(t, fixture.handler, fixture.request(conflictingSecond, fixture.payer, fixture.relay))
	if status != http.StatusConflict || !forkResponse.Frozen || forkResponse.Delta != 0 {
		t.Fatalf("same-sequence fork did not freeze: status=%d response=%+v", status, forkResponse)
	}
	secondID, err := secondVoucher.ID()
	if err != nil {
		t.Fatalf("second ID: %v", err)
	}
	thirdVoucher := fixture.voucher(3, 1536<<10, secondID, fixture.sessionID, fixture.payer, fixture.relay)
	frozenResponse, status := postVoucher(t, fixture.handler, fixture.request(thirdVoucher, fixture.payer, fixture.relay))
	if status != http.StatusConflict || !frozenResponse.Frozen {
		t.Fatalf("frozen channel accepted successor: status=%d response=%+v", status, frozenResponse)
	}
	if fixture.ledger.balance(fixture.payer.cert.Cert.SubjectNodeID) != balanceBeforeFork ||
		fixture.ledger.balance(fixture.relay.cert.Cert.SubjectNodeID) != relayBeforeFork {
		t.Fatal("fork or frozen successor changed balances")
	}

	reloaded := newLedger(ledgerPath)
	if reloaded.loadErr != nil {
		t.Fatalf("reload frozen ledger: %v", reloaded.loadErr)
	}
	channel := reloaded.channels[voucherChannelKey(firstVoucher.Body)]
	if !channel.Frozen {
		t.Fatal("frozen state did not survive restart")
	}

	newSession := testIdentifier("independent-session")
	independentVoucher := fixture.voucher(1, 256<<10, billingvoucher.Identifier{}, newSession, fixture.payer, fixture.relay)
	independentResponse, status := postVoucher(t, fixture.handler, fixture.request(independentVoucher, fixture.payer, fixture.relay))
	if status != http.StatusOK || independentResponse.Frozen {
		t.Fatalf("independent session was not isolated: status=%d response=%+v", status, independentResponse)
	}
}

func TestVoucherLedgerBoundsHistoryAndAcceptsEvictedReplayAfterRestart(t *testing.T) {
	fixture := newVoucherTestFixture(t, "")
	const voucherCount = 10_000
	initialBalance := int64(voucherCount)*int64(billingvoucher.CumulativeWindowBytes) + 1
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, initialBalance); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	started := time.Now()
	var previousID billingvoucher.Identifier
	var oldestRequest admission.VoucherSettleRequest
	var settlementChannelKey string
	for sequence := uint64(1); sequence <= voucherCount; sequence++ {
		voucher := fixture.voucher(
			sequence,
			sequence*billingvoucher.CumulativeWindowBytes,
			previousID,
			fixture.sessionID,
			fixture.payer,
			fixture.relay,
		)
		voucherID, err := voucher.ID()
		if err != nil {
			t.Fatalf("voucher %d ID: %v", sequence, err)
		}
		request := fixture.request(voucher, fixture.payer, fixture.relay)
		if sequence == 1 {
			oldestRequest = request
			settlementChannelKey = voucherChannelKey(voucher.Body)
		}
		response, status := fixture.ledger.settleVoucher(validatedVoucher{request: request, voucher: voucher, id: voucherID})
		if status != http.StatusOK || !response.Allow || response.Delta != int64(billingvoucher.CumulativeWindowBytes) {
			t.Fatalf("voucher %d settlement failed: status=%d response=%+v", sequence, status, response)
		}
		previousID = voucherID
	}
	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Fatalf("bounded in-memory settlement of %d vouchers took %s", voucherCount, elapsed)
	}
	if len(fixture.ledger.channels) != 1 || len(fixture.ledger.sessionBindings) != 1 ||
		len(fixture.ledger.acceptedSequences) != 1 || len(fixture.ledger.decisions) != recentVoucherDecisionCacheSize ||
		len(fixture.ledger.evidence) != recentVoucherDecisionCacheSize || len(fixture.ledger.decisionOrder) != recentVoucherDecisionCacheSize {
		t.Fatalf("ledger history is not bounded: channels=%d bindings=%d accepted=%d decisions=%d evidence=%d order=%d",
			len(fixture.ledger.channels), len(fixture.ledger.sessionBindings), len(fixture.ledger.acceptedSequences),
			len(fixture.ledger.decisions), len(fixture.ledger.evidence), len(fixture.ledger.decisionOrder))
	}

	ledgerPath := filepath.Join(t.TempDir(), "bounded-ledger.json")
	fixture.ledger.mu.Lock()
	fixture.ledger.path = ledgerPath
	err := fixture.ledger.persistStateLocked(fixture.ledger.stateLocked())
	fixture.ledger.mu.Unlock()
	if err != nil {
		t.Fatalf("persist bounded ledger: %v", err)
	}
	info, err := os.Stat(ledgerPath)
	if err != nil {
		t.Fatalf("stat bounded ledger: %v", err)
	}
	const maximumLedgerBytes = 512 << 10
	if info.Size() > maximumLedgerBytes {
		t.Fatalf("bounded ledger grew to %d bytes, limit=%d", info.Size(), maximumLedgerBytes)
	}

	reloaded := newLedger(ledgerPath)
	if reloaded.loadErr != nil {
		t.Fatalf("reload bounded ledger: %v", reloaded.loadErr)
	}
	payerBefore := reloaded.balance(fixture.payer.cert.Cert.SubjectNodeID)
	relayBefore := reloaded.balance(fixture.relay.cert.Cert.SubjectNodeID)
	decisionsBefore := len(reloaded.decisions)
	handler := newCAHandler(fixture.ca(), "", "test-ca", 3600, reloaded)
	response, status := postVoucher(t, handler, oldestRequest)
	if status != http.StatusOK || !response.Replayed || !response.Stale || !response.Allow ||
		response.Delta != 0 || response.RelayCredit != 0 {
		t.Fatalf("evicted old replay was not zero-delta after restart: status=%d response=%+v", status, response)
	}
	channel := reloaded.channels[settlementChannelKey]
	if channel.Frozen || reloaded.balance(fixture.payer.cert.Cert.SubjectNodeID) != payerBefore ||
		reloaded.balance(fixture.relay.cert.Cert.SubjectNodeID) != relayBefore || len(reloaded.decisions) != decisionsBefore {
		t.Fatal("evicted old replay changed or froze the authoritative ledger")
	}
}

func TestVoucherSettlementRejectsCrossPayeeSessionReuse(t *testing.T) {
	fixture := newVoucherTestFixture(t, "")
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, 4<<20); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	firstVoucher := fixture.voucher(1, 256<<10, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, fixture.relay)
	if response, status := postVoucher(t, fixture.handler, fixture.request(firstVoucher, fixture.payer, fixture.relay)); status != http.StatusOK {
		t.Fatalf("first voucher: status=%d response=%+v", status, response)
	}
	otherRelay := newVoucherTestIdentity(t, fixture.ca(), admission.RoleRelay)
	crossPayeeVoucher := fixture.voucher(1, 256<<10, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, otherRelay)
	response, status := postVoucher(t, fixture.handler, fixture.request(crossPayeeVoucher, fixture.payer, otherRelay))
	if status != http.StatusConflict || !response.Frozen || fixture.ledger.balance(otherRelay.cert.Cert.SubjectNodeID) != 0 {
		t.Fatalf("cross-payee session reuse accepted: status=%d response=%+v", status, response)
	}
	if !fixture.ledger.channels[voucherChannelKey(firstVoucher.Body)].Frozen {
		t.Fatal("original channel was not frozen after session binding conflict")
	}
}

func TestVoucherSettlementPersistenceFailureIsAtomic(t *testing.T) {
	missingDirectory := filepath.Join(t.TempDir(), "missing")
	fixture := newVoucherTestFixture(t, "")
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, 1<<20); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	fixture.ledger.path = filepath.Join(missingDirectory, "ledger.json")
	voucher := fixture.voucher(1, 256<<10, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, fixture.relay)
	response, status := postVoucher(t, fixture.handler, fixture.request(voucher, fixture.payer, fixture.relay))
	if status != http.StatusInternalServerError || response.Error == "" {
		t.Fatalf("persistence failure not surfaced: status=%d response=%+v", status, response)
	}
	if fixture.ledger.balance(fixture.payer.cert.Cert.SubjectNodeID) != 1<<20 ||
		fixture.ledger.balance(fixture.relay.cert.Cert.SubjectNodeID) != 0 || fixture.ledger.caRevenueTotal() != 0 ||
		len(fixture.ledger.channels) != 0 || len(fixture.ledger.decisions) != 0 {
		t.Fatal("failed durable commit leaked partial in-memory state")
	}
}

func TestLegacyMutatingEndpointsAreGone(t *testing.T) {
	fixture := newVoucherTestFixture(t, "")
	if _, err := fixture.ledger.creditChecked("payer", 1000); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	for _, endpoint := range []string{admission.PathSettle, admission.PathReserve} {
		request := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"used_delta":-999999,"client_fee":-1}`))
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusGone {
			t.Fatalf("%s status=%d, want 410", endpoint, recorder.Code)
		}
	}
	if fixture.ledger.balance("payer") != 1000 {
		t.Fatal("legacy endpoint mutated ledger")
	}
}

func TestLedgerLoadsLegacyBalanceMap(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(ledgerPath, []byte(`{"legacy-node":777}`), 0o600); err != nil {
		t.Fatalf("write legacy ledger: %v", err)
	}
	loaded := newLedger(ledgerPath)
	if loaded.loadErr != nil || loaded.balance("legacy-node") != 777 {
		t.Fatalf("legacy load failed: err=%v balance=%d", loaded.loadErr, loaded.balance("legacy-node"))
	}
	if _, err := loaded.creditChecked("legacy-node", 1); err != nil {
		t.Fatalf("migrate legacy ledger: %v", err)
	}
	reloaded := newLedger(ledgerPath)
	if reloaded.loadErr != nil || reloaded.balance("legacy-node") != 778 {
		t.Fatalf("migrated reload failed: err=%v balance=%d", reloaded.loadErr, reloaded.balance("legacy-node"))
	}
}

func newVoucherTestFixture(t *testing.T, ledgerPath string) *voucherTestFixture {
	t.Helper()
	caPrivateKey, err := admission.GenerateCAKey()
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	payer := newVoucherTestIdentity(t, caPrivateKey, admission.RoleServer)
	relay := newVoucherTestIdentity(t, caPrivateKey, admission.RoleRelay)
	pubPEM, err := admission.MarshalCAPublicKeyPEM(&caPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal CA public key: %v", err)
	}
	ledger := newLedger(ledgerPath)
	return &voucherTestFixture{
		testing:      t,
		caPrivateKey: caPrivateKey,
		payer:        payer,
		relay:        relay,
		sessionID:    testIdentifier("session"),
		ledger:       ledger,
		handler:      newCAHandler(caPrivateKey, pubPEM, "test-ca", 3600, ledger),
	}
}

func (fixture *voucherTestFixture) ca() *ecdsa.PrivateKey {
	return fixture.caPrivateKey
}

func newVoucherTestIdentity(t *testing.T, caPrivateKey *ecdsa.PrivateKey, role admission.Role) voucherTestIdentity {
	t.Helper()
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	publicHex := hex.EncodeToString(privateKey.PublicKey().Bytes())
	return voucherTestIdentity{
		privateKey: privateKey,
		publicHex:  publicHex,
		cert:       issueTestCertificate(t, caPrivateKey, publicHex, role),
	}
}

func issueTestCertificate(t *testing.T, caPrivateKey *ecdsa.PrivateKey, publicHex string, role admission.Role) *admission.SignedCert {
	t.Helper()
	certificate, err := issue(caPrivateKey, admission.IssueRequest{SubjectPubKey: publicHex, Role: role}, "test-ca", 3600)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	return certificate
}

func (fixture *voucherTestFixture) voucher(
	sequence uint64,
	cumulative uint64,
	previous billingvoucher.Identifier,
	session billingvoucher.Identifier,
	payer voucherTestIdentity,
	relay voucherTestIdentity,
) billingvoucher.MutualVoucher {
	fixture.testing.Helper()
	payerID, err := billingvoucher.NodeIDFromPublicKey(payer.privateKey.PublicKey())
	if err != nil {
		fixture.testing.Fatalf("payer ID: %v", err)
	}
	relayID, err := billingvoucher.NodeIDFromPublicKey(relay.privateKey.PublicKey())
	if err != nil {
		fixture.testing.Fatalf("relay ID: %v", err)
	}
	body := billingvoucher.VoucherBody{
		Version:                 billingvoucher.CurrentVersion,
		SessionID:               session,
		PayerNatID:              payerID,
		PayeeRelayID:            relayID,
		Direction:               billingvoucher.DirectionPayerOutbound,
		Sequence:                sequence,
		PreviousMutualVoucherID: previous,
		CumulativeUniqueBytes:   cumulative,
		LastRecordID:            testIdentifier("record-" + strconv.FormatUint(sequence, 10)),
		LastRecordSequence:      sequence,
		RecordSetDigest:         testDigest("record-set-" + strconv.FormatUint(sequence, 10)),
		PolicyDigest:            billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes:  billingvoucher.MaxBillableBytes,
	}
	return signVoucher(fixture.testing, body, payer.privateKey, relay.privateKey)
}

func signVoucher(t *testing.T, body billingvoucher.VoucherBody, payer, relay *ecdh.PrivateKey) billingvoucher.MutualVoucher {
	t.Helper()
	payerSignature, err := billingvoucher.SignPayer(body, payer)
	if err != nil {
		t.Fatalf("sign payer: %v", err)
	}
	relaySignature, err := billingvoucher.SignRelay(body, relay)
	if err != nil {
		t.Fatalf("sign relay: %v", err)
	}
	voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		t.Fatalf("new mutual voucher: %v", err)
	}
	return voucher
}

func (fixture *voucherTestFixture) request(voucher billingvoucher.MutualVoucher, payer, relay voucherTestIdentity) admission.VoucherSettleRequest {
	fixture.testing.Helper()
	canonical, err := voucher.CanonicalBytes()
	if err != nil {
		fixture.testing.Fatalf("canonical voucher: %v", err)
	}
	return admission.VoucherSettleRequest{
		CanonicalVoucher: canonical,
		PayerPublicKey:   payer.publicHex,
		RelayPublicKey:   relay.publicHex,
		PayerCert:        payer.cert,
		RelayCert:        relay.cert,
	}
}

func postVoucher(t *testing.T, handler http.Handler, request admission.VoucherSettleRequest) (admission.VoucherSettleResponse, int) {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal voucher request: %v", err)
	}
	return postRawVoucher(t, handler, body)
}

func postRawVoucher(t *testing.T, handler http.Handler, body []byte) (admission.VoucherSettleResponse, int) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, admission.PathVoucherSettle, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var response admission.VoucherSettleResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode voucher response status=%d body=%q: %v", recorder.Code, recorder.Body.String(), err)
	}
	return response, recorder.Code
}

func testIdentifier(label string) billingvoucher.Identifier {
	return sha256.Sum256([]byte("identifier/" + label))
}

func testDigest(label string) billingvoucher.Digest {
	return sha256.Sum256([]byte("digest/" + label))
}
