package billingadversary

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"bnfs_p2p/billingcontrol"
	"bnfs_p2p/billingqueue"
	"bnfs_p2p/billingrecord"
	"bnfs_p2p/billingvoucher"
)

const (
	probeSchemaVersion = 1
	probeWindowBytes   = billingvoucher.CumulativeWindowBytes
)

var (
	Scenarios = []string{
		"relay_usage_inflation",
		"relay_request_replay",
		"relay_fee_override",
		"relay_window_overrun",
		"nat_stale_watermark",
		"nat_same_sequence_fork",
		"nat_signature_refusal",
		"relay_voucher_tamper",
		"index_disconnect_backlog_recovery",
	}
	probeNoncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,160}$`)
	probeLimitations  = []string{
		"component_probe_not_full_p2p_socket_path",
		"nat_relay_session_state_machine_not_instantiated",
	}
)

type Request struct {
	Scenario string `json:"scenario"`
	Nonce    string `json:"nonce"`
	StateDir string `json:"-"`
}

type Result struct {
	SchemaVersion      int      `json:"schemaVersion"`
	Scenario           string   `json:"scenario"`
	Status             string   `json:"status"`
	FailureCode        string   `json:"failureCode"`
	Checks             []string `json:"checks"`
	ProductionPackages []string `json:"productionPackages"`
	Limitations        []string `json:"limitations"`
}

type probeFailure struct {
	code string
}

func (failure probeFailure) Error() string {
	return failure.code
}

type claimState struct {
	cumulative uint64
	lastID     billingvoucher.Identifier
	lastSeq    uint64
	digest     billingvoucher.Digest
}

type probeFixture struct {
	payer      *ecdh.PrivateKey
	relay      *ecdh.PrivateKey
	payerID    billingvoucher.Identifier
	relayID    billingvoucher.Identifier
	sessionID  billingvoucher.Identifier
	policy     billingvoucher.Digest
	authorized uint64
	nonce      string
}

func Run(request Request) Result {
	result := Result{
		SchemaVersion:      probeSchemaVersion,
		Scenario:           request.Scenario,
		Status:             "FAIL",
		FailureCode:        "component_probe_invalid_request",
		Checks:             []string{},
		ProductionPackages: []string{},
		Limitations:        append([]string(nil), probeLimitations...),
	}
	if !knownScenario(request.Scenario) || !probeNoncePattern.MatchString(request.Nonce) || request.StateDir == "" {
		return result
	}

	fixture, err := newProbeFixture(request.Nonce)
	if err != nil {
		result.FailureCode = "component_probe_fixture_failed"
		return result
	}
	baselineBytes := uint64(512 * 1024)
	if request.Scenario == "relay_request_replay" || request.Scenario == "index_disconnect_backlog_recovery" {
		baselineBytes = probeWindowBytes
	}
	baseline, baselineState, err := fixture.issueVoucher(1, baselineBytes, claimState{}, nil, "baseline")
	if err != nil {
		result.FailureCode = failureCode(err, "component_probe_baseline_failed")
		return result
	}
	result.Checks = append(result.Checks,
		"record_derived_relay_claim_nat_matched",
		"double_signed_canonical_voucher_verified",
	)
	result.ProductionPackages = []string{"billingrecord", "billingvoucher"}

	checks, packages, err := runScenario(request, fixture, baseline, baselineState)
	result.Checks = append(result.Checks, checks...)
	result.ProductionPackages = appendUnique(result.ProductionPackages, packages...)
	if err != nil {
		result.FailureCode = failureCode(err, "component_probe_internal_error")
		return result
	}
	result.Status = "PASS"
	result.FailureCode = ""
	return result
}

func runScenario(request Request, fixture *probeFixture, baseline billingvoucher.MutualVoucher, baselineState claimState) ([]string, []string, error) {
	switch request.Scenario {
	case "relay_usage_inflation":
		body := baseline.Body
		body.CumulativeUniqueBytes += 64 * 1024
		relaySignature, err := billingvoucher.SignRelay(body, fixture.relay)
		if err != nil {
			return nil, nil, probeFailure{"inflated_relay_claim_sign_failed"}
		}
		if err := billingvoucher.VerifyRelaySignature(body, relaySignature, fixture.relay.PublicKey()); err != nil {
			return nil, nil, probeFailure{"inflated_relay_claim_auth_failed"}
		}
		if err := fixture.validateClaim(body, baselineState); err == nil {
			return nil, nil, probeFailure{"inflated_relay_claim_accepted"}
		}
		return []string{"nat_meter_rejected_relay_usage_inflation"}, nil, nil

	case "relay_request_replay":
		if err := probeReplayQueue(request.StateDir, baseline); err != nil {
			return nil, []string{"billingqueue"}, err
		}
		return []string{"queue_duplicate_rejected_before_and_after_reopen"}, []string{"billingqueue"}, nil

	case "relay_fee_override":
		body := baseline.Body
		body.PolicyDigest[0] ^= 1
		relaySignature, err := billingvoucher.SignRelay(body, fixture.relay)
		if err != nil {
			return nil, nil, probeFailure{"overridden_policy_claim_sign_failed"}
		}
		if err := billingvoucher.VerifyRelaySignature(body, relaySignature, fixture.relay.PublicKey()); err != nil {
			return nil, nil, probeFailure{"overridden_policy_claim_auth_failed"}
		}
		if err := fixture.validateClaim(body, baselineState); err == nil {
			return nil, nil, probeFailure{"overridden_policy_claim_accepted"}
		}
		return []string{"immutable_policy_digest_enforced"}, nil, nil

	case "relay_window_overrun":
		state, err := fixture.advanceRecord(claimState{}, probeWindowBytes+1, 1, "overrun")
		if err != nil {
			return nil, nil, probeFailure{"window_overrun_record_failed"}
		}
		body := fixture.body(1, billingvoucher.Identifier{}, state)
		if err := body.Validate(); err == nil {
			return nil, nil, probeFailure{"one_mib_window_overrun_accepted"}
		}
		if _, err := billingvoucher.SignRelay(body, fixture.relay); err == nil {
			return nil, nil, probeFailure{"one_mib_window_overrun_signed"}
		}
		return []string{"voucher_body_rejected_one_mib_window_overrun"}, nil, nil

	case "nat_stale_watermark":
		state, err := fixture.advanceRecord(baselineState, 256*1024, 2, "stale")
		if err != nil {
			return nil, nil, probeFailure{"stale_watermark_record_failed"}
		}
		previousID, err := baseline.ID()
		if err != nil {
			return nil, nil, probeFailure{"stale_watermark_predecessor_failed"}
		}
		body := fixture.body(2, previousID, state)
		body.CumulativeUniqueBytes = baseline.Body.CumulativeUniqueBytes
		candidate, err := fixture.signMutual(body)
		if err != nil {
			return nil, nil, probeFailure{"stale_watermark_candidate_failed"}
		}
		if err := billingvoucher.ValidateSuccessor(baseline, candidate); err == nil {
			return nil, nil, probeFailure{"stale_watermark_successor_accepted"}
		}
		return []string{"successor_rejected_non_increasing_watermark"}, nil, nil

	case "nat_same_sequence_fork":
		forkState, err := fixture.advanceRecord(claimState{}, 640*1024, 1, "fork")
		if err != nil {
			return nil, nil, probeFailure{"same_sequence_fork_record_failed"}
		}
		fork, err := fixture.signMutual(fixture.body(1, billingvoucher.Identifier{}, forkState))
		if err != nil {
			return nil, nil, probeFailure{"same_sequence_fork_sign_failed"}
		}
		forkID, err := fork.ID()
		if err != nil {
			return nil, nil, probeFailure{"same_sequence_fork_id_failed"}
		}
		baselineID, err := baseline.ID()
		if err != nil || forkID == baselineID {
			return nil, nil, probeFailure{"same_sequence_fork_not_distinct"}
		}
		if err := billingvoucher.ValidateSuccessor(baseline, fork); err == nil {
			return nil, nil, probeFailure{"same_sequence_fork_successor_accepted"}
		}
		if err := probeSessionBindings(fixture, baseline, baselineState); err != nil {
			return nil, []string{"billingcontrol"}, err
		}
		return []string{
			"same_sequence_fork_rejected_by_chain",
			"session_chain_and_ready_proof_binding_enforced",
		}, []string{"billingcontrol"}, nil

	case "nat_signature_refusal":
		relaySignature, err := billingvoucher.SignRelay(baseline.Body, fixture.relay)
		if err != nil {
			return nil, nil, probeFailure{"relay_only_claim_sign_failed"}
		}
		if _, err := billingvoucher.NewMutualVoucher(baseline.Body, nil, relaySignature); err == nil {
			return nil, nil, probeFailure{"missing_nat_signature_accepted"}
		}
		return []string{"mutual_voucher_required_nat_signature"}, nil, nil

	case "relay_voucher_tamper":
		candidate := baseline
		candidate.Body.LastRecordID[0] ^= 1
		candidate.Body.RecordSetDigest[0] ^= 1
		if err := candidate.Verify(fixture.payer.PublicKey(), fixture.relay.PublicKey()); err == nil {
			return nil, nil, probeFailure{"tampered_record_root_accepted"}
		}
		return []string{"double_signatures_bound_record_id_and_root"}, nil, nil

	case "index_disconnect_backlog_recovery":
		if err := probeBacklogRecovery(request.StateDir, fixture, baseline, baselineState); err != nil {
			return nil, []string{"billingqueue"}, err
		}
		return []string{
			"one_mib_vouchers_persisted_on_each_enqueue",
			"queue_reopened_and_drained_in_fifo_order",
			"queued_tail_duplicate_rejected",
		}, []string{"billingqueue"}, nil
	default:
		return nil, nil, probeFailure{"component_probe_unknown_scenario"}
	}
}

func newProbeFixture(nonce string) (*probeFixture, error) {
	payer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	relay, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	payerID, err := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	if err != nil {
		return nil, err
	}
	relayID, err := billingvoucher.NodeIDFromPublicKey(relay.PublicKey())
	if err != nil {
		return nil, err
	}
	return &probeFixture{
		payer:      payer,
		relay:      relay,
		payerID:    payerID,
		relayID:    relayID,
		sessionID:  probeIdentifier("session:" + nonce),
		policy:     billingvoucher.CurrentPolicyDigest(),
		authorized: 16 * probeWindowBytes,
		nonce:      nonce,
	}, nil
}

func (fixture *probeFixture) issueVoucher(sequence, bytes uint64, previousState claimState, previous *billingvoucher.MutualVoucher, label string) (billingvoucher.MutualVoucher, claimState, error) {
	state, err := fixture.advanceRecord(previousState, bytes, sequence, label)
	if err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	var previousID billingvoucher.Identifier
	if previous != nil {
		previousID, err = previous.ID()
		if err != nil {
			return billingvoucher.MutualVoucher{}, claimState{}, err
		}
	}
	body := fixture.body(sequence, previousID, state)
	relaySignature, err := billingvoucher.SignRelay(body, fixture.relay)
	if err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	if err := billingvoucher.VerifyRelaySignature(body, relaySignature, fixture.relay.PublicKey()); err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	if err := fixture.validateClaim(body, state); err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	payerSignature, err := billingvoucher.SignPayer(body, fixture.payer)
	if err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	canonical, err := voucher.CanonicalBytes()
	if err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	parsed, err := billingvoucher.ParseCanonicalVoucher(canonical)
	if err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	if err := parsed.Verify(fixture.payer.PublicKey(), fixture.relay.PublicKey()); err != nil {
		return billingvoucher.MutualVoucher{}, claimState{}, err
	}
	if previous != nil {
		if err := billingvoucher.ValidateSuccessor(*previous, parsed); err != nil {
			return billingvoucher.MutualVoucher{}, claimState{}, err
		}
	}
	return parsed, state, nil
}

func (fixture *probeFixture) advanceRecord(previous claimState, bytes, sequence uint64, label string) (claimState, error) {
	record := billingrecord.Record{
		SessionID:   fixture.sessionID,
		Sequence:    sequence,
		Bytes:       bytes,
		Connection:  "component-probe",
		E2ERecordID: []byte(fmt.Sprintf("record-%d-%s", sequence, label)),
		Ciphertext:  []byte("synthetic-component-ciphertext:" + fixture.nonce + ":" + label),
	}
	recordID, err := record.ID()
	if err != nil {
		return claimState{}, err
	}
	digest, err := billingrecord.Advance(previous.digest, recordID, sequence, bytes)
	if err != nil {
		return claimState{}, err
	}
	return claimState{
		cumulative: previous.cumulative + bytes,
		lastID:     recordID,
		lastSeq:    sequence,
		digest:     digest,
	}, nil
}

func (fixture *probeFixture) body(sequence uint64, previousID billingvoucher.Identifier, state claimState) billingvoucher.VoucherBody {
	return billingvoucher.VoucherBody{
		Version:                 billingvoucher.CurrentVersion,
		SessionID:               fixture.sessionID,
		PayerNatID:              fixture.payerID,
		PayeeRelayID:            fixture.relayID,
		Direction:               billingvoucher.DirectionPayerOutbound,
		Sequence:                sequence,
		PreviousMutualVoucherID: previousID,
		CumulativeUniqueBytes:   state.cumulative,
		LastRecordID:            state.lastID,
		LastRecordSequence:      state.lastSeq,
		RecordSetDigest:         state.digest,
		PolicyDigest:            fixture.policy,
		AuthorizedThroughBytes:  fixture.authorized,
	}
}

func (fixture *probeFixture) validateClaim(body billingvoucher.VoucherBody, expected claimState) error {
	if err := body.Validate(); err != nil {
		return err
	}
	if body.SessionID != fixture.sessionID || body.PayerNatID != fixture.payerID || body.PayeeRelayID != fixture.relayID ||
		body.Direction != billingvoucher.DirectionPayerOutbound || body.PolicyDigest != fixture.policy ||
		body.AuthorizedThroughBytes != fixture.authorized || body.CumulativeUniqueBytes != expected.cumulative ||
		body.LastRecordID != expected.lastID || body.LastRecordSequence != expected.lastSeq ||
		body.RecordSetDigest != expected.digest {
		return errors.New("component probe: Relay claim differs from Nat meter")
	}
	return nil
}

func (fixture *probeFixture) signMutual(body billingvoucher.VoucherBody) (billingvoucher.MutualVoucher, error) {
	payerSignature, err := billingvoucher.SignPayer(body, fixture.payer)
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	relaySignature, err := billingvoucher.SignRelay(body, fixture.relay)
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	return billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
}

func probeReplayQueue(stateDir string, voucher billingvoucher.MutualVoucher) error {
	queuePath, cleanup, err := newQueuePath(stateDir, "replay")
	if err != nil {
		return probeFailure{"replay_queue_state_dir_failed"}
	}
	defer cleanup()
	limits := billingqueue.Limits{MaxItems: 8, MaxBytes: 1 << 20}
	queue, err := billingqueue.Open(queuePath, limits)
	if err != nil {
		return probeFailure{"replay_queue_open_failed"}
	}
	if err := queue.Enqueue(voucher); err != nil {
		return probeFailure{"replay_queue_enqueue_failed"}
	}
	if err := queue.Enqueue(voucher); !errors.Is(err, billingqueue.ErrDuplicate) {
		return probeFailure{"replay_queue_duplicate_accepted"}
	}
	if err := queue.Close(); err != nil {
		return probeFailure{"replay_queue_close_failed"}
	}
	queue, err = billingqueue.Open(queuePath, limits)
	if err != nil {
		return probeFailure{"replay_queue_reopen_failed"}
	}
	defer queue.Close()
	if err := queue.Enqueue(voucher); !errors.Is(err, billingqueue.ErrDuplicate) {
		return probeFailure{"replay_queue_duplicate_lost_after_reopen"}
	}
	peeked, err := queue.Peek()
	if err != nil {
		return probeFailure{"replay_queue_peek_failed"}
	}
	wantID, err := voucher.ID()
	if err != nil {
		return probeFailure{"replay_queue_voucher_id_failed"}
	}
	gotID, err := peeked.ID()
	if err != nil || gotID != wantID {
		return probeFailure{"replay_queue_head_changed"}
	}
	return nil
}

func probeBacklogRecovery(stateDir string, fixture *probeFixture, baseline billingvoucher.MutualVoucher, baselineState claimState) error {
	queuePath, cleanup, err := newQueuePath(stateDir, "backlog")
	if err != nil {
		return probeFailure{"backlog_state_dir_failed"}
	}
	defer cleanup()
	vouchers := []billingvoucher.MutualVoucher{baseline}
	states := []claimState{baselineState}
	for sequence := uint64(2); sequence <= 3; sequence++ {
		voucher, state, err := fixture.issueVoucher(sequence, probeWindowBytes, states[len(states)-1], &vouchers[len(vouchers)-1], fmt.Sprintf("backlog-%d", sequence))
		if err != nil {
			return probeFailure{"backlog_voucher_chain_failed"}
		}
		vouchers = append(vouchers, voucher)
		states = append(states, state)
	}

	limits := billingqueue.Limits{MaxItems: 16, MaxBytes: 2 << 20}
	queue, err := billingqueue.Open(queuePath, limits)
	if err != nil {
		return probeFailure{"backlog_queue_open_failed"}
	}
	previousSize := fileSize(queuePath)
	for index, voucher := range vouchers {
		if err := queue.Enqueue(voucher); err != nil {
			return probeFailure{"backlog_enqueue_failed"}
		}
		currentSize := fileSize(queuePath)
		if currentSize <= previousSize {
			return probeFailure{"backlog_enqueue_not_persisted"}
		}
		previousSize = currentSize
		if err := queue.Close(); err != nil {
			return probeFailure{"backlog_enqueue_close_failed"}
		}
		queue, err = billingqueue.Open(queuePath, limits)
		if err != nil || queue.Len() != index+1 {
			return probeFailure{"backlog_enqueue_reopen_failed"}
		}
	}
	if err := queue.Enqueue(vouchers[len(vouchers)-1]); !errors.Is(err, billingqueue.ErrDuplicate) {
		return probeFailure{"backlog_tail_duplicate_accepted"}
	}
	snapshot, err := queue.Snapshot()
	if err != nil || len(snapshot) != len(vouchers) {
		return probeFailure{"backlog_snapshot_failed"}
	}
	for index := range vouchers {
		wantID, wantErr := vouchers[index].ID()
		gotID, gotErr := snapshot[index].ID()
		if wantErr != nil || gotErr != nil || gotID != wantID {
			return probeFailure{"backlog_fifo_order_changed"}
		}
	}
	for index, voucher := range vouchers {
		voucherID, err := voucher.ID()
		if err != nil || queue.Remove(voucherID) != nil {
			return probeFailure{"backlog_remove_failed"}
		}
		if err := queue.Close(); err != nil {
			return probeFailure{"backlog_remove_close_failed"}
		}
		queue, err = billingqueue.Open(queuePath, limits)
		if err != nil || queue.Len() != len(vouchers)-index-1 {
			return probeFailure{"backlog_remove_reopen_failed"}
		}
	}
	defer queue.Close()
	if _, err := queue.Peek(); !errors.Is(err, billingqueue.ErrEmpty) {
		return probeFailure{"backlog_queue_not_empty"}
	}
	return nil
}

func probeSessionBindings(fixture *probeFixture, baseline billingvoucher.MutualVoucher, baselineState claimState) error {
	successor, successorState, err := fixture.issueVoucher(2, 256*1024, baselineState, &baseline, "session-guard")
	if err != nil {
		return probeFailure{"session_guard_successor_failed"}
	}
	changedBody := successor.Body
	changedBody.SessionID = probeIdentifier("changed-session:" + fixture.nonce)
	changedSession, err := fixture.signMutual(changedBody)
	if err != nil {
		return probeFailure{"session_guard_changed_voucher_failed"}
	}
	if err := billingvoucher.ValidateSuccessor(baseline, changedSession); err == nil {
		return probeFailure{"session_change_accepted_in_chain"}
	}
	if successorState.cumulative <= baselineState.cumulative {
		return probeFailure{"session_guard_meter_not_advanced"}
	}

	publicKeyHex := hex.EncodeToString(fixture.payer.PublicKey().Bytes())
	challenge := probeIdentifier("challenge:" + fixture.nonce)
	binding := billingcontrol.ProofBinding{
		Challenge: challenge[:],
		SessionID: fixture.sessionID.String(),
		PayerID:   fixture.payerID.String(),
		RelayID:   fixture.relayID.String(),
	}
	proof, err := billingcontrol.SignReadyProof(fixture.payer, binding)
	if err != nil || billingcontrol.VerifyReadyProof(publicKeyHex, binding, proof) != nil {
		return probeFailure{"ready_proof_baseline_failed"}
	}
	binding.SessionID = changedBody.SessionID.String()
	if err := billingcontrol.VerifyReadyProof(publicKeyHex, binding, proof); err == nil {
		return probeFailure{"ready_proof_replay_across_session_accepted"}
	}
	return nil
}

func newQueuePath(stateDir, prefix string) (string, func(), error) {
	absolute, err := filepath.Abs(stateDir)
	if err != nil || absolute == filepath.Dir(absolute) {
		return "", func() {}, errors.New("invalid component probe state directory")
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return "", func() {}, err
	}
	directory, err := os.MkdirTemp(absolute, prefix+"-")
	if err != nil {
		return "", func() {}, err
	}
	return filepath.Join(directory, "waitsubmit.wal"), func() { _ = os.RemoveAll(directory) }, nil
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

func knownScenario(scenario string) bool {
	for _, candidate := range Scenarios {
		if scenario == candidate {
			return true
		}
	}
	return false
}

func failureCode(err error, fallback string) string {
	var failure probeFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	return fallback
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if _, exists := seen[value]; exists {
			continue
		}
		values = append(values, value)
		seen[value] = struct{}{}
	}
	return values
}

func probeIdentifier(label string) billingvoucher.Identifier {
	return sha256.Sum256([]byte(label))
}
