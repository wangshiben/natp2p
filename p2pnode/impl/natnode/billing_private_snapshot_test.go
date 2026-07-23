package natnode

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/crypoto"
)

func TestBillingPrivateSnapshotIsFreshSecureAndRedacted(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "billing-meter.json")
	if err := meter.setPrivateSnapshotPath(path); err != nil {
		t.Fatalf("configure private snapshot: %v", err)
	}
	defer func() {
		if err := meter.closePrivateSnapshot(); err != nil {
			t.Errorf("close private snapshot: %v", err)
		}
	}()

	initial := readNatBillingPrivateSnapshot(t, path)
	initialGeneratedAt, err := time.Parse(time.RFC3339Nano, initial.GeneratedAt)
	if err != nil {
		t.Fatalf("parse initial generated_at: %v", err)
	}
	if initial.Version != natBillingPrivateSnapshotVersion || initial.ActiveSessionCount != 0 || initial.Sessions == nil {
		t.Fatalf("unexpected initial private snapshot: %+v", initial)
	}
	assertFileMode(t, filepath.Dir(path), 0o700)
	assertFileMode(t, path, 0o600)

	sessionID := billingvoucher.Identifier{0x11, 0x12, 0x13}
	relayID := billingvoucher.Identifier{0x21, 0x22, 0x23}
	relayAddress := "relay-private-name.example:9000"
	meter.mu.Lock()
	meter.enabled = true
	session := newNatBillingSession()
	session.relayID = relayID
	session.cumulative = 4096
	session.nextAssigned = 5
	session.nextAdvance = 5
	session.confirmedSequence = 4
	meter.sessions[sessionID] = session
	meter.relaySessions[relayAddress] = sessionID
	meter.channels[sessionID.String()+"|"+relayID.String()] = &natVoucherChannel{
		has: true,
		last: billingvoucher.MutualVoucher{Body: billingvoucher.VoucherBody{
			SessionID:             sessionID,
			PayeeRelayID:          relayID,
			CumulativeUniqueBytes: 3072,
		}},
	}
	meter.notifyPrivateSnapshotLocked()
	meter.mu.Unlock()

	current := waitForNatBillingPrivateSnapshot(t, path, func(snapshot natBillingPrivateSnapshot) bool {
		return snapshot.ActiveSessionCount == 1 && snapshot.CumulativeObservedBytes == 4096 &&
			snapshot.LastCosignedCumulative == 3072
	})
	if !current.BillingEnabled || len(current.Sessions) != 1 {
		t.Fatalf("unexpected active private snapshot: %+v", current)
	}
	wantSession := natBillingPrivateSessionSnapshot{
		SessionID:               sessionID.String(),
		CumulativeObservedBytes: 4096,
		LastRecordSequence:      4,
		ConfirmedSequence:       4,
		LastCosignedCumulative:  3072,
	}
	if current.Sessions[0] != wantSession {
		t.Fatalf("private session snapshot = %+v, want %+v", current.Sessions[0], wantSession)
	}
	currentGeneratedAt, err := time.Parse(time.RFC3339Nano, current.GeneratedAt)
	if err != nil || !currentGeneratedAt.After(initialGeneratedAt) {
		t.Fatalf("state-change generated_at = %q, initial = %q, err = %v", current.GeneratedAt, initial.GeneratedAt, err)
	}

	periodic := waitForNatBillingPrivateSnapshot(t, path, func(snapshot natBillingPrivateSnapshot) bool {
		generatedAt, parseErr := time.Parse(time.RFC3339Nano, snapshot.GeneratedAt)
		return parseErr == nil && generatedAt.After(currentGeneratedAt)
	})
	if periodic.CumulativeObservedBytes != current.CumulativeObservedBytes {
		t.Fatal("periodic refresh changed the observed billing watermark")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertNatBillingPrivateSnapshotSchema(t, raw)
	for _, sensitive := range []string{
		relayAddress,
		relayID.String(),
		hex.EncodeToString(payerKey.Bytes()),
		"payer_signature",
		"relay_signature",
		"record_set",
		"last_record_id",
	} {
		if strings.Contains(string(raw), sensitive) {
			t.Fatalf("private snapshot exposed forbidden material %q: %s", sensitive, raw)
		}
	}
}

func TestBillingPrivateSnapshotRejectsNonPrivateParent(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := meter.setPrivateSnapshotPath(""); err != nil || meter.privateSnapshotWriter != nil {
		t.Fatalf("empty snapshot path changed behavior: writer=%v err=%v", meter.privateSnapshotWriter, err)
	}

	directory := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "billing-meter.json")
	if err := meter.setPrivateSnapshotPath(path); err == nil {
		t.Fatal("configured private billing snapshot in a non-private directory")
	}
	if meter.privateSnapshotWriter != nil {
		t.Fatal("failed configuration retained a private snapshot writer")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed configuration created snapshot file: %v", err)
	}
}

func TestBillingPrivateSnapshotAtomicDuringConcurrentUpdates(t *testing.T) {
	payerKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meter, err := newNatBillingMeter(payerKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "billing-meter.json")
	if err := meter.setPrivateSnapshotPath(path); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := meter.closePrivateSnapshot(); err != nil {
			t.Errorf("close private snapshot: %v", err)
		}
	}()

	sessionID := billingvoucher.Identifier{0x31, 0x32, 0x33}
	relayID := billingvoucher.Identifier{0x41, 0x42, 0x43}
	meter.mu.Lock()
	session := newNatBillingSession()
	session.relayID = relayID
	meter.sessions[sessionID] = session
	meter.relaySessions["concurrent-relay"] = sessionID
	meter.notifyPrivateSnapshotLocked()
	meter.mu.Unlock()

	stopReader := make(chan struct{})
	readerDone := make(chan struct{})
	readError := make(chan error, 1)
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stopReader:
				return
			default:
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				readError <- readErr
				return
			}
			var snapshot natBillingPrivateSnapshot
			if decodeErr := json.Unmarshal(raw, &snapshot); decodeErr != nil {
				readError <- fmt.Errorf("decode atomic snapshot: %w", decodeErr)
				return
			}
			if snapshot.Version != natBillingPrivateSnapshotVersion || snapshot.Sessions == nil {
				readError <- fmt.Errorf("observed incomplete atomic snapshot: %+v", snapshot)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	for sequence := uint64(1); sequence <= 150; sequence++ {
		meter.mu.Lock()
		session.cumulative = sequence * 100
		session.nextAssigned = sequence + 1
		session.nextAdvance = sequence + 1
		session.confirmedSequence = sequence
		meter.notifyPrivateSnapshotLocked()
		meter.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	final := waitForNatBillingPrivateSnapshot(t, path, func(snapshot natBillingPrivateSnapshot) bool {
		return snapshot.CumulativeObservedBytes == 15000 && len(snapshot.Sessions) == 1 &&
			snapshot.Sessions[0].ConfirmedSequence == 150
	})
	if final.Sessions[0].LastRecordSequence != final.Sessions[0].ConfirmedSequence {
		t.Fatalf("final observed/confirmed sequence mismatch: %+v", final.Sessions[0])
	}
	close(stopReader)
	<-readerDone
	select {
	case err := <-readError:
		t.Fatal(err)
	default:
	}
	assertFileMode(t, path, 0o600)
}

func readNatBillingPrivateSnapshot(t *testing.T, path string) natBillingPrivateSnapshot {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot natBillingPrivateSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode private snapshot: %v", err)
	}
	return snapshot
}

func waitForNatBillingPrivateSnapshot(
	t *testing.T,
	path string,
	condition func(natBillingPrivateSnapshot) bool,
) natBillingPrivateSnapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last natBillingPrivateSnapshot
	var lastError error
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(raw, &last)
		}
		if err == nil && condition(last) {
			return last
		}
		lastError = err
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for private billing snapshot: last=%+v err=%v", last, lastError)
	return natBillingPrivateSnapshot{}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s permissions = %04o, want %04o", path, got, want)
	}
}

func assertNatBillingPrivateSnapshotSchema(t *testing.T, raw []byte) {
	t.Helper()
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	topLevelKeys := map[string]struct{}{
		"version": {}, "generated_at": {}, "billing_enabled": {}, "active_session_count": {},
		"cumulative_observed_bytes": {}, "last_cosigned_cumulative": {}, "sessions": {},
	}
	if len(document) != len(topLevelKeys) {
		t.Fatalf("unexpected private snapshot fields: %s", raw)
	}
	for key := range document {
		if _, allowed := topLevelKeys[key]; !allowed {
			t.Fatalf("unexpected private snapshot field %q", key)
		}
	}
	var sessions []map[string]json.RawMessage
	if err := json.Unmarshal(document["sessions"], &sessions); err != nil || len(sessions) != 1 {
		t.Fatalf("decode private snapshot sessions: len=%d err=%v", len(sessions), err)
	}
	sessionKeys := map[string]struct{}{
		"session_id": {}, "cumulative_observed_bytes": {}, "last_record_sequence": {},
		"confirmed_sequence": {}, "last_cosigned_cumulative": {},
	}
	if len(sessions[0]) != len(sessionKeys) {
		t.Fatalf("unexpected private session fields: %s", raw)
	}
	for key := range sessions[0] {
		if _, allowed := sessionKeys[key]; !allowed {
			t.Fatalf("unexpected private session field %q", key)
		}
	}
}
