package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"bnfs_p2p/billingvoucher"
)

func TestLedgerWALRecoversOnlyIncompleteTail(t *testing.T) {
	tests := []struct {
		name string
		tail []byte
	}{
		{name: "partial length", tail: []byte{0, 0}},
		{name: "partial record", tail: append([]byte{0, 0, 0, 64}, []byte("partial")...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
			loaded := newLedger(ledgerPath)
			if _, err := loaded.creditChecked("payer", 100); err != nil {
				t.Fatalf("credit payer: %v", err)
			}
			appendWALBytes(t, ledgerWALPath(ledgerPath), test.tail)

			recovered := newLedger(ledgerPath)
			if recovered.loadErr != nil {
				t.Fatalf("recover incomplete WAL tail: %v", recovered.loadErr)
			}
			if recovered.balance("payer") != 100 || recovered.transactionSeq != 1 {
				t.Fatalf("recovered state mismatch: balance=%d sequence=%d", recovered.balance("payer"), recovered.transactionSeq)
			}
			assertResetWAL(t, ledgerPath)
		})
	}
}

func TestLedgerWALRejectsCompleteCorruptRecord(t *testing.T) {
	tests := []struct {
		name          string
		credits       []int64
		recordToBreak int
	}{
		{name: "final record", credits: []int64{100}, recordToBreak: 0},
		{name: "middle record", credits: []int64{100, 50}, recordToBreak: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
			loaded := newLedger(ledgerPath)
			for _, credit := range test.credits {
				if _, err := loaded.creditChecked("payer", credit); err != nil {
					t.Fatalf("credit payer: %v", err)
				}
			}
			corruptWALChecksum(t, ledgerWALPath(ledgerPath), test.recordToBreak)

			failed := newLedger(ledgerPath)
			if failed.loadErr == nil || !strings.Contains(failed.loadErr.Error(), "checksum") {
				t.Fatalf("complete corrupt WAL was not rejected: %v", failed.loadErr)
			}
		})
	}
}

func TestLedgerWALReplayIsExactlyOnceAcrossSnapshotCrashWindow(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
	loaded := newLedger(ledgerPath)
	if _, err := loaded.creditChecked("payer", 100); err != nil {
		t.Fatalf("first credit: %v", err)
	}
	if _, err := loaded.creditChecked("payer", 50); err != nil {
		t.Fatalf("second credit: %v", err)
	}
	loaded.mu.Lock()
	err := loaded.persistStateLocked(loaded.stateLocked())
	loaded.mu.Unlock()
	if err != nil {
		t.Fatalf("persist crash-window snapshot: %v", err)
	}

	recovered := newLedger(ledgerPath)
	if recovered.loadErr != nil || recovered.balance("payer") != 150 || recovered.transactionSeq != 2 {
		t.Fatalf("stale WAL replayed twice: err=%v balance=%d sequence=%d", recovered.loadErr, recovered.balance("payer"), recovered.transactionSeq)
	}
	assertResetWAL(t, ledgerPath)
	if _, err := recovered.creditChecked("payer", 25); err != nil {
		t.Fatalf("post-recovery credit: %v", err)
	}
	restarted := newLedger(ledgerPath)
	if restarted.loadErr != nil || restarted.balance("payer") != 175 || restarted.transactionSeq != 3 {
		t.Fatalf("new WAL replay mismatch: err=%v balance=%d sequence=%d", restarted.loadErr, restarted.balance("payer"), restarted.transactionSeq)
	}
}

func TestLedgerWALCompactsAtTransactionBoundary(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
	loaded := newLedger(ledgerPath)
	loaded.walTransactions = ledgerWALCompactionTransactionCount - 1
	if _, err := loaded.creditChecked("payer", 100); err != nil {
		t.Fatalf("boundary credit: %v", err)
	}
	if loaded.loadErr != nil || loaded.walTransactions != 0 {
		t.Fatalf("compaction boundary failed: err=%v transactions=%d", loaded.loadErr, loaded.walTransactions)
	}
	assertResetWAL(t, ledgerPath)
	reloaded := newLedger(ledgerPath)
	if reloaded.loadErr != nil || reloaded.balance("payer") != 100 || reloaded.transactionSeq != 1 {
		t.Fatalf("compacted snapshot mismatch: err=%v balance=%d sequence=%d", reloaded.loadErr, reloaded.balance("payer"), reloaded.transactionSeq)
	}
}

func TestLedgerMigratesVersionTwoVoucherSnapshot(t *testing.T) {
	fixture := newVoucherTestFixture(t, "")
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, 4<<20); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	voucher := fixture.voucher(1, billingvoucher.CumulativeWindowBytes, billingvoucher.Identifier{}, fixture.sessionID, fixture.payer, fixture.relay)
	voucherID, err := voucher.ID()
	if err != nil {
		t.Fatalf("voucher ID: %v", err)
	}
	response, status := fixture.ledger.settleVoucher(validatedVoucher{request: fixture.request(voucher, fixture.payer, fixture.relay), voucher: voucher, id: voucherID})
	if status != http.StatusOK || response.Delta != int64(billingvoucher.CumulativeWindowBytes) {
		t.Fatalf("seed settlement: status=%d response=%+v", status, response)
	}
	fixture.ledger.mu.Lock()
	legacy := fixture.ledger.stateLocked()
	fixture.ledger.mu.Unlock()
	legacy.Version = legacyVoucherLedgerVersion
	legacy.DecisionOrder = nil
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal v2 snapshot: %v", err)
	}
	ledgerPath := filepath.Join(t.TempDir(), "ledger-v2.json")
	if err := os.WriteFile(ledgerPath, encoded, 0o600); err != nil {
		t.Fatalf("write v2 snapshot: %v", err)
	}

	migrated := newLedger(ledgerPath)
	if migrated.loadErr != nil || len(migrated.channels) != 1 || len(migrated.acceptedSequences) != 1 ||
		len(migrated.decisions) != 1 || len(migrated.decisionOrder) != 1 {
		t.Fatalf("v2 migration mismatch: err=%v channels=%d accepted=%d decisions=%d order=%d",
			migrated.loadErr, len(migrated.channels), len(migrated.acceptedSequences), len(migrated.decisions), len(migrated.decisionOrder))
	}
	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read migrated snapshot: %v", err)
	}
	var persisted ledgerDiskState
	if err := json.Unmarshal(data, &persisted); err != nil || persisted.Version != ledgerFormatVersion {
		t.Fatalf("migrated snapshot was not persisted as v%d: version=%d err=%v", ledgerFormatVersion, persisted.Version, err)
	}
}

func TestVoucherSettlementWALRecordDoesNotGrowWithChannelCount(t *testing.T) {
	fixture := newVoucherTestFixture(t, "")
	const channelCount = 3_000
	initialBalance := int64(channelCount+2)*int64(billingvoucher.CumulativeWindowBytes) + 1
	if _, err := fixture.ledger.creditChecked(fixture.payer.cert.Cert.SubjectNodeID, initialBalance); err != nil {
		t.Fatalf("credit payer: %v", err)
	}
	started := time.Now()
	for index := 0; index < channelCount; index++ {
		sessionID := testIdentifier("capacity-session-" + strconv.Itoa(index))
		voucher := fixture.voucher(1, billingvoucher.CumulativeWindowBytes, billingvoucher.Identifier{}, sessionID, fixture.payer, fixture.relay)
		voucherID, err := voucher.ID()
		if err != nil {
			t.Fatalf("voucher %d ID: %v", index, err)
		}
		response, status := fixture.ledger.settleVoucher(validatedVoucher{request: fixture.request(voucher, fixture.payer, fixture.relay), voucher: voucher, id: voucherID})
		if status != http.StatusOK || response.Delta != int64(billingvoucher.CumulativeWindowBytes) {
			t.Fatalf("voucher %d settlement: status=%d response=%+v", index, status, response)
		}
	}
	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Fatalf("settling %d independent channels took %s", channelCount, elapsed)
	}
	ledgerPath := filepath.Join(t.TempDir(), "capacity-ledger.json")
	fixture.ledger.mu.Lock()
	fixture.ledger.path = ledgerPath
	err := fixture.ledger.persistStateLocked(fixture.ledger.stateLocked())
	fixture.ledger.mu.Unlock()
	if err != nil {
		t.Fatalf("persist capacity snapshot: %v", err)
	}

	lastSession := testIdentifier("capacity-session-last")
	lastVoucher := fixture.voucher(1, billingvoucher.CumulativeWindowBytes, billingvoucher.Identifier{}, lastSession, fixture.payer, fixture.relay)
	lastID, err := lastVoucher.ID()
	if err != nil {
		t.Fatalf("last voucher ID: %v", err)
	}
	response, status := fixture.ledger.settleVoucher(validatedVoucher{request: fixture.request(lastVoucher, fixture.payer, fixture.relay), voucher: lastVoucher, id: lastID})
	if status != http.StatusOK || response.Delta != int64(billingvoucher.CumulativeWindowBytes) {
		t.Fatalf("last settlement: status=%d response=%+v", status, response)
	}
	payload := firstWALPayload(t, ledgerWALPath(ledgerPath))
	if len(payload) > 16<<10 {
		t.Fatalf("single-channel WAL transaction grew to %d bytes with %d existing channels", len(payload), channelCount)
	}
	var transaction ledgerWALTransaction
	if err := json.Unmarshal(payload, &transaction); err != nil {
		t.Fatalf("decode WAL transaction: %v", err)
	}
	if len(transaction.ChannelSet) != 1 || len(transaction.SessionBindingSet) != 1 || len(transaction.AcceptedSequenceSet) != 1 ||
		len(transaction.DecisionSet) != 1 || len(transaction.EvidenceSet) != 1 {
		t.Fatalf("WAL transaction is not local: channels=%d bindings=%d accepted=%d decisions=%d evidence=%d",
			len(transaction.ChannelSet), len(transaction.SessionBindingSet), len(transaction.AcceptedSequenceSet), len(transaction.DecisionSet), len(transaction.EvidenceSet))
	}
	reloaded := newLedger(ledgerPath)
	if reloaded.loadErr != nil || len(reloaded.channels) != channelCount+1 {
		t.Fatalf("capacity WAL reload mismatch: err=%v channels=%d", reloaded.loadErr, len(reloaded.channels))
	}
}

func appendWALBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open WAL for append: %v", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		t.Fatalf("append WAL bytes: %v", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatalf("sync WAL bytes: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close WAL: %v", err)
	}
}

func corruptWALChecksum(t *testing.T, path string, recordIndex int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	offset := len(ledgerWALHeader)
	for index := 0; ; index++ {
		if offset+4 > len(data) {
			t.Fatalf("WAL record %d does not exist", recordIndex)
		}
		length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		checksumEnd := offset + 4 + length + 32
		if checksumEnd > len(data) {
			t.Fatalf("WAL record %d is incomplete", index)
		}
		if index == recordIndex {
			data[checksumEnd-1] ^= 0xff
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("write corrupt WAL: %v", err)
			}
			return
		}
		offset = checksumEnd
	}
}

func firstWALPayload(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	offset := len(ledgerWALHeader)
	if offset+4 > len(data) {
		t.Fatal("WAL contains no transaction")
	}
	length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	payloadEnd := offset + 4 + length
	if payloadEnd+32 > len(data) {
		t.Fatal("WAL transaction is incomplete")
	}
	return bytes.Clone(data[offset+4 : payloadEnd])
}

func assertResetWAL(t *testing.T, ledgerPath string) {
	t.Helper()
	data, err := os.ReadFile(ledgerWALPath(ledgerPath))
	if err != nil {
		t.Fatalf("read reset WAL: %v", err)
	}
	if !bytes.Equal(data, []byte(ledgerWALHeader)) {
		t.Fatalf("WAL was not reset after snapshot: %d bytes", len(data))
	}
}
