package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	ledgerWALFormatVersion              = 1
	ledgerWALHeader                     = "BNFSCAW1\n"
	maximumLedgerWALRecordBytes         = 4 << 20
	ledgerWALCompactionTransactionCount = 4096
)

type ledgerWALTransaction struct {
	Version                int                              `json:"version"`
	Sequence               uint64                           `json:"sequence"`
	BalanceSet             map[string]int64                 `json:"balance_set,omitempty"`
	BalanceDelete          []string                         `json:"balance_delete,omitempty"`
	RelayIncomeSet         map[string]int64                 `json:"relay_income_set,omitempty"`
	RelayIncomeDelete      []string                         `json:"relay_income_delete,omitempty"`
	CARevenueChanged       bool                             `json:"ca_revenue_changed,omitempty"`
	CARevenue              int64                            `json:"ca_revenue,omitempty"`
	ChannelSet             map[string]channelWatermark      `json:"channel_set,omitempty"`
	ChannelDelete          []string                         `json:"channel_delete,omitempty"`
	SessionBindingSet      map[string]string                `json:"session_binding_set,omitempty"`
	SessionBindingDelete   []string                         `json:"session_binding_delete,omitempty"`
	AcceptedSequenceSet    map[string]string                `json:"accepted_sequence_set,omitempty"`
	AcceptedSequenceDelete []string                         `json:"accepted_sequence_delete,omitempty"`
	DecisionSet            map[string]voucherDecisionRecord `json:"decision_set,omitempty"`
	DecisionDelete         []string                         `json:"decision_delete,omitempty"`
	EvidenceSet            map[string]voucherEvidence       `json:"evidence_set,omitempty"`
	EvidenceDelete         []string                         `json:"evidence_delete,omitempty"`
	DecisionOrderChanged   bool                             `json:"decision_order_changed,omitempty"`
	DecisionOrder          []string                         `json:"decision_order,omitempty"`
}

func (transaction ledgerWALTransaction) empty() bool {
	return len(transaction.BalanceSet) == 0 && len(transaction.BalanceDelete) == 0 &&
		len(transaction.RelayIncomeSet) == 0 && len(transaction.RelayIncomeDelete) == 0 &&
		!transaction.CARevenueChanged && len(transaction.ChannelSet) == 0 && len(transaction.ChannelDelete) == 0 &&
		len(transaction.SessionBindingSet) == 0 && len(transaction.SessionBindingDelete) == 0 &&
		len(transaction.AcceptedSequenceSet) == 0 && len(transaction.AcceptedSequenceDelete) == 0 &&
		len(transaction.DecisionSet) == 0 && len(transaction.DecisionDelete) == 0 &&
		len(transaction.EvidenceSet) == 0 && len(transaction.EvidenceDelete) == 0 && !transaction.DecisionOrderChanged
}

func applyLedgerWALTransaction(state *ledgerDiskState, transaction ledgerWALTransaction) {
	applyLedgerMapDelta(state.Balances, transaction.BalanceSet, transaction.BalanceDelete)
	applyLedgerMapDelta(state.RelayIncome, transaction.RelayIncomeSet, transaction.RelayIncomeDelete)
	if transaction.CARevenueChanged {
		state.CARevenue = transaction.CARevenue
	}
	applyLedgerMapDelta(state.Channels, transaction.ChannelSet, transaction.ChannelDelete)
	applyLedgerMapDelta(state.SessionBindings, transaction.SessionBindingSet, transaction.SessionBindingDelete)
	applyLedgerMapDelta(state.AcceptedSequences, transaction.AcceptedSequenceSet, transaction.AcceptedSequenceDelete)
	applyLedgerMapDelta(state.Decisions, transaction.DecisionSet, transaction.DecisionDelete)
	applyLedgerMapDelta(state.Evidence, transaction.EvidenceSet, transaction.EvidenceDelete)
	if transaction.DecisionOrderChanged {
		state.DecisionOrder = append([]string(nil), transaction.DecisionOrder...)
	}
	state.TransactionSeq = transaction.Sequence
}

func applyLedgerMapDelta[V any](target map[string]V, set map[string]V, deleted []string) {
	for _, key := range deleted {
		delete(target, key)
	}
	for key, value := range set {
		target[key] = value
	}
}

func ledgerWALPath(snapshotPath string) string {
	return snapshotPath + ".wal"
}

func appendLedgerWAL(snapshotPath string, transaction ledgerWALTransaction) error {
	payload, err := json.Marshal(transaction)
	if err != nil {
		return fmt.Errorf("编码 WAL 事务: %w", err)
	}
	if len(payload) == 0 || len(payload) > maximumLedgerWALRecordBytes {
		return fmt.Errorf("WAL 事务大小 %d 超出上限", len(payload))
	}
	frame := make([]byte, 4+len(payload)+sha256.Size)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	checksum := sha256.Sum256(payload)
	copy(frame[4+len(payload):], checksum[:])

	path := ledgerWALPath(snapshotPath)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("打开账本 WAL: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("读取账本 WAL 状态: %w", err)
	}
	originalSize := info.Size()
	if originalSize == 0 {
		if _, err := file.WriteAt([]byte(ledgerWALHeader), 0); err != nil {
			return rollbackLedgerWAL(file, originalSize, fmt.Errorf("写 WAL 文件头: %w", err))
		}
	} else {
		header := make([]byte, len(ledgerWALHeader))
		if _, err := file.ReadAt(header, 0); err != nil || !bytes.Equal(header, []byte(ledgerWALHeader)) {
			_ = file.Close()
			return errors.New("账本 WAL 文件头损坏")
		}
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		return fmt.Errorf("定位账本 WAL 尾部: %w", err)
	}
	if _, err := file.Write(frame); err != nil {
		return rollbackLedgerWAL(file, originalSize, fmt.Errorf("追加账本 WAL: %w", err))
	}
	if err := file.Sync(); err != nil {
		return rollbackLedgerWAL(file, originalSize, fmt.Errorf("同步账本 WAL: %w", err))
	}
	_ = file.Close()
	return nil
}

func rollbackLedgerWAL(file *os.File, originalSize int64, cause error) error {
	truncateErr := file.Truncate(originalSize)
	syncErr := file.Sync()
	closeErr := file.Close()
	if truncateErr != nil || syncErr != nil || closeErr != nil {
		return fmt.Errorf("%v；WAL 回滚失败 truncate=%v sync=%v close=%v", cause, truncateErr, syncErr, closeErr)
	}
	return cause
}

func loadLedgerWAL(snapshotPath string, state ledgerDiskState) (ledgerDiskState, uint64, uint64, bool, error) {
	path := ledgerWALPath(snapshotPath)
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return state, 0, 0, false, nil
	}
	if err != nil {
		return ledgerDiskState{}, 0, 0, false, fmt.Errorf("打开账本 WAL: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ledgerDiskState{}, 0, 0, false, fmt.Errorf("读取账本 WAL 状态: %w", err)
	}
	fileSize := info.Size()
	if fileSize == 0 {
		return state, 0, 0, true, nil
	}
	if fileSize < int64(len(ledgerWALHeader)) {
		partial := make([]byte, fileSize)
		if _, err := file.ReadAt(partial, 0); err != nil || !bytes.Equal(partial, []byte(ledgerWALHeader)[:len(partial)]) {
			return ledgerDiskState{}, 0, 0, false, errors.New("账本 WAL 文件头损坏")
		}
		if err := truncateLedgerWALTail(file, 0); err != nil {
			return ledgerDiskState{}, 0, 0, false, err
		}
		return state, 0, 0, true, nil
	}
	header := make([]byte, len(ledgerWALHeader))
	if _, err := file.ReadAt(header, 0); err != nil || !bytes.Equal(header, []byte(ledgerWALHeader)) {
		return ledgerDiskState{}, 0, 0, false, errors.New("账本 WAL 文件头损坏")
	}

	offset := int64(len(ledgerWALHeader))
	lastSequence := uint64(0)
	applied := uint64(0)
	records := uint64(0)
	repaired := false
	for offset < fileSize {
		recordStart := offset
		if fileSize-offset < 4 {
			if err := truncateLedgerWALTail(file, recordStart); err != nil {
				return ledgerDiskState{}, 0, 0, false, err
			}
			repaired = true
			break
		}
		var lengthBytes [4]byte
		if _, err := file.ReadAt(lengthBytes[:], offset); err != nil {
			return ledgerDiskState{}, 0, 0, false, fmt.Errorf("读取 WAL 记录长度: %w", err)
		}
		offset += 4
		length := uint64(binary.BigEndian.Uint32(lengthBytes[:]))
		if length == 0 || length > maximumLedgerWALRecordBytes {
			return ledgerDiskState{}, 0, 0, false, fmt.Errorf("WAL 记录长度 %d 非法", length)
		}
		frameBytes := int64(length + sha256.Size)
		if frameBytes > fileSize-offset {
			if err := truncateLedgerWALTail(file, recordStart); err != nil {
				return ledgerDiskState{}, 0, 0, false, err
			}
			repaired = true
			break
		}
		frame := make([]byte, frameBytes)
		if _, err := file.ReadAt(frame, offset); err != nil {
			return ledgerDiskState{}, 0, 0, false, fmt.Errorf("读取 WAL 记录: %w", err)
		}
		offset += frameBytes
		payload := frame[:length]
		expectedChecksum := frame[length:]
		actualChecksum := sha256.Sum256(payload)
		if !bytes.Equal(actualChecksum[:], expectedChecksum) {
			return ledgerDiskState{}, 0, 0, false, fmt.Errorf("WAL 完整记录 checksum 损坏，offset=%d", recordStart)
		}
		var transaction ledgerWALTransaction
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&transaction); err != nil {
			return ledgerDiskState{}, 0, 0, false, fmt.Errorf("解析 WAL 事务: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return ledgerDiskState{}, 0, 0, false, errors.New("WAL 事务含尾随 JSON")
		}
		if transaction.Version != ledgerWALFormatVersion || transaction.Sequence == 0 || transaction.empty() {
			return ledgerDiskState{}, 0, 0, false, errors.New("WAL 事务版本、序号或内容非法")
		}
		if lastSequence != 0 && transaction.Sequence != lastSequence+1 {
			return ledgerDiskState{}, 0, 0, false, fmt.Errorf("WAL 序号不连续: %d -> %d", lastSequence, transaction.Sequence)
		}
		lastSequence = transaction.Sequence
		records++
		if transaction.Sequence <= state.TransactionSeq {
			continue
		}
		if transaction.Sequence != state.TransactionSeq+1 {
			return ledgerDiskState{}, 0, 0, false, fmt.Errorf("WAL 与快照序号不连续: snapshot=%d wal=%d", state.TransactionSeq, transaction.Sequence)
		}
		applyLedgerWALTransaction(&state, transaction)
		applied++
	}
	if err := validateLedgerState(state); err != nil {
		return ledgerDiskState{}, 0, 0, false, fmt.Errorf("WAL 重放后的账本非法: %w", err)
	}
	return state, applied, records, repaired, nil
}

func truncateLedgerWALTail(file *os.File, size int64) error {
	if err := file.Truncate(size); err != nil {
		return fmt.Errorf("截断损坏 WAL 尾部: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("同步截断后的 WAL: %w", err)
	}
	return nil
}

func resetLedgerWAL(snapshotPath string) error {
	return writeLedgerAtomicFile(ledgerWALPath(snapshotPath), []byte(ledgerWALHeader), ".ca-ledger-wal-*.tmp")
}

func writeLedgerAtomicFile(path string, data []byte, pattern string) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}
