package natnode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/logx"
)

const (
	natBillingPrivateSnapshotVersion  = 1
	natBillingPrivateSnapshotInterval = 100 * time.Millisecond
)

type natBillingPrivateSessionSnapshot struct {
	SessionID               string `json:"session_id"`
	CumulativeObservedBytes uint64 `json:"cumulative_observed_bytes"`
	LastRecordSequence      uint64 `json:"last_record_sequence"`
	ConfirmedSequence       uint64 `json:"confirmed_sequence"`
	LastCosignedCumulative  uint64 `json:"last_cosigned_cumulative"`
}

type natBillingPrivateSnapshot struct {
	Version                 int                                `json:"version"`
	GeneratedAt             string                             `json:"generated_at"`
	BillingEnabled          bool                               `json:"billing_enabled"`
	ActiveSessionCount      int                                `json:"active_session_count"`
	CumulativeObservedBytes uint64                             `json:"cumulative_observed_bytes"`
	LastCosignedCumulative  uint64                             `json:"last_cosigned_cumulative"`
	Sessions                []natBillingPrivateSessionSnapshot `json:"sessions"`
}

type natBillingPrivateSnapshotWriter struct {
	meter *natBillingMeter
	path  string
	wake  chan struct{}
	stop  chan struct{}
	done  chan struct{}

	closeOnce sync.Once
	resultMu  sync.Mutex
	closeErr  error
}

func newNatBillingPrivateSnapshotWriter(meter *natBillingMeter, path string) *natBillingPrivateSnapshotWriter {
	return &natBillingPrivateSnapshotWriter{
		meter: meter,
		path:  filepath.Clean(path),
		wake:  make(chan struct{}, 1),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
}

func (meter *natBillingMeter) setPrivateSnapshotPath(path string) error {
	if meter == nil {
		return errors.New("natnode: billing meter is unavailable")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	path = filepath.Clean(path)
	if err := prepareNatBillingPrivateSnapshotDirectory(filepath.Dir(path)); err != nil {
		return err
	}

	writer := newNatBillingPrivateSnapshotWriter(meter, path)
	meter.mu.Lock()
	if meter.privateSnapshotWriter != nil {
		meter.mu.Unlock()
		return errors.New("natnode: private billing snapshot path is already configured")
	}
	snapshot, err := meter.privateSnapshotLocked(time.Now())
	if err == nil {
		err = writer.write(snapshot)
	}
	if err != nil {
		meter.mu.Unlock()
		return fmt.Errorf("natnode: initialize private billing snapshot: %w", err)
	}
	meter.privateSnapshotWriter = writer
	go writer.run()
	meter.mu.Unlock()
	return nil
}

func (meter *natBillingMeter) closePrivateSnapshot() error {
	if meter == nil {
		return nil
	}
	meter.mu.Lock()
	writer := meter.privateSnapshotWriter
	meter.privateSnapshotWriter = nil
	meter.mu.Unlock()
	if writer == nil {
		return nil
	}
	return writer.close()
}

func (meter *natBillingMeter) notifyPrivateSnapshotLocked() {
	writer := meter.privateSnapshotWriter
	if writer == nil {
		return
	}
	select {
	case writer.wake <- struct{}{}:
	default:
	}
}

func (meter *natBillingMeter) privateSnapshot() (natBillingPrivateSnapshot, error) {
	meter.mu.Lock()
	defer meter.mu.Unlock()
	return meter.privateSnapshotLocked(time.Now())
}

func (meter *natBillingMeter) privateSnapshotLocked(now time.Time) (natBillingPrivateSnapshot, error) {
	snapshot := natBillingPrivateSnapshot{
		Version:        natBillingPrivateSnapshotVersion,
		GeneratedAt:    now.UTC().Format(time.RFC3339Nano),
		BillingEnabled: meter.enabled,
		Sessions:       make([]natBillingPrivateSessionSnapshot, 0),
	}
	activeSessions := make(map[billingvoucher.Identifier]*natBillingSession)
	for _, sessionID := range meter.relaySessions {
		if _, invalid := meter.invalidSessions[sessionID]; invalid {
			continue
		}
		if session := meter.sessions[sessionID]; session != nil {
			activeSessions[sessionID] = session
		}
	}
	sessionIDs := make([]billingvoucher.Identifier, 0, len(activeSessions))
	for sessionID := range activeSessions {
		sessionIDs = append(sessionIDs, sessionID)
	}
	sort.Slice(sessionIDs, func(left, right int) bool {
		return sessionIDs[left].String() < sessionIDs[right].String()
	})

	for _, sessionID := range sessionIDs {
		session := activeSessions[sessionID]
		lastRecordSequence := uint64(0)
		if session.nextAdvance > 0 {
			lastRecordSequence = session.nextAdvance - 1
		}
		lastCosignedCumulative := uint64(0)
		channel := meter.channels[sessionID.String()+"|"+session.relayID.String()]
		if channel != nil && channel.has && channel.last.Body.SessionID == sessionID &&
			channel.last.Body.PayeeRelayID == session.relayID {
			lastCosignedCumulative = channel.last.Body.CumulativeUniqueBytes
		}
		if math.MaxUint64-snapshot.CumulativeObservedBytes < session.cumulative ||
			math.MaxUint64-snapshot.LastCosignedCumulative < lastCosignedCumulative {
			return natBillingPrivateSnapshot{}, errors.New("private billing snapshot aggregate overflow")
		}
		snapshot.CumulativeObservedBytes += session.cumulative
		snapshot.LastCosignedCumulative += lastCosignedCumulative
		snapshot.Sessions = append(snapshot.Sessions, natBillingPrivateSessionSnapshot{
			SessionID:               sessionID.String(),
			CumulativeObservedBytes: session.cumulative,
			LastRecordSequence:      lastRecordSequence,
			ConfirmedSequence:       session.confirmedSequence,
			LastCosignedCumulative:  lastCosignedCumulative,
		})
	}
	snapshot.ActiveSessionCount = len(snapshot.Sessions)
	return snapshot, nil
}

func (writer *natBillingPrivateSnapshotWriter) run() {
	ticker := time.NewTicker(natBillingPrivateSnapshotInterval)
	defer ticker.Stop()
	defer close(writer.done)
	hadError := false
	write := func() error {
		snapshot, err := writer.meter.privateSnapshot()
		if err == nil {
			err = writer.write(snapshot)
		}
		if err != nil {
			if !hadError {
				logx.Warnf("[natnode] 私有计费快照写入失败: %v", err)
			}
			hadError = true
			return err
		}
		if hadError {
			logx.Infof("[natnode] 私有计费快照写入已恢复")
			hadError = false
		}
		return nil
	}

	for {
		select {
		case <-writer.wake:
			_ = write()
		case <-ticker.C:
			_ = write()
		case <-writer.stop:
			writer.resultMu.Lock()
			writer.closeErr = write()
			writer.resultMu.Unlock()
			return
		}
	}
}

func (writer *natBillingPrivateSnapshotWriter) close() error {
	writer.closeOnce.Do(func() {
		close(writer.stop)
	})
	<-writer.done
	writer.resultMu.Lock()
	defer writer.resultMu.Unlock()
	return writer.closeErr
}

func (writer *natBillingPrivateSnapshotWriter) write(snapshot natBillingPrivateSnapshot) error {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeNatBillingPrivateSnapshotAtomic(writer.path, encoded); err != nil {
		return err
	}
	return nil
}

func prepareNatBillingPrivateSnapshotDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("natnode: create private billing snapshot directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("natnode: inspect private billing snapshot directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("natnode: private billing snapshot parent must be a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("natnode: private billing snapshot directory permissions must be 0700, got %04o", info.Mode().Perm())
	}
	return nil
}

func writeNatBillingPrivateSnapshotAtomic(path string, encoded []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".billing-meter-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary snapshot: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("protect temporary snapshot: %w", err)
	}
	written, err := temporary.Write(encoded)
	if err != nil {
		cleanup()
		return fmt.Errorf("write temporary snapshot: %w", err)
	}
	if written != len(encoded) {
		cleanup()
		return fmt.Errorf("write temporary snapshot: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("close temporary snapshot: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("publish snapshot: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open snapshot directory: %w", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		_ = directoryHandle.Close()
		return fmt.Errorf("sync snapshot directory: %w", err)
	}
	if err := directoryHandle.Close(); err != nil {
		return fmt.Errorf("close snapshot directory: %w", err)
	}
	return nil
}
