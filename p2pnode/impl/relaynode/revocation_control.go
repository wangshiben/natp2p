package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/logx"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	revocationStateVersion     = 1
	revocationStateMaxSize     = 64 << 20
	revocationFreshnessLimit   = 60 * time.Second
	revocationHardOfflineLimit = 5 * time.Minute
)

type persistedRevocationState struct {
	Version      int                         `json:"version"`
	RelayID      string                      `json:"relay_id"`
	AppliedEpoch uint64                      `json:"applied_epoch"`
	Events       []admission.RevocationEvent `json:"events"`
	Decisions    []admission.DenyDecision    `json:"deny_decisions,omitempty"`
	UpdatedAt    int64                       `json:"updated_at"`
}

type relayRevocationControl struct {
	node        *RelayNode
	client      *admission.CAClient
	certificate *admission.SignedCert
	path        string

	mu             sync.RWMutex
	state          persistedRevocationState
	currentEpoch   uint64
	lastSuccessful time.Time
	hardClosed     bool
}

func (n *RelayNode) ConfigureRevocationControl(client *admission.CAClient, certificate *admission.SignedCert, path string) error {
	if client == nil || certificate == nil || path == "" {
		return errors.New("relaynode: revocation control requires CA client, relay certificate and state path")
	}
	control := &relayRevocationControl{node: n, client: client, certificate: certificate, path: path}
	state, err := control.loadState()
	if err != nil {
		return err
	}
	control.state = state
	n.mu.Lock()
	if n.revocationControl != nil {
		n.mu.Unlock()
		return errors.New("relaynode: revocation control is already configured")
	}
	n.revocationControl = control
	n.mu.Unlock()
	for _, event := range state.Events {
		if err := n.applyRevocationEvent(event); err != nil {
			return fmt.Errorf("relaynode: apply persisted revocation event: %w", err)
		}
	}
	for _, decision := range state.Decisions {
		if err := client.VerifyStoredDenyDecision(&decision, n.idStr()); err != nil {
			return fmt.Errorf("relaynode: verify persisted deny decision: %w", err)
		}
		if err := n.applyVerifiedDeny(decision.DecisionID, decision.ScopeType, decision.ScopeID, decision.ErrorCode, decision.EffectiveAt, &decision); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	err = control.syncUntilCurrent(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("relaynode: initial revocation sync failed: %w", err)
	}
	go control.run()
	return nil
}

func (control *relayRevocationControl) syncUntilCurrent(ctx context.Context) error {
	for {
		if err := control.syncOnce(ctx, 0); err != nil {
			return err
		}
		control.mu.RLock()
		converged := control.state.AppliedEpoch == control.currentEpoch
		control.mu.RUnlock()
		if converged {
			return nil
		}
	}
}

func (control *relayRevocationControl) run() {
	backoff := time.Second
	for control.node.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(control.node.ctx, 8*time.Second)
		err := control.syncOnce(ctx, 3)
		cancel()
		if err == nil {
			backoff = time.Second
			continue
		}
		logx.Warnf("[relaynode] 撤销 control sync 失败，%s 后重试: %v", backoff, err)
		if control.offlineDuration() >= revocationHardOfflineLimit {
			control.failClosedForStaleness()
		}
		timer := time.NewTimer(backoff)
		select {
		case <-control.node.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (control *relayRevocationControl) syncOnce(ctx context.Context, waitSeconds int) error {
	control.mu.RLock()
	afterEpoch := control.state.AppliedEpoch
	control.mu.RUnlock()
	request, err := admission.NewRevocationSyncRequest(
		control.node.privKey, control.certificate, afterEpoch, afterEpoch, waitSeconds, time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	response, err := control.client.SyncRevocations(ctx, request)
	if err != nil {
		return err
	}
	if response.CurrentEpoch < afterEpoch {
		return errors.New("relaynode: CA revocation epoch rolled back")
	}
	nextEpoch := afterEpoch + 1
	for _, event := range response.Events {
		if event.Epoch != nextEpoch {
			return fmt.Errorf("relaynode: non-contiguous revocation delta: got %d want %d", event.Epoch, nextEpoch)
		}
		if _, ok := permanentDenyCodes[event.ErrorCode]; !ok {
			return fmt.Errorf("relaynode: unknown revocation error code %q", event.ErrorCode)
		}
		nextEpoch++
	}
	if len(response.Events) == 0 && response.FromEpoch != afterEpoch {
		return errors.New("relaynode: invalid empty revocation delta")
	}
	if len(response.Events) == 0 && response.CurrentEpoch > afterEpoch {
		return errors.New("relaynode: revocation delta omitted pending epochs")
	}
	control.mu.Lock()
	proposed := control.state
	proposed.Events = append(append([]admission.RevocationEvent(nil), control.state.Events...), response.Events...)
	if len(response.Events) > 0 {
		proposed.AppliedEpoch = response.Events[len(response.Events)-1].Epoch
	}
	proposed.UpdatedAt = time.Now().UTC().Unix()
	if err := control.writeState(proposed); err != nil {
		control.mu.Unlock()
		return err
	}
	control.state = proposed
	control.currentEpoch = response.CurrentEpoch
	control.lastSuccessful = time.Now().UTC()
	control.mu.Unlock()
	for _, event := range response.Events {
		if err := control.node.applyRevocationEvent(event); err != nil {
			return err
		}
	}
	return nil
}

func (control *relayRevocationControl) persistDecision(decision admission.DenyDecision) error {
	control.mu.Lock()
	defer control.mu.Unlock()
	for _, existing := range control.state.Decisions {
		if existing.DecisionID == decision.DecisionID {
			return nil
		}
	}
	proposed := control.state
	proposed.Events = append([]admission.RevocationEvent(nil), control.state.Events...)
	proposed.Decisions = append(append([]admission.DenyDecision(nil), control.state.Decisions...), decision)
	proposed.UpdatedAt = time.Now().UTC().Unix()
	if err := control.writeState(proposed); err != nil {
		return err
	}
	control.state = proposed
	return nil
}

func (control *relayRevocationControl) isFresh() bool {
	control.mu.RLock()
	lastSuccessful := control.lastSuccessful
	control.mu.RUnlock()
	return !lastSuccessful.IsZero() && time.Since(lastSuccessful) <= revocationFreshnessLimit
}

func (control *relayRevocationControl) offlineDuration() time.Duration {
	control.mu.RLock()
	lastSuccessful := control.lastSuccessful
	control.mu.RUnlock()
	if lastSuccessful.IsZero() {
		return revocationHardOfflineLimit
	}
	return time.Since(lastSuccessful)
}

func (control *relayRevocationControl) failClosedForStaleness() {
	control.mu.Lock()
	if control.hardClosed {
		control.mu.Unlock()
		return
	}
	control.hardClosed = true
	control.mu.Unlock()
	logx.Errorf("[relaynode] CA 撤销状态超过 %s 未刷新，关闭所有托管注册与 Relay 链路", revocationHardOfflineLimit)
	for _, account := range control.node.accounts.snapshot() {
		_ = control.node.starter.Cover().CloseHostedRegistration(account.NodeID)
	}
	control.node.closeAllPeerLinks()
}

func (control *relayRevocationControl) loadState() (persistedRevocationState, error) {
	state := persistedRevocationState{Version: revocationStateVersion, RelayID: control.node.idStr(), Events: make([]admission.RevocationEvent, 0), Decisions: make([]admission.DenyDecision, 0)}
	file, err := os.Open(control.path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(control.path), 0o700); err != nil {
			return state, err
		}
		if err := control.writeState(state); err != nil {
			return state, err
		}
		return state, nil
	}
	if err != nil {
		return state, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > revocationStateMaxSize || info.Mode().Perm()&0o077 != 0 {
		return state, errors.New("relaynode: revocation state must be a private regular file up to 64 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, revocationStateMaxSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return state, errors.New("relaynode: revocation state contains trailing data")
	}
	if state.Version != revocationStateVersion || state.RelayID != control.node.idStr() || state.AppliedEpoch != uint64(len(state.Events)) {
		return state, errors.New("relaynode: revocation state identity or epoch is invalid")
	}
	for index, event := range state.Events {
		if event.Epoch != uint64(index+1) {
			return state, errors.New("relaynode: persisted revocation events are not contiguous")
		}
		if err := control.client.VerifyRevocationEvent(event); err != nil {
			return state, err
		}
	}
	return state, nil
}

func (control *relayRevocationControl) writeState(state persistedRevocationState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(encoded) > revocationStateMaxSize {
		return errors.New("relaynode: revocation state exceeds 64 MiB")
	}
	directory := filepath.Dir(control.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	nonce, err := admission.NewNonce()
	if err != nil {
		return err
	}
	temporary := filepath.Join(directory, "."+filepath.Base(control.path)+"."+nonce+".tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, control.path); err != nil {
		return err
	}
	removeTemporary = false
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = directoryHandle.Sync()
	closeErr := directoryHandle.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (n *RelayNode) revocationSyncFresh() bool {
	cfg := n.admissionConfig()
	if cfg == nil || cfg.Profile != SecurityProfileProduction {
		return true
	}
	n.mu.RLock()
	control := n.revocationControl
	n.mu.RUnlock()
	return control != nil && control.isFresh()
}
