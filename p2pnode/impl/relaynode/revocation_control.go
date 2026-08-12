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
	// 初始化撤销控制面，恢复本地状态后先追平 CA 再启动后台同步。
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
	// 在 Relay 对外提供生产准入前循环拉取撤销增量直到 epoch 收敛。
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
	// 以长轮询和指数退避持续同步撤销状态，避免 CA 故障造成重连风暴。
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
	// 执行一次带签名校验、连续 epoch 检查和原子落盘的撤销同步。
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
	// 幂等保存实时收到的阻断决定，保证进程重启后仍能恢复处置。
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
	// 判断最近一次成功同步是否仍在生产准入允许的时间窗口内。
	control.mu.RLock()
	lastSuccessful := control.lastSuccessful
	control.mu.RUnlock()
	return !lastSuccessful.IsZero() && time.Since(lastSuccessful) <= revocationFreshnessLimit
}

func (control *relayRevocationControl) offlineDuration() time.Duration {
	// 计算撤销控制面连续离线时长，用于触发 fail-closed。
	control.mu.RLock()
	lastSuccessful := control.lastSuccessful
	control.mu.RUnlock()
	if lastSuccessful.IsZero() {
		return revocationHardOfflineLimit
	}
	return time.Since(lastSuccessful)
}

func (control *relayRevocationControl) failClosedForStaleness() {
	// 控制面长时间不可用时关闭新注册和现有 Relay 链路，防止撤销失效。
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
	// 以私有权限读取并验证撤销状态文件，拒绝截断、越权或非连续事件。
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
	// 通过临时文件、fsync 和原子重命名持久化撤销状态，避免崩溃留下半文件。
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
	// 返回当前 Relay 是否具备足够新鲜的撤销快照以继续接受连接。
	cfg := n.admissionConfig()
	if cfg == nil || cfg.Profile != SecurityProfileProduction {
		return true
	}
	n.mu.RLock()
	control := n.revocationControl
	n.mu.RUnlock()
	return control != nil && control.isFresh()
}
