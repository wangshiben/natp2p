package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/logx"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// 本文件实现 nat→relay 注册准入（无交互 indexSign）与被托管节点的角色账户。
//
// nat 节点注册时把 CA 签发的 indexSign 放进注册消息（见 networkFrameWork.EncodeRegisterPayload）。
// relay 在【建 StreamGroup 之前】经 onRegisterVerify 钩子离线验签：enforce 下失败即拒绝注册，
// 通过则把证书里的 Role 落到账户表——供计费方向区分 clientNode / serverNode。

// natAccount 是一个被托管 NAT 节点的账户信息。
type natAccount struct {
	NodeID string
	Role   admission.Role
	Cert   *admission.SignedCert
	Since  time.Time
	// UplinkBytes 是该节点（作为 serverNode 时）经本 relay 转发给客户端的累计上行净荷
	// （relay_to_clients 方向）。由 forward hook 累加（见 SetForwardHook 计费配置）。
	UplinkBytes int64
	// settledBytes 是已向 CA 上报结算过的净荷累计。UplinkBytes - settledBytes = 待上报增量。
	settledBytes int64
	// cutoff 为 true 表示 CA 裁决该节点 server 上行余额耗尽，metering hook 熔断其上行转发。
	// 由周期结算循环据 CA 裁决维护（默认 false；注册即可服务，白嫖由建连保证金兜底）。
	cutoff bool
}

// accountStore 是 relay 侧被托管节点账户表（按 nodeId）。
type accountStore struct {
	mu       sync.RWMutex
	accounts map[string]*natAccount
}

func newAccountStore() *accountStore {
	return &accountStore{accounts: make(map[string]*natAccount)}
}

// putRole 记录/更新某节点的角色（注册准入通过时调用）。
func (s *accountStore) putRole(nodeID string, role admission.Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc := s.accounts[nodeID]
	if acc == nil {
		acc = &natAccount{NodeID: nodeID, Since: time.Now()}
		s.accounts[nodeID] = acc
	}
	acc.Role = role
}

func (s *accountStore) putCert(nodeID string, cert *admission.SignedCert) {
	if cert == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acc := s.accounts[nodeID]
	if acc == nil {
		acc = &natAccount{NodeID: nodeID, Since: time.Now()}
		s.accounts[nodeID] = acc
	}
	copyCert := *cert
	acc.Cert = &copyCert
	acc.Role = cert.Cert.Role
}

func (s *accountStore) cert(nodeID string) *admission.SignedCert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if acc := s.accounts[nodeID]; acc != nil && acc.Cert != nil {
		copyCert := *acc.Cert
		return &copyCert
	}
	return nil
}

// addUplink 给某节点累加 server 上行净荷字节，返回累加后总量。
func (s *accountStore) addUplink(nodeID string, delta int64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc := s.accounts[nodeID]
	if acc == nil {
		acc = &natAccount{NodeID: nodeID, Since: time.Now()}
		s.accounts[nodeID] = acc
	}
	acc.UplinkBytes += delta
	return acc.UplinkBytes
}

// role 返回某节点的角色（未知返回空）。
func (s *accountStore) role(nodeID string) admission.Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if acc := s.accounts[nodeID]; acc != nil {
		return acc.Role
	}
	return ""
}

// isCutoff 报告某节点是否已被熔断（CA 裁决余额耗尽）。
func (s *accountStore) isCutoff(nodeID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if acc := s.accounts[nodeID]; acc != nil {
		return acc.cutoff
	}
	return false
}

// setCutoff 设置某节点熔断状态（结算循环据 CA 裁决调用）。
func (s *accountStore) setCutoff(nodeID string, cutoff bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if acc := s.accounts[nodeID]; acc != nil {
		acc.cutoff = cutoff
	}
}

// takeUnsettled 返回某节点自上次上报以来的上行增量, 并把 settledBytes 推进到当前 UplinkBytes。
// 结算循环调用它取增量上报给 CA（原子「读取+推进」，避免重复计费）。
func (s *accountStore) takeUnsettled(nodeID string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc := s.accounts[nodeID]
	if acc == nil {
		return 0
	}
	delta := acc.UplinkBytes - acc.settledBytes
	acc.settledBytes = acc.UplinkBytes
	return delta
}

// cutoffServerNodes 返回当前处于熔断状态的 server 节点（结算循环对其发余额探针以便充值后恢复）。
func (s *accountStore) cutoffServerNodes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for id, acc := range s.accounts {
		if acc.Role == admission.RoleServer && acc.cutoff {
			out = append(out, id)
		}
	}
	return out
}

// serverNodes 返回当前所有 server 角色节点的 NodeId（结算循环遍历用）。
func (s *accountStore) serverNodes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for id, acc := range s.accounts {
		if acc.Role == admission.RoleServer {
			out = append(out, id)
		}
	}
	return out
}

// snapshot 返回账户表快照（供状态打印/结算上报）。
func (s *accountStore) snapshot() []natAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]natAccount, 0, len(s.accounts))
	for _, acc := range s.accounts {
		out = append(out, *acc)
	}
	return out
}

// onRegisterVerify 是 TransportCover 的注册准入校验钩子实现（建 group 前调用）。
//
//	nodeId    被托管节点 NodeId（已由传输层按信封内公钥修正为真实值）。
//	signJSON  注册消息携带的 indexSign(admission.SignedCert JSON)，可空。
//	remoteAddr底层远端地址（仅日志）。
//
// 返回非 nil 表示拒绝注册。校验绑定 ExpectNodeID=nodeId，确保证书主体正是这个注册者。
// 校验通过后把证书 Role 落账户表。Mode=Off 时本钩子不会被安装（见 applyAdmissionHooks）。
func (n *RelayNode) onRegisterVerify(nodeId string, signJSON []byte, remoteAddr string) error {
	cert, err := n.verifyPeerCertJSON(signJSON, "", nodeId) // 角色不限定(nat 可能是 client/server)
	if !n.gateAdmission(cert, err, "register "+nodeId[:min(16, len(nodeId))]) {
		return err
	}
	if cert != nil {
		n.accounts.putRole(nodeId, cert.Role)
		n.accounts.putCert(nodeId, &admission.SignedCert{Cert: *cert, Sig: signedCertSignature(signJSON)})
		logx.Infof("[relaynode] NAT 节点注册准入通过: %.16s role=%s remote=%s", nodeId, cert.Role, remoteAddr)
	}
	return nil
}

func signedCertSignature(signJSON []byte) string {
	var signed admission.SignedCert
	if json.Unmarshal(signJSON, &signed) != nil {
		return ""
	}
	return signed.Sig
}

// AccountRole 返回本 relay 记录的某被托管节点角色（未知返回空）。供状态打印/计费与测试。
func (n *RelayNode) AccountRole(nodeID string) admission.Role { return n.accounts.role(nodeID) }

// AccountUplinkBytes 返回某被托管节点累计上行净荷字节。供状态打印/结算与测试。
func (n *RelayNode) AccountUplinkBytes(nodeID string) int64 {
	for _, acc := range n.accounts.snapshot() {
		if acc.NodeID == nodeID {
			return acc.UplinkBytes
		}
	}
	return 0
}

// applyAdmissionHooks 在准入启用时把注册校验钩子装到 TransportCover。
// 由 SetAdmission 调用；Mode=Off 时卸载钩子（保持旧行为）。
func (n *RelayNode) applyAdmissionHooks() {
	cover := n.starter.Cover()
	if n.admissionEnabled() {
		cover.SetRegisterVerifyHook(n.onRegisterVerify)
		cover.SetBusinessConnectHook(n.onBusinessConnect) // 方案B: 服务边界角色强制
		n.installSecureBillingPipeline()
	} else {
		cover.SetRegisterVerifyHook(nil)
		cover.SetBusinessConnectHook(nil)
	}
}

// 以下常量和 helper 属于已退役的连接保证金实现；当前 onBusinessConnect 不再调用它们，
// 字节费用只通过双签累计凭证结算。
const (
	connFeeClient int64 = 5 * 1024 * 1024 // 5 MB
	connFeeServer int64 = 50 * 1024       // 0.05 MB
	// depositWindow 是同一 (client,server) 对重复建连的免重复扣费窗口：窗口内的 dual-leg、
	// 断线重连、Connect 重试只扣一笔保证金，避免链路抖动的重试风暴以 5MB/次瞬间打空余额。
	depositWindow = 60 * time.Second
)

// depositReservation 是已退役连接保证金实现的一次裁决状态。
// done 关闭前代表 CA 裁决仍在进行；关闭后 err 是所有等待者都必须继承的结果。只有 paidAt
// 非零才表示 CA 已实际完成扣费，结果才可在 depositWindow 内复用。
type depositReservation struct {
	done   chan struct{}
	err    error
	paidAt time.Time
}

// onBusinessConnect 在业务连接接入本地托管的目标节点前被调用（StreamOn 之前）：
//
//  1. 方案B 服务边界角色强制：只有 role=server 的被托管节点才能作为连接目标被服务。
//     堵死「持 client 证书却对外提供服务逃计费」——client 角色即便被寻址到也拒绝接入。
//
// 参数：targetNodeId=目标(server) NodeId；clientPubKeyHex 与 connID 为传输层 hook 保留参数，
// 当前角色门不会用它们发起扣款。
//
// 为何在托管 relay 这一点：目标角色只在托管它的 relay 落账；而此处业务首帧同时带着
// 目标(Header)与发起方公钥(Payload)，是唯一能同时拿到两端身份、且覆盖同机/跨中继的点。
// 模式：Off 不安装；Warn 记 WARN 放行；Enforce 仅在目标角色不符时拒绝。
func (n *RelayNode) onBusinessConnect(targetNodeId, clientPubKeyHex, connID string) error {
	cfg := n.admissionConfig()
	if cfg == nil || cfg.Mode == AdmissionOff {
		return nil
	}

	// —— 1) 服务边界角色强制 ——
	role := n.accounts.role(targetNodeId)
	if role != admission.RoleServer {
		if cfg.Mode == AdmissionEnforce {
			logx.Warnf("[relaynode] 服务边界拒绝(enforce): 目标 %.16s 角色=%q 非 server", targetNodeId, role)
			return fmt.Errorf("relaynode: 目标节点 %.16s 角色非 server(=%q), 拒绝业务连接(方案B)", targetNodeId, role)
		}
		logx.Warnf("[relaynode] 服务边界告警(warn, 放行): 目标 %.16s 角色=%q 非 server", targetNodeId, role)
		return nil // warn 模式只记录角色异常
	}

	// 字节费用只允许走双签累计凭证；旧 /reserve 入口已停用，不能成为额外扣款或可用性依赖。
	return nil
}

// reservePair 是已退役连接保证金实现的 single-flight helper，当前业务连接路径不调用。
// pending 状态从不等同于已付款：
// follower 必须等待 leader 的 /reserve 返回，并继承成功或拒绝结果。
func (n *RelayNode) reservePair(cfg *AdmissionConfig, settler *admission.CAClient, pairKey, clientNodeID, targetNodeID, connID string) error {
	for {
		candidate := &depositReservation{done: make(chan struct{})}
		value, loaded := n.reservedPairs.LoadOrStore(pairKey, candidate)
		if !loaded {
			paid, err := n.reserveConnectionDeposit(cfg, settler, clientNodeID, targetNodeID, connID)
			candidate.err = err
			if paid {
				candidate.paidAt = time.Now()
			}
			close(candidate.done)
			if !paid {
				n.reservedPairs.CompareAndDelete(pairKey, candidate)
			}
			return err
		}

		reservation, ok := value.(*depositReservation)
		if !ok {
			// 仅用于兼容运行时遗留的旧值；删除后按当前协议重新裁决。
			n.reservedPairs.CompareAndDelete(pairKey, value)
			continue
		}

		select {
		case <-reservation.done:
			if reservation.err != nil {
				return reservation.err
			}
			if !reservation.paidAt.IsZero() && time.Since(reservation.paidAt) < depositWindow {
				return nil
			}
			// Warn 模式下的故障/余额不足会被策略性放行，但绝不能伪装成已付款；
			// 等待到该裁决的 follower 继承放行，新到的连接则重新请求 CA。
			if reservation.paidAt.IsZero() {
				return nil
			}
			n.reservedPairs.CompareAndDelete(pairKey, reservation)
		case <-n.ctx.Done():
			return fmt.Errorf("relaynode: 中继已关闭，取消连接保证金裁决")
		}
	}
}

// reserveConnectionDeposit 是已退役连接保证金实现的 CA 预扣 helper，当前业务连接路径不调用。
// 返回 paid=true 仅表示 CA 已原子完成双扣；Warn 模式的策略性放行始终返回 paid=false。
func (n *RelayNode) reserveConnectionDeposit(cfg *AdmissionConfig, settler *admission.CAClient, clientNodeID, targetNodeId, connID string) (paid bool, err error) {
	ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
	resp, err := settler.Reserve(ctx, admission.ReserveRequest{
		ConnID:       connID,
		ClientNodeID: clientNodeID,
		ServerNodeID: targetNodeId,
		RelayNodeID:  n.idStr(),
		ClientFee:    connFeeClient,
		ServerFee:    connFeeServer,
	})
	cancel()
	if err != nil {
		if cfg.Mode == AdmissionEnforce {
			logx.Warnf("[relaynode] 连接保证金请求失败(enforce, 拒绝) conn=%s: %v", connID, err)
			return false, fmt.Errorf("relaynode: 连接保证金预扣失败, 拒绝建连: %w", err)
		}
		logx.Warnf("[relaynode] 连接保证金请求失败(warn, 放行) conn=%s: %v", connID, err)
		return false, nil
	}
	if !resp.Allow {
		logx.Warnf("[relaynode] 连接保证金不足, 拒绝建连: client=%.16s(余%dB) server=%.16s(余%dB)",
			clientNodeID, resp.ClientBalance, targetNodeId, resp.ServerBalance)
		if cfg.Mode == AdmissionEnforce {
			return false, fmt.Errorf("relaynode: 连接保证金余额不足(client 余%dB/server 余%dB), 拒绝建连",
				resp.ClientBalance, resp.ServerBalance)
		}
		return false, nil
	}
	logx.Infof("[relaynode] 连接保证金已扣: conn=%s client=%.16s(余%dB) server=%.16s(余%dB)",
		connID, clientNodeID, resp.ClientBalance, targetNodeId, resp.ServerBalance)
	return true, nil
}
