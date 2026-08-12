package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/logx"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"
)

const (
	peerLinkRedialInitial = 500 * time.Millisecond
	peerLinkRedialMax     = 10 * time.Second
)

// peerLink 表示本 relay 与一台对端 relay 之间的「控制链路」。
//
// 控制链路是明文 Message 通道，只承载控制面元数据（HELLO / FIND / FIND_RESP），
// 不承载业务数据；业务数据走端到端加密并由 bridge 单独转发，relay 看不到明文。
//
// 链路是「可重试的」（req 4）：
//   - leg 级：底层 DualStream 对单条 TCP/KCP leg 自带指数退避重连；
//   - 链路级：本结构的 manage() 在整条链路断开后按退避重新拨号 + 重新 HELLO + 重新 serve。
//
// 两端都可能主动拨号：dialPeer 一侧由本 relay 发起（manage 循环），acceptPeer 一侧
// 由对端发起、经 MissingGroupHandler 进来。两侧建立后行为对称。
type peerLink struct {
	owner    *RelayNode
	addr     string // 对端 relay 的拨号地址（仅 dial 侧已知；accept 侧为空直到 HELLO）
	outbound bool   // true=本端主动拨号维持；false=对端拨入
	// inboundSessionKey / inboundGeneration 标识被动接入的逻辑 dual session；主动链路恒为空/0。
	inboundSessionKey string
	inboundGeneration uint64
	expectedPeerID    string

	mu        sync.Mutex
	sc        *client.StreamClient
	peerID    string // 对端 relay NodeId（HELLO 后获知）
	peerAddr  string // 对端 relay 公网业务地址（HELLO 后获知）
	peerCert  *admission.SignedCert
	countedUp bool
	// observedRemoteIP 是对端实际连入/被连的 IP（accept 侧从底层连接的 RemoteAddr 取得）。
	// HELLO 里对端自报的 Addr 可能是 ":9000" 这类不可路由的占位（relay 不知道自己的公网 IP），
	// 因此桥接拨号时优先用「可路由地址」: 见 dialHostAddr。
	observedRemoteIP string

	ctx    context.Context
	cancel context.CancelFunc
}

// observedDialAddr 返回「本端观察到的对端公网可路由地址」: observedRemoteIP + 对端自报端口。
// 仅 inbound(被动接入)链路有 observedRemoteIP。无法构造时返回空串。
// 用途: index 在回 HELLO 时把它告知主动注册进来的 relay, 让 relay 修正自己的对外地址。
func (pl *peerLink) observedDialAddr() string {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	if pl.observedRemoteIP == "" {
		return ""
	}
	port := portOf(pl.peerAddr)
	if port == "" {
		port = "9000"
	}
	return net.JoinHostPort(pl.observedRemoteIP, port)
}

// dialHostAddr 返回向「该对端 relay」发起桥接拨号时应使用的可路由地址。
//
// 选取优先级（关键修复）：
//  1. outbound 链路: 直接用我方拨号时用的 addr —— 它本来就是可路由的对端地址。
//  2. inbound 链路: 用「观察到的对端 IP」+「对端 HELLO 自报地址里的端口」拼成可路由地址,
//     因为对端自报的 host 部分（如空 / 0.0.0.0 / 内网）不可信, 但端口可信。
//  3. 兜底: 用对端自报的 peerAddr 原样返回。
//
// 这样即使 relay 启动时没有正确配置 -public（自报 ":9000"），跨中继桥接也能拨到真正的对端。
func (pl *peerLink) dialHostAddr() string {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	if pl.outbound && pl.addr != "" {
		return pl.addr
	}
	if pl.observedRemoteIP != "" {
		port := portOf(pl.peerAddr)
		if port == "" {
			port = "9000"
		}
		return net.JoinHostPort(pl.observedRemoteIP, port)
	}
	return pl.peerAddr
}

// portOf 从 "host:port" / ":port" 中取端口; 失败返回空。
func portOf(addr string) string {
	if addr == "" {
		return ""
	}
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return ""
}

// startOutboundPeerLink 创建并启动一条主动维持的控制链路（带链路级重试）。
func startOutboundPeerLink(owner *RelayNode, addr string) *peerLink {
	ctx, cancel := context.WithCancel(owner.ctx)
	pl := &peerLink{owner: owner, addr: addr, outbound: true, ctx: ctx, cancel: cancel}
	go pl.manage()
	return pl
}

// manage 是链路级重试循环：链路未建立 / 断开后按指数退避重新拨号、HELLO、serve。
func (pl *peerLink) manage() {
	backoff := peerLinkRedialInitial
	for {
		select {
		case <-pl.ctx.Done():
			return
		default:
		}

		sc, err := pl.dial()
		if err != nil {
			logx.Warnf("[relaynode] 拨号对端 relay %s 失败, %v 后重试: %v", pl.addr, backoff, err)
			if !pl.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		pl.setStream(sc)

		// 发送 HELLO，交换身份。准入证书(indexSign)随 HELLO 一并携带(见 sendHello),
		// 对端在 dispatch(ctrlHello) 里离线验签; 无交互, 每条 leg 各自验证。
		if err := pl.sendHello(); err != nil {
			logx.Warnf("[relaynode] 向 %s 发送 HELLO 失败: %v", pl.addr, err)
			sc.Close()
			if !pl.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		logx.Infof("[relaynode] 控制链路已建立(主动): peer=%s", pl.addr)
		backoff = peerLinkRedialInitial // 成功后重置退避

		// serve 阻塞直到链路断开。
		pl.serve(sc)
		logx.Infof("[relaynode] 控制链路断开(主动), 准备重连: peer=%s", pl.addr)

		if !pl.sleep(backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// dial 建立到对端 relay 的底层控制流。targetNodeId 用对端地址占位即可——
// 对端没有对应该 ID 的 group, 会落进 MissingGroupHandler, 据 RouteName 识别为控制链路。
//
// 保持 dual(KCP+TCP): 准入改为【无交互 indexSign】——每条 leg 在自己的 HELLO 里各带一份
// CA 签名证书, 对端在收到 HELLO 时【离线】独立验签, 无需两条 leg 之间 rendezvous, 天然规避
// 双 leg 握手竞态。故控制链路无需降级为单 TCP。
func (pl *peerLink) dial() (*client.StreamClient, error) {
	stream, _, err := networkFrameWork.TryConnectControlStream(
		pl.addr, pl.owner.controlTargetID(), pl.owner.pubKeyHex(), RelayControlRoute)
	if err != nil {
		return nil, err
	}
	return client.NewStreamClient(stream), nil
}

// adoptInbound 把对端拨入并经 MissingGroupHandler 接管的流接管为本链路（accept 侧）。
func (pl *peerLink) adoptInbound(sc *client.StreamClient) {
	pl.setStream(sc)
	go pl.serve(sc)
}

func (pl *peerLink) sendHello() error {
	cm := &controlMessage{Type: ctrlHello, NodeId: pl.owner.idStr(), Addr: pl.owner.getAddr()}
	// 无交互准入：HELLO 携带本端准入证书(indexSign)，对端离线验签。未启用准入时为 nil。
	cm.IndexSign = pl.owner.selfCertJSON()
	return pl.send(cm)
}

// send 在控制链路上发送一条控制消息。
func (pl *peerLink) send(cm *controlMessage) error {
	return pl.sendContext(pl.ctx, cm)
}

// sendContext 在控制链路上发送一条受调用方截止时间约束的控制消息。
func (pl *peerLink) sendContext(ctx context.Context, cm *controlMessage) error {
	pl.mu.Lock()
	sc := pl.sc
	pl.mu.Unlock()
	if sc == nil {
		return errPeerLinkDown
	}
	return sc.SendMessage(ctx, encodeControl(cm, pl.owner.idStr(), ""))
}

// serve 持续读取并分派对端发来的控制消息，直到链路出错或上下文取消。
func (pl *peerLink) serve(sc *client.StreamClient) {
	for {
		msg, err := sc.NextMessage(pl.ctx)
		if err != nil {
			pl.clearStream(sc)
			return
		}
		cm, err := decodeControl(msg)
		if err != nil {
			logx.Warnf("[relaynode] 解码控制消息失败: %v", err)
			continue
		}
		pl.mu.Lock()
		peerID := pl.peerID
		pl.mu.Unlock()
		pl.owner.relayControlSeen(peerID)
		pl.dispatch(sc, cm)
	}
}

// dispatch 处理单条控制消息。
func (pl *peerLink) dispatch(sc *client.StreamClient, cm *controlMessage) {
	switch cm.Type {
	case ctrlHello:
		// 无交互准入：校验对端 HELLO 携带的准入证书(indexSign)。绑定到对端自报 NodeId,
		// 要求角色为 relay。enforce 下校验失败即关闭链路; warn/off 放行。未启用时直接放行。
		var verifiedCertificate *admission.SignedCert
		if pl.owner.admissionEnabled() {
			cert, verr := pl.owner.verifyPeerCertJSON(cm.IndexSign, admission.RoleRelay, cm.NodeId)
			if !pl.owner.gateAdmission(cert, verr, "control-hello "+cm.NodeId[:min(16, len(cm.NodeId))]) {
				pl.clearStream(sc) // 关闭该 leg; outbound 由 manage 退避重连, inbound 直接废弃
				return
			}
			if cert != nil {
				var signed admission.SignedCert
				if err := json.Unmarshal(cm.IndexSign, &signed); err == nil {
					verifiedCertificate = &signed
				}
			}
		}
		pl.mu.Lock()
		if pl.sc != sc || pl.ctx.Err() != nil {
			pl.mu.Unlock()
			return
		}
		wasCounted := pl.countedUp
		if pl.expectedPeerID != "" && pl.expectedPeerID != cm.NodeId {
			expectedPeerID := pl.expectedPeerID
			pl.mu.Unlock()
			logx.Warnf("[relaynode] 控制链路身份与接入公钥不匹配，关闭链路: expected=%.16s got=%.16s", expectedPeerID, cm.NodeId)
			pl.clearStream(sc)
			return
		}
		if wasCounted && pl.peerID != cm.NodeId {
			oldPeerID := pl.peerID
			pl.mu.Unlock()
			logx.Warnf("[relaynode] 控制链路身份发生变化，关闭链路: old=%.16s new=%.16s", oldPeerID, cm.NodeId)
			pl.clearStream(sc)
			return
		}
		pl.peerID = cm.NodeId
		pl.peerAddr = cm.Addr
		pl.peerCert = verifiedCertificate
		if !wasCounted {
			// 在 pl.mu 内完成 owner 计数上升，保证并发 close 不会先 down 后 up。
			pl.owner.relayLinkUp(cm.NodeId)
			pl.countedUp = true
		}
		pl.mu.Unlock()
		if wasCounted {
			pl.owner.relayControlSeen(cm.NodeId)
		}
		if !pl.outbound && !pl.owner.activateInboundLink(pl, cm.NodeId) {
			return
		}
		// 带上本链路的主动拨号地址（accept 侧为空）, 让 owner 能识别「这条正是注册到 index 的链路」,
		// 从而在自动获知 index 真实 NodeID 后回调确认。
		dialAddr := ""
		if pl.outbound {
			dialAddr = pl.addr
		}
		// outbound(主动注册方, 通常是 relay): 若对端(index)在回应里告知了观察到的本端公网地址,
		// 采纳它作为自己的对外地址, 使后续上报给 natNode 的 relay 列表可路由。
		if pl.outbound && cm.ObservedAddr != "" {
			pl.owner.adoptObservedAddr(cm.ObservedAddr)
		}
		// 登记对端 relay 邻居时, inbound(被动接入, 如 index 接受 relay 注册)侧优先用「观察到的
		// 对端公网可路由地址」, 而非对端自报的可能不可路由的 cm.Addr(如 ":9000"); 这样 natNode
		// 向 index 查询 relay 列表时拿到的就是可拨地址。outbound 侧 cm.Addr 即对方公网地址, 直接用。
		registerAddr := cm.Addr
		if !pl.outbound {
			if obs := pl.observedDialAddr(); obs != "" {
				registerAddr = obs
			}
		}
		pl.owner.onPeerHello(cm.NodeId, registerAddr, dialAddr)
		// accept 侧收到 HELLO 后回一个 HELLO, 让对端也获知本端身份与地址,
		// 并把「观察到的对端公网可路由地址」一并告知, 帮助对端修正其对外地址。
		if !pl.outbound {
			reply := &controlMessage{Type: ctrlHello, NodeId: pl.owner.idStr(), Addr: pl.owner.getAddr()}
			if obs := pl.observedDialAddr(); obs != "" {
				reply.ObservedAddr = obs
			}
			reply.IndexSign = pl.owner.selfCertJSON() // 回程 HELLO 也带 indexSign, 供对端离线验签
			_ = pl.send(reply)
		}
		pl.owner.syncHostRoutes(pl)
	case ctrlFind:
		hosts := pl.owner.hostsLocally(cm.Target) || len(pl.owner.transitRouteNextHops(cm.Target, pl.peerIdentity())) > 0
		resp := &controlMessage{Type: ctrlFindResp, ReqID: cm.ReqID, Target: cm.Target, Hosts: hosts}
		if hosts {
			resp.Addr = pl.owner.getAddr()
		}
		_ = pl.send(resp)
	case ctrlFindResp:
		pl.owner.deliverFindResp(pl, cm)
	case ctrlHostRoutes:
		pl.owner.receiveHostRoutes(pl, cm.Routes)
	case ctrlHostWithdraw:
		pl.owner.receiveHostWithdrawals(pl, cm.Withdrawals)
	default:
		logx.Infof("[relaynode] 未知控制消息类型: %s", cm.Type)
	}
}

func (pl *peerLink) setStream(sc *client.StreamClient) {
	pl.mu.Lock()
	pl.sc = sc
	pl.mu.Unlock()
}

func (pl *peerLink) clearStream(sc *client.StreamClient) {
	pl.mu.Lock()
	downPeerID := ""
	cleared := false
	if pl.sc == sc {
		cleared = true
		pl.sc = nil
		if pl.countedUp {
			downPeerID = pl.peerID
			pl.countedUp = false
		}
	}
	pl.mu.Unlock()
	if cleared && !pl.outbound {
		pl.cancel()
	}
	if downPeerID != "" {
		pl.owner.relayLinkDown(downPeerID)
	}
	if cleared && !pl.outbound {
		pl.owner.removeInboundLink(pl)
	}
	sc.Close()
}

func (pl *peerLink) sleep(d time.Duration) bool {
	select {
	case <-pl.ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (pl *peerLink) close() {
	pl.cancel()
	pl.mu.Lock()
	sc := pl.sc
	pl.sc = nil
	downPeerID := ""
	if pl.countedUp {
		downPeerID = pl.peerID
		pl.countedUp = false
	}
	pl.mu.Unlock()
	if downPeerID != "" {
		pl.owner.relayLinkDown(downPeerID)
	}
	if !pl.outbound {
		pl.owner.removeInboundLink(pl)
	}
	if sc != nil {
		sc.Close()
	}
}

func (pl *peerLink) matchesDeny(decision admission.DenyDecision) bool {
	pl.mu.Lock()
	certificate := pl.peerCert
	pl.mu.Unlock()
	return certificateMatchesDeny(certificate, "", decision)
}

func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > peerLinkRedialMax {
		next = peerLinkRedialMax
	}
	return next
}
