package relaynode

import (
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"context"
	"log"
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

	mu       sync.Mutex
	sc       *client.StreamClient
	peerID   string // 对端 relay NodeId（HELLO 后获知）
	peerAddr string // 对端 relay 公网业务地址（HELLO 后获知）

	ctx    context.Context
	cancel context.CancelFunc
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
			log.Printf("[relaynode] 拨号对端 relay %s 失败, %v 后重试: %v", pl.addr, backoff, err)
			if !pl.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		pl.setStream(sc)
		// 发送 HELLO，交换身份。
		if err := pl.sendHello(); err != nil {
			log.Printf("[relaynode] 向 %s 发送 HELLO 失败: %v", pl.addr, err)
			sc.Close()
			if !pl.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		log.Printf("[relaynode] 控制链路已建立(主动): peer=%s", pl.addr)
		backoff = peerLinkRedialInitial // 成功后重置退避

		// serve 阻塞直到链路断开。
		pl.serve(sc)
		log.Printf("[relaynode] 控制链路断开(主动), 准备重连: peer=%s", pl.addr)

		if !pl.sleep(backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// dial 建立到对端 relay 的底层控制流。targetNodeId 用对端地址占位即可——
// 对端没有对应该 ID 的 group, 会落进 MissingGroupHandler, 据 RouteName 识别为控制链路。
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
	cm := &controlMessage{Type: ctrlHello, NodeId: pl.owner.idStr(), Addr: pl.owner.addr}
	return pl.send(cm)
}

// send 在控制链路上发送一条控制消息。
func (pl *peerLink) send(cm *controlMessage) error {
	pl.mu.Lock()
	sc := pl.sc
	pl.mu.Unlock()
	if sc == nil {
		return errPeerLinkDown
	}
	return sc.SendMessage(pl.ctx, encodeControl(cm, pl.owner.idStr(), ""))
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
			log.Printf("[relaynode] 解码控制消息失败: %v", err)
			continue
		}
		pl.dispatch(sc, cm)
	}
}

// dispatch 处理单条控制消息。
func (pl *peerLink) dispatch(sc *client.StreamClient, cm *controlMessage) {
	switch cm.Type {
	case ctrlHello:
		pl.mu.Lock()
		pl.peerID = cm.NodeId
		pl.peerAddr = cm.Addr
		pl.mu.Unlock()
		pl.owner.onPeerHello(cm.NodeId, cm.Addr)
		// accept 侧收到 HELLO 后回一个 HELLO, 让对端也获知本端身份与地址。
		if !pl.outbound {
			_ = pl.send(&controlMessage{Type: ctrlHello, NodeId: pl.owner.idStr(), Addr: pl.owner.addr})
		}
	case ctrlFind:
		hosts := pl.owner.hostsLocally(cm.Target)
		resp := &controlMessage{Type: ctrlFindResp, ReqID: cm.ReqID, Target: cm.Target, Hosts: hosts}
		if hosts {
			resp.Addr = pl.owner.addr
		}
		_ = pl.send(resp)
	case ctrlFindResp:
		pl.owner.deliverFindResp(cm)
	default:
		log.Printf("[relaynode] 未知控制消息类型: %s", cm.Type)
	}
}

func (pl *peerLink) setStream(sc *client.StreamClient) {
	pl.mu.Lock()
	pl.sc = sc
	pl.mu.Unlock()
}

func (pl *peerLink) clearStream(sc *client.StreamClient) {
	pl.mu.Lock()
	if pl.sc == sc {
		pl.sc = nil
	}
	pl.mu.Unlock()
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
	pl.mu.Unlock()
	if sc != nil {
		sc.Close()
	}
}

func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > peerLinkRedialMax {
		next = peerLinkRedialMax
	}
	return next
}
