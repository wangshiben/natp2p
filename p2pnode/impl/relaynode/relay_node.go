// Package relaynode 实现一个「中继节点」(RelayNode)。
//
// 与 natnode.NATNode 的区别：
//   - NATNode 是 NAT 后的普通节点，所有连接都要经过 relay 中转，自身不接受 TCP 接入。
//   - RelayNode 跑在公网，既是 p2pnode.Node（有身份、有 DHT 路由表、可被查找），
//     又内嵌一个 relay 服务器（networkFrameWork.RelayStarter），为 NAT 节点提供中转，
//     并与其它 RelayNode 建立可重试的控制链路、协作完成跨中继的节点查找与桥接。
//
// 设计要点（对应需求）：
//  1. 接入已实现的 DHTable，做动态查找。
//  2. 区分 NatNode 与 RelayNode：用两张独立 DHTable（natNodes / relayNodes），
//     条目用 RelayNodeEntry / 复用 DHTable.Node 表达。
//  3. 当某节点要连接本 relay 未托管的 nat 节点时，向邻近 relayNode 发 FIND，
//     查到后跨中继桥接；查不到返回错误。
//  4. RelayNode 之间的控制链路可重试（peerLink.manage + DualStream leg 级重连）。
package relaynode

import (
	"bnfs_p2p/DHTable"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/interfaces"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"bnfs_p2p/p2pnode"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var errPeerLinkDown = errors.New("relaynode: 控制链路未建立")

// pendingFind 跟踪一次进行中的跨中继 FIND 请求。
type pendingFind struct {
	target string
	respCh chan findAnswer
}

// findAnswer 是一次 FIND 的应答, 带上「是哪条控制链路回的」, 以便用该链路的可路由地址拨号。
type findAnswer struct {
	cm   *controlMessage
	link *peerLink
}

// RelayNode 是公网中继节点，实现 p2pnode.Node 接口。
type RelayNode struct {
	identity *DHTable.Node
	privKey  *ecdh.PrivateKey
	addr     string // 本 relay 的公网业务监听地址（如 "0.0.0.0:9000" 对外可达地址）

	// 两张独立 DHT：区分 Nat 节点与 Relay 节点（需求 2）。
	natNodes   interfaces.DHTTable // 本 relay 当前托管（已注册）的 NAT 节点
	relayNodes interfaces.DHTTable // 已知的对端 relay 节点

	starter *networkFrameWork.RelayStarter

	mu             sync.RWMutex
	peerLinks      map[string]*peerLink // 主动维持的控制链路, key = 对端 relay 拨号地址
	inboundLinks   []*peerLink          // 对端拨入并被本端接管的控制链路
	peerIDToAddr   map[string]string    // relay NodeId -> 业务地址
	relayAddrIndex map[p2pnode.NodeID][]string

	pendingFinds map[uint64]*pendingFind
	findCounter  atomic.Uint64

	// localLegs 按 ConnectionId 聚合「本地接入的源节点 leg」。
	// 源节点（如 local1）经 dual 传输拨号会产生 KCP+TCP 两条 leg, 同一 ConnectionId
	// 会两次进入 onMissingGroup; 这里把后到的 leg attach 到已建桥的本地 DualStream 上,
	// 避免重复拨向对端 relay、重复建桥导致握手错乱。
	localLegs map[string]*localBridgeEntry

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// localBridgeEntry 跟踪一条已建立跨中继桥接的本地源连接。
type localBridgeEntry struct {
	bridge *networkFrameWork.CrossRelayBridge
}

// NewRelayNode 创建一个中继节点。
//
//	privKey   为 nil 时自动生成；持有私钥即持有节点身份。
//	listenAddr 是 relay 服务器监听地址（如 ":9000"）。
//	publicAddr 是对端用来拨号本 relay 的可达地址（如 "1.2.3.4:9000"）；
//	           为空时回退用 listenAddr，便于本地测试。
func NewRelayNode(privKey *ecdh.PrivateKey, listenAddr, publicAddr string) (*RelayNode, error) {
	if privKey == nil {
		var err error
		privKey, err = crypoto.MakeKeyPair()
		if err != nil {
			return nil, fmt.Errorf("relaynode: 生成密钥对失败: %w", err)
		}
	}

	identity, err := DHTable.NewNodeWithKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("relaynode: 创建节点身份失败: %w", err)
	}

	natNodes, err := DHTable.NewDHTTable(identity.PeerID(), 20)
	if err != nil {
		return nil, fmt.Errorf("relaynode: 创建 NAT 节点 DHT 失败: %w", err)
	}
	relayNodes, err := DHTable.NewDHTTable(identity.PeerID(), 20)
	if err != nil {
		return nil, fmt.Errorf("relaynode: 创建 relay 节点 DHT 失败: %w", err)
	}

	if publicAddr == "" {
		publicAddr = listenAddr
	}

	ctx, cancel := context.WithCancel(context.Background())
	n := &RelayNode{
		identity:       identity,
		privKey:        privKey,
		addr:           publicAddr,
		natNodes:       natNodes,
		relayNodes:     relayNodes,
		starter:        networkFrameWork.NewRelayStarter(listenAddr),
		peerLinks:      make(map[string]*peerLink),
		peerIDToAddr:   make(map[string]string),
		relayAddrIndex: make(map[p2pnode.NodeID][]string),
		pendingFinds:   make(map[uint64]*pendingFind),
		ctx:            ctx,
		cancel:         cancel,
	}

	n.localLegs = make(map[string]*localBridgeEntry)

	// 安装框架回调：注册流建立时登记到 natNodes；业务连接未命中本地 group 时走跨中继逻辑。
	cover := n.starter.Cover()
	cover.SetRegisterHook(n.onRegister)
	cover.SetMissingGroupHandler(n.onMissingGroup)

	return n, nil
}

// ID 返回本节点 NodeID。
func (n *RelayNode) ID() p2pnode.NodeID { return p2pnode.NodeID(n.identity.PeerID()) }

func (n *RelayNode) idStr() string     { return n.identity.PeerID() }
func (n *RelayNode) pubKeyHex() string { return n.identity.Pubkey() }

// controlTargetID 是本 relay 拨向对端 relay 时, 首条 hello 的 Header.NodeId 占位值。
// 取本端 NodeId 即可：对端只用它来确认「不是自己托管的 nat 节点」, 据 RouteName 识别控制链路。
func (n *RelayNode) controlTargetID() string { return n.idStr() }

// Addr 返回本 relay 的公网业务地址。
func (n *RelayNode) Addr() string { return n.addr }

// ExportPrivateKeyHex 返回本节点私钥 hex。
func (n *RelayNode) ExportPrivateKeyHex() string { return crypoto.GetPrivKeyStr(n.privKey) }

// Start 启动内嵌 relay 服务器（阻塞）。应在独立 goroutine 中调用。
// 服务器开始监听后, 即可接受 NAT 节点注册与其它 relay 的控制链路接入。
func (n *RelayNode) Start() {
	n.starter.StartListen()
}

// ConnectPeer 与另一台 relay 建立可重试的控制链路（主动方向）。
// addr 是对端 relay 的公网业务地址。重复调用同一地址是幂等的。
func (n *RelayNode) ConnectPeer(addr string) {
	n.mu.Lock()
	if _, ok := n.peerLinks[addr]; ok {
		n.mu.Unlock()
		return
	}
	pl := startOutboundPeerLink(n, addr)
	n.peerLinks[addr] = pl
	n.mu.Unlock()
	log.Printf("[relaynode] 开始维持到 relay %s 的控制链路", addr)
}

// onRegister 是「新 NAT 节点注册流建立」回调：把它登记进 natNodes DHT（需求 1、2）。
func (n *RelayNode) onRegister(nodeId string) {
	n.natNodes.AddNode(DHTable.NewNodeFromPeerID(nodeId))
	log.Printf("[relaynode] 本地托管的 NAT 节点登记到 natNodes: %.16s", nodeId)
}

// hostsLocally 判断某个 nat 节点是否当前注册在本 relay 上。
func (n *RelayNode) hostsLocally(nodeId string) bool {
	return n.starter.Cover().HasGroup(nodeId)
}

// onPeerHello 在收到对端 relay 的 HELLO 后被调用：登记对端 relay 身份与地址（需求 1、2）。
func (n *RelayNode) onPeerHello(peerID, peerAddr string) {
	if peerID == "" || peerID == n.idStr() {
		return
	}
	n.mu.Lock()
	n.peerIDToAddr[peerID] = peerAddr
	n.relayAddrIndex[p2pnode.NodeID(peerID)] = []string{peerAddr}
	n.mu.Unlock()
	n.relayNodes.AddNode(DHTable.NewNodeFromPeerID(peerID))
	log.Printf("[relaynode] 登记对端 relay: id=%.16s addr=%s", peerID, peerAddr)
}

// deliverFindResp 把 FIND_RESP 投递给等待中的发起者, 附带回应的控制链路。
func (n *RelayNode) deliverFindResp(pl *peerLink, cm *controlMessage) {
	n.mu.Lock()
	pf := n.pendingFinds[cm.ReqID]
	n.mu.Unlock()
	if pf == nil {
		return
	}
	select {
	case pf.respCh <- findAnswer{cm: cm, link: pl}:
	default:
	}
}

// onMissingGroup 是框架回调：业务连接寻址的目标在本地没有 group 时进入这里。
//
// 两种情况：
//  1. firstMsg.Header.RouteName == RelayControlRoute：对端 relay 拨入的控制链路，
//     接管为一条 accept 侧 peerLink。
//  2. 否则：某节点（如 local1）想连接一个本 relay 未托管的 nat 节点。
//     向邻近 relay 发 FIND；命中则跨中继桥接，否则返回错误（需求 3）。
//
// 返回 nil 表示已接管 stream 生命周期；返回 error 表示处理失败（框架会关闭 stream）。
func (n *RelayNode) onMissingGroup(stream network.Stream, firstMsg *network.Message) error {
	if firstMsg.Header.RouteName == RelayControlRoute {
		return n.acceptControlLink(stream, firstMsg)
	}
	return n.findAndBridge(stream, firstMsg)
}

// acceptControlLink 接管对端 relay 拨入的控制链路。
func (n *RelayNode) acceptControlLink(stream network.Stream, firstMsg *network.Message) error {
	// 绑定对端身份：用 hello payload（对端公钥）推导其 NodeId，与现有 relay 接入流程一致。
	hash := sha256.Sum256(firstMsg.Payload)
	peerNodeId := hex.EncodeToString(hash[:])
	if !networkFrameWork.SetStreamIdentity(stream, peerNodeId, firstMsg.Header.ConnectionId) {
		return errors.New("relaynode: 控制链路 SetStreamIdentity 失败")
	}
	sc := client.NewStreamClient(stream)

	pl := &peerLink{owner: n, outbound: false, ctx: n.ctx, cancel: func() {}}
	// 记录对端实际连入的 IP, 供 dialHostAddr 拼出可路由的桥接地址
	// （对端 HELLO 自报的 host 可能是 ":9000" 等不可路由占位）。
	if tcp := networkFrameWork.TCPStreamOf(stream); tcp != nil && tcp.RawConn() != nil {
		if host, _, err := net.SplitHostPort(tcp.RawConn().RemoteAddr().String()); err == nil {
			pl.observedRemoteIP = host
		}
	}
	n.mu.Lock()
	n.inboundLinks = append(n.inboundLinks, pl)
	n.mu.Unlock()
	pl.adoptInbound(sc)
	log.Printf("[relaynode] 控制链路已建立(被动): peerNodeId=%.16s remoteIP=%s", peerNodeId, pl.observedRemoteIP)
	return nil
}

// findAndBridge 处理「连接本地未托管 nat 节点」的请求：
// 向所有控制链路并发 FIND，命中后拨向托管该节点的 relay 并把两条流桥接起来。
//
// 源节点经 dual 传输拨号会对同一 ConnectionId 产生两条 leg（KCP/TCP）。
// 第一条 leg 负责真正的 FIND + 拨号 + 建桥；后到的同 ConnectionId leg 只 attach 到
// 已建桥的本地 DualStream 上，不再重复拨号建桥。
func (n *RelayNode) findAndBridge(stream network.Stream, firstMsg *network.Message) error {
	target := firstMsg.Header.NodeId
	connID := firstMsg.Header.ConnectionId

	// 同一 connID 可能有多条 leg 进入（dual 拨号）。只用第一条建桥, 其余关闭。
	// natnode 现以 TCP 单 leg 连 relay, 通常只有一条。
	n.mu.Lock()
	entry := n.localLegs[connID]
	if entry != nil {
		n.mu.Unlock()
		_ = stream.Close() // 已有桥接, 多余的 leg 关闭
		return nil
	}
	entry = &localBridgeEntry{}
	n.localLegs[connID] = entry
	n.mu.Unlock()

	cleanup := func() {
		n.mu.Lock()
		delete(n.localLegs, connID)
		n.mu.Unlock()
		_ = stream.Close()
	}

	hostLink, err := n.findHostRelay(target)
	if err != nil {
		cleanup()
		return fmt.Errorf("relaynode: 查找 nat 节点 %.16s 失败: %w", target, err)
	}
	// 用控制链路的可路由地址桥接拨号, 而不是对端自报的 Addr（可能是 ":9000" 等不可路由占位,
	// 会导致 relay 误拨到自身形成环路 —— 正是本次测试 connect 超时的根因）。
	hostAddr := hostLink.dialHostAddr()
	if hostAddr == "" {
		cleanup()
		return fmt.Errorf("relaynode: 无法确定托管 relay 的可路由地址 (target=%.16s)", target)
	}

	// 裸字节级跨中继桥接：relay 退化成哑字节管道, 不重写 MessageId / 不组包 / 不 ACK,
	// local1↔local2 端到端可靠性完全自洽。透传 local1 的 hello（含公钥）与原始 connID。
	br := networkFrameWork.NewCrossRelayBridge(n.ctx, hostAddr, target, string(firstMsg.Payload), connID)
	if err := br.SpliceLeg(stream); err != nil {
		cleanup()
		return fmt.Errorf("relaynode: 建立裸字节桥接失败: %w", err)
	}
	n.mu.Lock()
	entry.bridge = br
	n.mu.Unlock()
	log.Printf("[relaynode] 跨中继桥接建立: target=%.16s via relay=%s connId=%s leg=%s",
		target, hostAddr, connID, networkFrameWork.LegTransport(stream))
	return nil
}

// findHostRelay 向所有已建立的控制链路并发 FIND, 返回首个声称托管 target 的「控制链路」。
// 调用方用该链路的 dialHostAddr() 得到可路由的桥接地址（而非对端自报的可能不可路由的 Addr）。
// 全部未命中或超时则返回错误（需求 3）。
func (n *RelayNode) findHostRelay(target string) (*peerLink, error) {
	n.mu.RLock()
	links := make([]*peerLink, 0, len(n.peerLinks)+len(n.inboundLinks))
	for _, pl := range n.peerLinks {
		links = append(links, pl)
	}
	links = append(links, n.inboundLinks...)
	n.mu.RUnlock()

	if len(links) == 0 {
		return nil, errors.New("无可用的对端 relay 控制链路")
	}

	reqID := n.findCounter.Add(1)
	pf := &pendingFind{target: target, respCh: make(chan findAnswer, len(links))}
	n.mu.Lock()
	n.pendingFinds[reqID] = pf
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.pendingFinds, reqID)
		n.mu.Unlock()
	}()

	find := &controlMessage{Type: ctrlFind, ReqID: reqID, Target: target}
	for _, pl := range links {
		_ = pl.send(find)
	}

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for i := 0; i < len(links); i++ {
		select {
		case <-n.ctx.Done():
			return nil, errors.New("relaynode 已关闭")
		case <-deadline.C:
			return nil, errors.New("FIND 超时, 无 relay 托管目标节点")
		case ans := <-pf.respCh:
			if ans.cm.Hosts {
				return ans.link, nil
			}
		}
	}
	return nil, errors.New("没有 relay 托管目标 nat 节点")
}

// =============================================================================
// p2pnode.Node 接口实现
// =============================================================================

// OnConnection 对 RelayNode 暂无入站业务连接回调语义（relay 不是业务对端），保留空实现以满足接口。
func (n *RelayNode) OnConnection(cb p2pnode.OnConnectionCallback) {}

// Connect 与目标 relay 建立控制链路。target 必须是一个已知的 relay 节点。
// 返回的 Connection 仅用于表征「链路已发起」；RelayNode 的业务面是中转, 不在此连接上收发业务消息。
func (n *RelayNode) Connect(ctx context.Context, target p2pnode.NodeID) (p2pnode.Connection, error) {
	n.mu.RLock()
	addr := n.peerIDToAddr[string(target)]
	n.mu.RUnlock()
	if addr == "" {
		return nil, fmt.Errorf("relaynode: 未知的 relay 节点 %.16s, 请先用 ConnectPeer(addr) 建立链路", target)
	}
	n.ConnectPeer(addr)
	return nil, errors.New("relaynode: relay 节点间为控制链路, 无业务 Connection")
}

// Listen 对 RelayNode 而言等价于启动内嵌 relay 服务器（阻塞）。
// addr 被忽略（监听地址在 NewRelayNode 时已固定）, 仅为满足接口签名。
func (n *RelayNode) Listen(ctx context.Context, addr string) error {
	go func() {
		<-ctx.Done()
		n.Close()
	}()
	n.Start()
	return nil
}

// Broadcast 对 RelayNode 暂不支持业务广播（relay 不是业务节点）。
func (n *RelayNode) Broadcast(ctx context.Context, msg *p2pnode.Message) error {
	return errors.New("relaynode: 不支持业务广播")
}

// Neighbors 返回已知的 relay 邻居与本地托管的 nat 节点（合并两张 DHT, 按 XOR 距离升序）。
func (n *RelayNode) Neighbors() []p2pnode.PeerInfo {
	return n.collect(n.relayNodes, n.relayAddrIndexSnapshot())
}

// RelayNeighbors 仅返回已知的对端 relay 节点。
func (n *RelayNode) RelayNeighbors() []p2pnode.PeerInfo {
	return n.collect(n.relayNodes, n.relayAddrIndexSnapshot())
}

// HostedNatNodes 返回本 relay 当前托管的 nat 节点。
func (n *RelayNode) HostedNatNodes() []p2pnode.PeerInfo {
	return n.collect(n.natNodes, nil)
}

// ClosestPeers 返回 relayNodes 中离 target 最近的 k 个 relay 节点。
func (n *RelayNode) ClosestPeers(target p2pnode.NodeID, k int) []p2pnode.PeerInfo {
	closest := n.relayNodes.FindClosest(string(target), k)
	idx := n.relayAddrIndexSnapshot()
	result := make([]p2pnode.PeerInfo, 0, len(closest))
	for _, node := range closest {
		id := p2pnode.NodeID(node.PeerID())
		if id == n.ID() {
			continue
		}
		result = append(result, p2pnode.PeerInfo{
			ID:        id,
			Addresses: idx[id],
			LastSeen:  time.Unix(node.LastCalled(), 0),
		})
	}
	return result
}

// collect 把一张 DHT 的所有节点收敛为 PeerInfo 列表。
func (n *RelayNode) collect(table interfaces.DHTTable, addrIdx map[p2pnode.NodeID][]p2pnode.PeerAddr) []p2pnode.PeerInfo {
	buckets := table.GetBuckets()
	seen := make(map[p2pnode.NodeID]bool)
	var result []p2pnode.PeerInfo
	for _, b := range buckets {
		bucket, ok := b.(interface{ GetNodes() []interfaces.Node })
		if !ok {
			continue
		}
		for _, node := range bucket.GetNodes() {
			id := p2pnode.NodeID(node.PeerID())
			if id == n.ID() || seen[id] {
				continue
			}
			seen[id] = true
			info := p2pnode.PeerInfo{ID: id, LastSeen: time.Unix(node.LastCalled(), 0)}
			if addrIdx != nil {
				info.Addresses = addrIdx[id]
			}
			result = append(result, info)
		}
	}
	return result
}

func (n *RelayNode) relayAddrIndexSnapshot() map[p2pnode.NodeID][]p2pnode.PeerAddr {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make(map[p2pnode.NodeID][]p2pnode.PeerAddr, len(n.relayAddrIndex))
	for id, addrs := range n.relayAddrIndex {
		pa := make([]p2pnode.PeerAddr, len(addrs))
		for i, a := range addrs {
			pa[i] = p2pnode.PeerAddr{Relay: a}
		}
		out[id] = pa
	}
	return out
}

// Close 关闭中继节点：停止所有控制链路与内嵌 relay 服务器。
func (n *RelayNode) Close() error {
	n.closeOnce.Do(func() {
		n.cancel()
		n.mu.Lock()
		for _, pl := range n.peerLinks {
			pl.close()
		}
		for _, pl := range n.inboundLinks {
			pl.close()
		}
		n.peerLinks = nil
		n.inboundLinks = nil
		n.mu.Unlock()
		n.starter.Close()
	})
	return nil
}

// 确保 RelayNode 实现 p2pnode.Node 接口。
var _ p2pnode.Node = (*RelayNode)(nil)
