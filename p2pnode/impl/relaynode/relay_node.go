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
	"bnfs_p2p/admission"
	"bnfs_p2p/billingcontrol"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/interfaces"
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/relayquery"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
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

type inboundPeerSession struct {
	key        string
	generation uint64
}

type hostRouteBroadcastEvent struct {
	message      *controlMessage
	exceptPeerID string
}

// RelayNode 是公网中继节点，实现 p2pnode.Node 接口。
type RelayNode struct {
	identity          *DHTable.Node
	privKey           *ecdh.PrivateKey
	billingPrivateKey *ecdh.PrivateKey
	addr              string // 本 relay 的公网业务监听地址（如 "0.0.0.0:9000" 对外可达地址）

	// 两张独立 DHT：区分 Nat 节点与 Relay 节点（需求 2）。
	natNodes   interfaces.DHTTable // 本 relay 当前托管（已注册）的 NAT 节点
	relayNodes interfaces.DHTTable // 已知的对端 relay 节点

	starter *networkFrameWork.RelayStarter

	mu                   sync.RWMutex
	peerLinks            map[string]*peerLink // 主动维持的控制链路, key = 对端 relay 拨号地址
	inboundLinks         []*peerLink          // 对端拨入并被本端接管的控制链路
	inboundByPeerID      map[string]inboundPeerSession
	inboundSessionGens   map[string]uint64 // session tombstone 保留到 Close，阻止旧 dual leg 迟到夺权
	inboundCounter       atomic.Uint64
	peerIDToAddr         map[string]string // relay NodeId -> 业务地址
	relayAddrIndex       map[p2pnode.NodeID][]string
	relayOnlineSince     map[string]time.Time
	relayLastControlSeen map[string]time.Time
	relayActiveLinks     map[string]int
	// hostedNatAddr 记录本 relay 托管的每个 NAT 节点的来源地址（其底层连接远端 IP:port）,
	// 用于状态打印 / 排障, 判断"托管NAT节点"里每个节点的托管来源。
	hostedNatAddr        map[string]string // NAT 节点 NodeId -> 远端地址
	hostRoutes           map[string]map[string]hostRouteRecord
	hostRouteMultipath   map[string]bool
	hostRouteSequence    map[string]uint64
	hostRouteIncarnation string
	hostRouteCursor      atomic.Uint64
	// hostRouteBroadcastQueue 把托管路由的本地状态更新与慢控制链路发送解耦。
	// 单 worker 保持 offline/online 等事件顺序；固定容量避免异常邻居造成 goroutine/
	// 内存无界累计。队列满时只丢弃可由租约续期最终收敛的软状态广播。
	hostRouteBroadcastQueue   chan hostRouteBroadcastEvent
	hostRouteBroadcastDone    chan struct{}
	hostRouteBroadcastDropped atomic.Uint64
	hostRouteBroadcastSend    func(context.Context, *peerLink, *controlMessage) error

	pendingFinds map[uint64]*pendingFind
	findCounter  atomic.Uint64

	// localLegs 按 ConnectionId 聚合「本地接入的源节点 leg」。
	// 源节点（如 local1）经 dual 传输拨号会产生 KCP+TCP 两条 leg, 同一 ConnectionId
	// 会两次进入 onMissingGroup; 这里把后到的 leg attach 到已建桥的本地 DualStream 上,
	// 避免重复拨向对端 relay、重复建桥导致握手错乱。
	localLegs map[string]*localBridgeEntry

	// bridgePools 跨中继桥接连接池(Phase B+): key = hostAddr(对端 relay 可路由地址)。
	bridgePools map[string]*relayPeerPool

	// stripedLegs 条带化接入侧归并(F3): key = connID。
	// 一条条带化逻辑连接的 M 条 leg 分别从 M 条物理连接的 Accept 出来，按 connID 聚齐 legCount
	// 条后组装成一条 LogicalConn 交下游一次。
	stripedLegs          map[string]*stripedAccept
	stripedAcceptTimeout time.Duration

	// bridgeWidth 是桥接出站默认条带化宽度（每条逻辑连接用几条物理 leg）。
	// 0/1 = 不条带化（模式 A，默认）；>1 = 条带化（模式 B）。F4 将据流量压力动态调整；
	// 在此之前可由测试/配置显式设定。用 atomic 读写避免与 doBridge 竞争。
	bridgeWidth atomic.Int32

	// forwardHookConfig 转发 hook 配置（可选）
	forwardHookConfig *ForwardHookConfig

	// admission 准入配置（可选）。nil 或 Mode=AdmissionOff 时准入握手完全不启用,
	// 既有行为零变更。见 admission_link.go。
	admission *AdmissionConfig

	// accounts 被托管 NAT 节点的角色/上行账户表（准入通过后落 Role, forward hook 累加上行）。
	// 见 admission_register.go。
	accounts *accountStore

	// settleLoopOnce 保证周期结算循环只启动一次（SetAdmission 可能被多次调用）。
	settleLoopOnce sync.Once

	// billingPipeline 是 1 MiB 窗口双签凭证、durable waitSubmit 与 CA FIFO 提交流水线。
	billingPipeline    *relayBillingPipeline
	billingPipelineErr error
	billingQueuePath   string

	// reservedPairs 是已退役连接保证金实现的遗留内存状态；当前业务角色门和双签结算均不读取。
	reservedPairs sync.Map // map[string]*depositReservation

	// indexAddr 是本 relay 注册到的 index 地址（RegisterToIndex 设置, 可空）。
	// onIndexRegistered 在与该 index 完成 HELLO、自动获知其真实 NodeID 后回调一次,
	// 供上层（如 cmd）打印「已注册到 index: id=… addr=…」确认。
	indexAddr         string
	onIndexRegistered func(indexID, indexAddr string)
	indexAckedOnce    sync.Once
	startedAt         time.Time

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// localBridgeEntry 跟踪一条已建立跨中继桥接的本地源连接。
//
// dual 拨号会对同一 connID 产生 KCP+TCP 两条 leg。relay 侧**先到先建桥**：
// 哪条 leg 先到就用它建桥，后到的同 connID leg 一律 splice 成 failover。
// 不在 relay 侧偏好 KCP —— relay 只能观测到"收到 KCP 首帧"，无法区分 KCP 双向可用
// 还是仅出方向可用而回程已死（家庭 NAT）；只有客户端等到 ACK 才知道 KCP 是否真可用。
// 故 KCP 优先决策全部下放到客户端(kcpPriorityWindow)，relay 侧只做先到先得 + failover。
// 见记忆 natclient-relay-kcp-preferred-bug。
type localBridgeEntry struct {
	bridge   *networkFrameWork.CrossRelayBridge
	bridged  bool          // 是否已用某条 leg 建成桥接
	bridging bool          // 是否有某条 leg 正在建桥（防并发双发同时 doBridge）
	kcpReady chan struct{} // 建桥完成信号（并发到达的另一条 leg 监听后转 failover）
}

// stripedAccept 跟踪接入侧一条条带化逻辑连接的 leg 归并状态（F3）。
// M 条 leg 从 M 条不同物理连接的 Accept 陆续到达，聚齐 want 条后组装成一条 LogicalConn。
type stripedAccept struct {
	want     int
	attempt  uint64
	legs     map[int]*networkFrameWork.MuxStream
	target   string
	pubKey   string
	flags    uint8
	done     chan struct{}
	doneOnce sync.Once
}

const defaultStripedAcceptTimeout = 10 * time.Second

// NewRelayNode 创建一个中继节点。
//
//	privKey   为 nil 时自动生成；持有私钥即持有节点身份。
//	listenAddr 是 relay 服务器监听地址（如 ":9000"）。
//	publicAddr 是对端用来拨号本 relay 的可达地址（如 "203.0.113.10:9000"）；
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
		identity:                identity,
		privKey:                 privKey,
		billingPrivateKey:       privKey,
		addr:                    publicAddr,
		natNodes:                natNodes,
		relayNodes:              relayNodes,
		starter:                 networkFrameWork.NewRelayStarter(listenAddr),
		peerLinks:               make(map[string]*peerLink),
		inboundByPeerID:         make(map[string]inboundPeerSession),
		inboundSessionGens:      make(map[string]uint64),
		peerIDToAddr:            make(map[string]string),
		relayAddrIndex:          make(map[p2pnode.NodeID][]string),
		relayOnlineSince:        make(map[string]time.Time),
		relayLastControlSeen:    make(map[string]time.Time),
		relayActiveLinks:        make(map[string]int),
		pendingFinds:            make(map[uint64]*pendingFind),
		hostedNatAddr:           make(map[string]string),
		hostRoutes:              make(map[string]map[string]hostRouteRecord),
		hostRouteMultipath:      make(map[string]bool),
		hostRouteSequence:       make(map[string]uint64),
		hostRouteIncarnation:    uuid.New().String(),
		hostRouteBroadcastQueue: make(chan hostRouteBroadcastEvent, hostRouteBroadcastQueueCapacity),
		hostRouteBroadcastDone:  make(chan struct{}),
		ctx:                     ctx,
		cancel:                  cancel,
		startedAt:               time.Now(),
	}
	n.hostRouteBroadcastSend = func(ctx context.Context, link *peerLink, message *controlMessage) error {
		return link.sendContext(ctx, message)
	}

	n.localLegs = make(map[string]*localBridgeEntry)
	n.bridgePools = make(map[string]*relayPeerPool)
	n.stripedLegs = make(map[string]*stripedAccept)
	n.accounts = newAccountStore()

	// 安装框架回调：注册流建立时登记到 natNodes；业务连接未命中本地 group 时走跨中继逻辑。
	cover := n.starter.Cover()
	cover.SetRegisterHook(n.onRegister)
	cover.SetUnregisterHook(n.onUnregister)
	cover.SetMissingGroupHandler(n.onMissingGroup)
	go n.runHostRouteBroadcasts()
	go n.maintainHostRoutes()

	return n, nil
}

// ID 返回本节点 NodeID。
func (n *RelayNode) ID() p2pnode.NodeID { return p2pnode.NodeID(n.identity.PeerID()) }

func (n *RelayNode) idStr() string     { return n.identity.PeerID() }
func (n *RelayNode) pubKeyHex() string { return n.identity.Pubkey() }

// PubKeyHex 返回本 relay 公钥 hex（向 CA 申请 indexSign 时作为 subject 公钥）。
func (n *RelayNode) PubKeyHex() string { return n.identity.Pubkey() }

// controlTargetID 是本 relay 拨向对端 relay 时, 首条 hello 的 Header.NodeId 占位值。
// 取本端 NodeId 即可：对端只用它来确认「不是自己托管的 nat 节点」, 据 RouteName 识别控制链路。
func (n *RelayNode) controlTargetID() string { return n.idStr() }

// Addr 返回本 relay 的公网业务地址。
func (n *RelayNode) Addr() string { return n.getAddr() }

// getAddr 并发安全地读取本 relay 当前对外地址。
func (n *RelayNode) getAddr() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.addr
}

// adoptObservedAddr 采纳「对端(如 index)观察到的本端公网可路由地址」作为自己的对外地址。
//
// 仅当当前对外地址不可路由(host 为空 / 0.0.0.0 等占位, 典型如启动时没配 -public 而自报 ":9000")
// 时才覆盖; 若本端已显式配置了可路由的 -public, 则尊重既有配置不动。
// 这样 relay 上报给 natNode 的 relay 列表地址是可拨的, natNode 不必回退到 index。
func (n *RelayNode) adoptObservedAddr(observed string) {
	if observed == "" {
		return
	}
	n.mu.Lock()
	old := n.addr
	if isRoutableAddr(old) {
		n.mu.Unlock()
		return
	}
	n.addr = observed
	n.mu.Unlock()
	logx.Infof("[relaynode] 采纳 index 观察到的对外地址: %s -> %s", old, observed)
}

// isRoutableAddr 粗略判断地址的 host 部分是否可路由(非空、非通配 0.0.0.0/::)。
func isRoutableAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return false
	}
	return true
}

// ExportPrivateKeyHex 返回本节点私钥 hex。
func (n *RelayNode) ExportPrivateKeyHex() string { return crypoto.GetPrivKeyStr(n.privKey) }

// SetForwardHook 设置转发 hook 配置。
// 必须在 Start() 之前调用，否则不生效。
// 配置会下沉到底层 TransportCover，由它在新建 StreamGroup 时注入转发 pump。
func (n *RelayNode) SetForwardHook(config *ForwardHookConfig) {
	n.mu.Lock()
	n.forwardHookConfig = config
	n.mu.Unlock()
	if n.starter != nil {
		n.starter.Cover().SetForwardHook(config)
	}
}

// SetBillingQueuePath 指定双签凭证 waitSubmit 的持久文件。必须在 SetAdmission 之前调用。
// 生产部署应为每个稳定 Relay 身份配置独立路径，并把对应私钥一并持久化。
func (n *RelayNode) SetBillingQueuePath(path string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.billingPipeline != nil || n.billingPipelineErr != nil {
		return errors.New("relaynode: billing queue path must be set before admission")
	}
	n.billingQueuePath = path
	return nil
}

// SetBillingPrivateKey 配置独立于 Relay 节点身份私钥的扣费签名私钥。
// 必须在 SetAdmission 之前调用；旧证书无需调用。
func (n *RelayNode) SetBillingPrivateKey(privateKey *ecdh.PrivateKey) error {
	if privateKey == nil {
		return errors.New("relaynode: billing private key is nil")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.billingPipeline != nil || n.billingPipelineErr != nil {
		return errors.New("relaynode: billing private key must be set before admission")
	}
	n.billingPrivateKey = privateKey
	return nil
}

func (n *RelayNode) billingPublicKeyHex() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return hex.EncodeToString(n.billingPrivateKey.PublicKey().Bytes())
}

func (n *RelayNode) billingPublicKeyForWire() string {
	config := n.admissionConfig()
	if config == nil || config.SelfCert == nil || config.SelfCert.Cert.AuthorizationID == "" {
		return ""
	}
	return n.billingPublicKeyHex()
}

// BuildNodeAuthorizationRequest 使用 Relay 身份私钥与独立扣费私钥共同签署 CA 授权请求。
func (n *RelayNode) BuildNodeAuthorizationRequest(
	billingPrivateKey *ecdh.PrivateKey,
	ttl time.Duration,
) (admission.NodeAuthorizationRequest, error) {
	return admission.NewNodeAuthorizationRequest(
		n.privKey, billingPrivateKey, admission.RoleRelay, ttl,
	)
}

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
	logx.Infof("[relaynode] 开始维持到 relay %s 的控制链路", addr)
}

// RegisterToIndex 让本 relay 启动后主动向 index 节点注册成为其邻居。
//
// index 本质是一台没有上级的 RelayNode, 因此「向 index 注册」= 与 index 建立一条可重试的
// 控制链路（ConnectPeer）。链路建立后双方经 HELLO 互相登记进各自的 relayNodes DHT,
// 之后 NAT 节点查询 index 即可在 relay 列表中看到本 relay; 跨中继 FIND 也经此链路转发。
//
// 调用方只需提供 index 的【地址】——index 的真实 NodeID 会在 HELLO 握手后自动获知,
// 无需手填。onRegistered 可选, 在首次与该 index 完成 HELLO（拿到其真实 NodeID）后回调一次,
// 便于上层打印「已注册到 index: id=… addr=…」之类的确认信息; 不需要可传 nil。
// indexAddr 为空则不做任何事。重复调用同一地址幂等。
func (n *RelayNode) RegisterToIndex(indexAddr string, onRegistered func(indexID, indexAddr string)) {
	if indexAddr == "" {
		return
	}
	n.mu.Lock()
	n.indexAddr = indexAddr
	n.onIndexRegistered = onRegistered
	n.mu.Unlock()
	logx.Infof("[relaynode] 向 index 注册(建控制链路, ID 将在 HELLO 后自动获知): %s", indexAddr)
	n.ConnectPeer(indexAddr)
}

// onRegister 是「新 NAT 节点注册流建立」回调：把它登记进 natNodes DHT（需求 1、2）,
// 并记录它的来源地址（底层连接远端 IP:port）, 便于状态打印时展示托管来源。
func (n *RelayNode) onRegister(nodeId, remoteAddr string) {
	n.natNodes.AddNode(DHTable.NewNodeFromPeerID(nodeId))
	n.mu.Lock()
	n.hostedNatAddr[nodeId] = remoteAddr
	n.mu.Unlock()
	n.publishLocalHostRoute(nodeId, true)
	logx.Infof("[relaynode] 本地托管的 NAT 节点登记到 natNodes: %.16s 来源=%s", nodeId, remoteAddr)
}

// onUnregister 在 TransportCover 已 compare-delete 当前注册组后清理 Relay 侧托管索引。
// 账户与 durable 计费状态不在这里强删，避免丢失尚未结算的安全状态。
func (n *RelayNode) onUnregister(nodeId string) {
	n.natNodes.Remove(nodeId)
	n.mu.Lock()
	delete(n.hostedNatAddr, nodeId)
	n.mu.Unlock()
	n.publishLocalHostRoute(nodeId, false)
	logx.Infof("[relaynode] 已回收离线 NAT 节点托管状态: %.16s", nodeId)
}

// HostedNatInfo 描述本 relay 托管的一个 NAT 节点的状态信息。
type HostedNatInfo struct {
	NodeID     string // 完整 NodeId
	RemoteAddr string // 注册时底层连接的远端地址（托管来源 IP:port）; 可能为空(老连接)
}

// HostedNatNodesDetailed 返回本 relay 当前托管的 NAT 节点明细（含来源地址）, 供状态打印。
func (n *RelayNode) HostedNatNodesDetailed() []HostedNatInfo {
	hosted := n.HostedNatNodes() // 以 DHT 为准（真实托管集合）
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]HostedNatInfo, 0, len(hosted))
	for _, p := range hosted {
		out = append(out, HostedNatInfo{
			NodeID:     string(p.ID),
			RemoteAddr: n.hostedNatAddr[string(p.ID)],
		})
	}
	return out
}

// hostsLocally 判断某个 nat 节点是否当前注册在本 relay 上。
func (n *RelayNode) hostsLocally(nodeId string) bool {
	return n.starter.Cover().HasGroup(nodeId)
}

// TerminateHostedConnection 让托管某 server 节点(nodeId)的 relay 拆掉其一条业务连接(connID)。
// 这是「连接终止 server 也能参与」的 relay 侧能力：server 判定某入站连接为滥用后，
// 经其 nat→relay 控制通道请求本方法（控制通道 wire 信号为后续增强，见 BILLING 报告）。
func (n *RelayNode) TerminateHostedConnection(nodeId, connID string) error {
	return n.starter.Cover().CloseHostedConnection(nodeId, connID)
}

// onPeerHello 在收到对端 relay 的 HELLO 后被调用：登记对端 relay 身份与地址（需求 1、2）。
// dialAddr 是本端主动拨号该对端的地址（被动接入链路为空）, 用于识别「这条正是注册到 index
// 的链路」, 进而在自动获知 index 真实 NodeID 后回调确认。
func (n *RelayNode) onPeerHello(peerID, peerAddr, dialAddr string) {
	if peerID == "" || peerID == n.idStr() {
		return
	}
	var replacedPeerIDs []string
	n.mu.Lock()
	if peerAddr != "" {
		for knownPeerID, knownAddr := range n.peerIDToAddr {
			if knownPeerID == peerID || knownAddr != peerAddr {
				continue
			}
			replacedPeerIDs = append(replacedPeerIDs, knownPeerID)
			delete(n.peerIDToAddr, knownPeerID)
			delete(n.relayAddrIndex, p2pnode.NodeID(knownPeerID))
			delete(n.relayOnlineSince, knownPeerID)
			delete(n.relayLastControlSeen, knownPeerID)
			delete(n.relayActiveLinks, knownPeerID)
		}
	}
	n.peerIDToAddr[peerID] = peerAddr
	n.relayAddrIndex[p2pnode.NodeID(peerID)] = []string{peerAddr}
	isIndexLink := dialAddr != "" && dialAddr == n.indexAddr
	cb := n.onIndexRegistered
	n.mu.Unlock()
	for _, replacedPeerID := range replacedPeerIDs {
		n.relayNodes.Remove(replacedPeerID)
		logx.Infof("[relaynode] Relay 地址身份已更新: addr=%s old=%.16s new=%.16s", peerAddr, replacedPeerID, peerID)
	}
	n.relayNodes.AddNode(DHTable.NewNodeFromPeerID(peerID))
	n.relayNodes.Touch(peerID, time.Now())
	logx.Infof("[relaynode] 登记对端 relay: id=%.16s addr=%s", peerID, peerAddr)

	// 这条链路就是注册到 index 的那条：index 的真实 NodeID 现已自动获知, 回调确认一次。
	if isIndexLink {
		logx.Infof("[relaynode] 已注册到 index(自动获知其 ID): id=%.16s addr=%s", peerID, dialAddr)
		if cb != nil {
			indexAddr := dialAddr
			n.indexAckedOnce.Do(func() { cb(peerID, indexAddr) })
		}
	}
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
	if firstMsg.Header.RouteName == RelayBridgeMuxRoute {
		return n.acceptBridgeMux(stream, firstMsg)
	}
	if firstMsg.Header.RouteName == relayquery.Route {
		return n.answerRelayQuery(stream, firstMsg)
	}
	if firstMsg.Header.RouteName == billingcontrol.Route {
		n.mu.RLock()
		pipeline := n.billingPipeline
		pipelineErr := n.billingPipelineErr
		n.mu.RUnlock()
		if pipelineErr != nil {
			return pipelineErr
		}
		if pipeline == nil {
			return errors.New("relaynode: secure billing control is not enabled")
		}
		return pipeline.acceptControl(stream, firstMsg)
	}
	return n.findAndBridge(stream, firstMsg)
}

// acceptBridgeMux 接管一条对端 relay 拨入的「多路复用桥接物理连接」。
//
// 物理连接首帧（RelayBridgeMuxRoute）已被框架读走，底层 net.Conn 此刻正好停在 mux 帧边界
// （network.ReadFrame 精确分帧、不过读）。这里在该裸连接上建立 server 侧 MuxSession，
// 循环 Accept 出逐条逻辑会话；每条会话用 AcceptBridgeMuxStream 包装成「带合成 hello 首帧的
// net.Conn」，再交给 TransportCover.ListenTCPConnection 复用全部下游接入逻辑
// （→ 路由到本 relay 托管的 nat 节点，或继续向下游桥接）。
// knownRelayPeer 报告 nodeID 是否为本端已建立控制链路的对端 relay（peerLinks/inboundLinks）。
// 用于 bridge-mux 接入时的来源校验。空 nodeID 视为未知。
func (n *RelayNode) knownRelayPeer(nodeID string) bool {
	if nodeID == "" {
		return false
	}
	n.mu.RLock()
	links := make([]*peerLink, 0, len(n.peerLinks)+len(n.inboundLinks))
	for _, pl := range n.peerLinks {
		links = append(links, pl)
	}
	links = append(links, n.inboundLinks...)
	n.mu.RUnlock()
	for _, pl := range links {
		pl.mu.Lock()
		id := pl.peerID
		pl.mu.Unlock()
		if id == nodeID {
			return true
		}
	}
	return false
}

func (n *RelayNode) acceptBridgeMux(stream network.Stream, firstMsg *network.Message) error {
	tcp := networkFrameWork.TCPStreamOf(stream)
	if tcp == nil || tcp.RawConn() == nil {
		return errors.New("relaynode: bridge-mux 接入的流非 TcpStream")
	}
	rawConn := tcp.RawConn()
	peerNodeId := firstMsg.Header.NodeId
	// 来源校验（Phase E §3）：bridge-mux 物理连接会多路复用承载大量逻辑会话，
	// 接受陌生来源风险被放大。这里做「软校验」——未知来源记 WARN 但仍接受，
	// 保证不误杀控制链路尚未就绪时到达的桥接（零行为变更、纯可观测性）。
	// 待用户确认拓扑后，可将此处升级为硬拒绝（return error）。
	if !n.knownRelayPeer(peerNodeId) {
		logx.Warnf("[relaynode] bridge-mux 来源未在已知对端 relay 集合: peer=%.16s remote=%s (软校验放行, 见 Phase E §3)",
			peerNodeId, rawConn.RemoteAddr())
	}
	logx.Infof("[relaynode] 接受 bridge-mux 物理连接: peer=%.16s remote=%s", peerNodeId, rawConn.RemoteAddr())

	sess := networkFrameWork.NewMuxSession(n.ctx, rawConn, false)
	go func() {
		for {
			st, err := sess.Accept()
			if err != nil {
				logx.Debugf("[relaynode] bridge-mux session 结束: peer=%.16s err=%v", peerNodeId, err)
				return
			}
			// 条带化接入(F3)：legCount>1 的 leg 先归并，聚齐 M 条再组装下游连接。
			if st.LegCount() > 1 {
				n.collectStripedLeg(st)
				continue
			}
			conn, err := networkFrameWork.AcceptBridgeMuxStream(st)
			if err != nil {
				logx.Warnf("[relaynode] bridge-mux 合成 hello 失败: %v", err)
				_ = st.Close()
				continue
			}
			go func() {
				if e := n.starter.Cover().ListenTCPConnection(conn); e != nil {
					logx.Debugf("[relaynode] bridge-mux 会话接入结束: %v", e)
				}
			}()
		}
	}()
	return nil // 已接管该物理连接的生命周期
}

// collectStripedLeg 归并一条条带化 leg。按 connID(=StreamID) 聚齐 legCount 条后，
// 组装成一条条带化 LogicalConn 并交下游 ListenTCPConnection 一次。
func (n *RelayNode) collectStripedLeg(st *networkFrameWork.MuxStream) {
	if st == nil {
		return
	}
	connID := st.StreamID()
	want := st.LegCount()
	attempt, legIndex, valid := decodeStripedLegIndex(st.LegIndex(), want)
	if connID == "" || !valid {
		logx.Warnf("[relaynode] 拒绝非法 bridge-mux 条带 leg: connID=%q legIndex=%d legCount=%d", connID, st.LegIndex(), want)
		_ = st.Close()
		return
	}
	select {
	case <-st.Done():
		return
	default:
	}

	var stale *stripedAccept
	var accepted *stripedAccept
	var readyLegs []*networkFrameWork.MuxStream
	created := false
	reject := false

	n.mu.Lock()
	sa := n.stripedLegs[connID]
	switch {
	case sa == nil:
		sa = newStripedAccept(st, attempt, want)
		n.stripedLegs[connID] = sa
		created = true
	case attempt < sa.attempt:
		reject = true
	case attempt > sa.attempt:
		delete(n.stripedLegs, connID)
		sa.stop()
		stale = sa
		sa = newStripedAccept(st, attempt, want)
		n.stripedLegs[connID] = sa
		created = true
	case !sa.matches(st, want):
		delete(n.stripedLegs, connID)
		sa.stop()
		stale = sa
		reject = true
	case sa.legs[legIndex] != nil:
		reject = true
	}
	if !reject {
		sa.legs[legIndex] = st
		accepted = sa
	}
	if accepted != nil && len(accepted.legs) == accepted.want {
		delete(n.stripedLegs, connID)
		accepted.stop()
		readyLegs = make([]*networkFrameWork.MuxStream, accepted.want)
		for index := range readyLegs {
			readyLegs[index] = accepted.legs[index]
		}
	}
	n.mu.Unlock()

	if stale != nil {
		stale.closeLegs()
	}
	if reject {
		_ = st.Close()
		return
	}
	if readyLegs == nil {
		if created {
			go n.expireStripedAccept(connID, accepted)
		}
		go n.watchStripedLeg(connID, accepted, st)
		return
	}

	// 聚齐：组装条带化逻辑连接（接入侧用同 connID + M 条 leg）。
	lc := networkFrameWork.NewStripedConn(connID, readyLegs)
	conn, err := networkFrameWork.AcceptBridgeMuxLogicalConn(lc, accepted.target, accepted.pubKey, accepted.flags)
	if err != nil {
		logx.Warnf("[relaynode] bridge-mux 条带化合成 hello 失败: %v", err)
		_ = lc.Close()
		return
	}
	logx.Infof("[relaynode] bridge-mux 条带化接入: connID=%s legs=%d attempt=%d", connID, accepted.want, accepted.attempt)
	go func() {
		if e := n.starter.Cover().ListenTCPConnection(conn); e != nil {
			logx.Debugf("[relaynode] bridge-mux 条带化会话接入结束: %v", e)
		}
	}()
}

func decodeStripedLegIndex(encodedIndex, legCount int) (uint64, int, bool) {
	if legCount <= 1 || legCount > poolMaxConns || encodedIndex < 0 {
		return 0, 0, false
	}
	attempt := uint64(encodedIndex / poolMaxConns)
	legIndex := encodedIndex % poolMaxConns
	return attempt, legIndex, legIndex < legCount
}

func newStripedAccept(st *networkFrameWork.MuxStream, attempt uint64, want int) *stripedAccept {
	return &stripedAccept{
		want:    want,
		attempt: attempt,
		legs:    make(map[int]*networkFrameWork.MuxStream, want),
		target:  st.TargetNodeID(),
		pubKey:  st.OriginPubKey(),
		flags:   st.LegFlags(),
		done:    make(chan struct{}),
	}
}

func (sa *stripedAccept) matches(st *networkFrameWork.MuxStream, want int) bool {
	return sa.want == want && sa.target == st.TargetNodeID() && sa.pubKey == st.OriginPubKey() && sa.flags == st.LegFlags()
}

func (sa *stripedAccept) stop() {
	sa.doneOnce.Do(func() { close(sa.done) })
}

func (sa *stripedAccept) closeLegs() {
	sa.stop()
	for _, leg := range sa.legs {
		_ = leg.Close()
	}
}

func (n *RelayNode) watchStripedLeg(connID string, sa *stripedAccept, st *networkFrameWork.MuxStream) {
	var nodeDone <-chan struct{}
	if n.ctx != nil {
		nodeDone = n.ctx.Done()
	}
	select {
	case <-st.Done():
		n.discardStripedAccept(connID, sa)
	case <-nodeDone:
		n.discardStripedAccept(connID, sa)
	case <-sa.done:
	}
}

func (n *RelayNode) expireStripedAccept(connID string, sa *stripedAccept) {
	timeout := n.stripedAcceptTimeout
	if timeout <= 0 {
		timeout = defaultStripedAcceptTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var nodeDone <-chan struct{}
	if n.ctx != nil {
		nodeDone = n.ctx.Done()
	}
	select {
	case <-timer.C:
		n.discardStripedAccept(connID, sa)
	case <-nodeDone:
		n.discardStripedAccept(connID, sa)
	case <-sa.done:
	}
}

func (n *RelayNode) discardStripedAccept(connID string, sa *stripedAccept) {
	n.mu.Lock()
	if n.stripedLegs[connID] != sa {
		n.mu.Unlock()
		return
	}
	delete(n.stripedLegs, connID)
	sa.stop()
	n.mu.Unlock()
	sa.closeLegs()
}

// answerRelayQuery 应答 NAT 节点的「relay 列表查询」(RelayQueryRoute)。
//
// 这是一次性短连接: 回一条 RelayListResp 后即关闭 stream（不像控制链路那样常驻 serve）。
// 列表 = 本节点已知的对端 relay（含地址）外加本节点自身, 这样即便本 index 还没有任何子 relay,
// natNode 也能拿到「index 自身」作为可注册目标。
//
// 返回 nil 表示已接管并处理完该 stream 的生命周期（已自行 Close）；返回非 nil 由框架兜底关闭。
func (n *RelayNode) answerRelayQuery(stream network.Stream, firstMsg *network.Message) error {
	resp := &relayquery.ListResp{}
	// 本节点自身作为首个候选（最终回退目标）。
	resp.Relays = append(resp.Relays, relayquery.Info{
		NodeID:                n.idStr(),
		Addr:                  n.getAddr(),
		ContinuousOnlineSince: n.startedAt.Unix(),
		LastControlSeen:       time.Now().Unix(),
	})
	// 已知的对端 relay 邻居（含地址）。
	for _, p := range n.RelayNeighbors() {
		addr := ""
		if len(p.Addresses) > 0 {
			addr = p.Addresses[0].Relay
		}
		info := n.relayPresence(string(p.ID))
		info.NodeID = string(p.ID)
		info.Addr = addr
		resp.Relays = append(resp.Relays, info)
	}

	sc := client.NewStreamClient(stream)
	if err := sc.SendMessage(n.ctx, relayquery.EncodeListResp(resp, n.idStr())); err != nil {
		_ = stream.Close()
		return fmt.Errorf("relaynode: 应答 relay 列表查询失败: %w", err)
	}
	logx.Infof("[relaynode] 应答 relay 列表查询: 返回 %d 个 relay", len(resp.Relays))
	_ = stream.Close()
	return nil
}

func (n *RelayNode) relayLinkUp(peerID string) {
	if peerID == "" {
		return
	}
	now := time.Now()
	n.mu.Lock()
	if n.relayActiveLinks[peerID] == 0 {
		n.relayOnlineSince[peerID] = now
	}
	n.relayActiveLinks[peerID]++
	n.relayLastControlSeen[peerID] = now
	n.mu.Unlock()
	n.relayNodes.Touch(peerID, now)
}

func (n *RelayNode) relayControlSeen(peerID string) {
	if peerID == "" {
		return
	}
	now := time.Now()
	n.mu.Lock()
	n.relayLastControlSeen[peerID] = now
	n.mu.Unlock()
	n.relayNodes.Touch(peerID, now)
}

func (n *RelayNode) relayLinkDown(peerID string) {
	if peerID == "" {
		return
	}
	fullyDown := false
	n.mu.Lock()
	if count := n.relayActiveLinks[peerID]; count > 1 {
		n.relayActiveLinks[peerID] = count - 1
	} else {
		delete(n.relayActiveLinks, peerID)
		n.relayLastControlSeen[peerID] = time.Now()
		fullyDown = true
	}
	n.mu.Unlock()
	if fullyDown {
		n.removeHostRoutesVia(peerID)
	}
}

func (n *RelayNode) relayPresence(peerID string) relayquery.Info {
	n.mu.RLock()
	defer n.mu.RUnlock()
	info := relayquery.Info{}
	if since := n.relayOnlineSince[peerID]; !since.IsZero() {
		info.ContinuousOnlineSince = since.Unix()
	}
	if n.relayActiveLinks[peerID] > 0 {
		// 控制链路仍由 peerLink 持有时，以本次 Index 观察时间为准。底层 keepalive 在
		// StreamClient 内被过滤，不会进入 control dispatch，不能让安静但健康的链路误过期。
		info.LastControlSeen = time.Now().Unix()
	} else if seen := n.relayLastControlSeen[peerID]; !seen.IsZero() {
		info.LastControlSeen = seen.Unix()
	}
	return info
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

	linkCtx, linkCancel := context.WithCancel(n.ctx)
	sessionKey := peerNodeId + "\x00" + firstMsg.Header.ConnectionId
	pl := &peerLink{
		owner: n, outbound: false, expectedPeerID: peerNodeId,
		inboundSessionKey: sessionKey,
		ctx:               linkCtx, cancel: linkCancel,
	}
	// 记录对端实际连入的 IP, 供 dialHostAddr 拼出可路由的桥接地址
	// （对端 HELLO 自报的 host 可能是 ":9000" 等不可路由占位）。
	// TODO 此处仅仅提供查询功能，正式发布时会删除查询对端HELLO的IP和port信息
	if tcp := networkFrameWork.TCPStreamOf(stream); tcp != nil && tcp.RawConn() != nil {
		if host, _, err := net.SplitHostPort(tcp.RawConn().RemoteAddr().String()); err == nil {
			pl.observedRemoteIP = host
		}
	}
	n.mu.Lock()
	if n.ctx != nil && n.ctx.Err() != nil {
		n.mu.Unlock()
		linkCancel()
		_ = sc.Close()
		return errors.New("relaynode: 节点已关闭")
	}
	if n.inboundSessionGens == nil {
		n.inboundSessionGens = make(map[string]uint64)
	}
	generation := n.inboundSessionGens[sessionKey]
	if generation == 0 {
		generation = n.inboundCounter.Add(1)
		n.inboundSessionGens[sessionKey] = generation
	}
	pl.inboundGeneration = generation
	n.inboundLinks = append(n.inboundLinks, pl)
	n.mu.Unlock()
	pl.adoptInbound(sc)
	logx.Infof("[relaynode] 控制链路已建立(被动): peerNodeId=%.16s remoteIP=%s", peerNodeId, pl.observedRemoteIP)
	return nil
}

// activateInboundLink 让同一 peerID 只保留接入代次最高的逻辑 dual session。
// 同 session 的 KCP/TCP leg 共存；换 session 时在 n.mu 外关闭旧 session 的全部物理链路。
func (n *RelayNode) activateInboundLink(link *peerLink, peerID string) bool {
	if link == nil || link.outbound || peerID == "" {
		return true
	}

	active := false
	var stale []*peerLink
	n.mu.Lock()
	if n.ctx != nil && n.ctx.Err() != nil {
		stale = n.detachInboundSessionLocked(link.inboundSessionKey)
	} else {
		if n.inboundByPeerID == nil {
			n.inboundByPeerID = make(map[string]inboundPeerSession)
		}
		current, exists := n.inboundByPeerID[peerID]
		switch {
		case !exists:
			n.inboundByPeerID[peerID] = inboundPeerSession{key: link.inboundSessionKey, generation: link.inboundGeneration}
			active = true
		case current.key == link.inboundSessionKey:
			active = true
		case current.generation < link.inboundGeneration:
			stale = n.detachInboundSessionLocked(current.key)
			n.inboundByPeerID[peerID] = inboundPeerSession{key: link.inboundSessionKey, generation: link.inboundGeneration}
			active = true
		default:
			stale = n.detachInboundSessionLocked(link.inboundSessionKey)
		}
	}
	n.mu.Unlock()

	for _, staleLink := range stale {
		staleLink.close()
	}
	return active
}

func (n *RelayNode) removeInboundLink(link *peerLink) {
	if link == nil || link.outbound {
		return
	}
	n.mu.Lock()
	n.removeInboundLinkLocked(link)
	n.mu.Unlock()
}

// removeInboundLinkLocked 按指针身份删除，调用方必须持有 n.mu。
// session 代次 tombstone 不在此删除，旧 dual leg 迟到时仍会被识别为旧代。
func (n *RelayNode) removeInboundLinkLocked(link *peerLink) {
	if link == nil {
		return
	}
	writeIndex := 0
	for _, candidate := range n.inboundLinks {
		if candidate == link {
			continue
		}
		n.inboundLinks[writeIndex] = candidate
		writeIndex++
	}
	for clearIndex := writeIndex; clearIndex < len(n.inboundLinks); clearIndex++ {
		n.inboundLinks[clearIndex] = nil
	}
	n.inboundLinks = n.inboundLinks[:writeIndex]
}

func (n *RelayNode) detachInboundSessionLocked(sessionKey string) []*peerLink {
	if sessionKey == "" {
		return nil
	}
	stale := make([]*peerLink, 0, 2)
	writeIndex := 0
	for _, candidate := range n.inboundLinks {
		if candidate != nil && candidate.inboundSessionKey == sessionKey {
			stale = append(stale, candidate)
			continue
		}
		n.inboundLinks[writeIndex] = candidate
		writeIndex++
	}
	for clearIndex := writeIndex; clearIndex < len(n.inboundLinks); clearIndex++ {
		n.inboundLinks[clearIndex] = nil
	}
	n.inboundLinks = n.inboundLinks[:writeIndex]
	return stale
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
	leg := networkFrameWork.LegTransport(stream) // "kcp" / "tcp" / ""

	// dual 拨号会对同一 connID 产生 KCP+TCP 两条 leg。只用 KCP(send-preferred)建桥,
	// 既恢复跨境吞吐又避免双 leg 在桥接 active 字段上的竞态。
	n.mu.Lock()
	entry := n.localLegs[connID]
	if entry == nil {
		entry = &localBridgeEntry{kcpReady: make(chan struct{})}
		n.localLegs[connID] = entry
	}
	if entry.bridged {
		// 已建桥：把这条同 connID 的多余 leg 作为 failover leg splice 进已有桥接，
		// 而非关闭。CrossRelayBridge 会把多条 local leg 聚合成逐帧端点，旧 leg 的半帧
		// 不会与新 leg 的完整重传混入同一 peer 字节流。
		// 这从根上消除「客户端给 extra leg 注册了重连器、relay 却关掉它 → 无限重连风暴」。
		br := entry.bridge
		n.mu.Unlock()
		return n.spliceFailoverLeg(br, stream, firstMsg, target, connID)
	}

	// relay 侧【先到先建桥】，不在此偏好 KCP。关键不对称：家庭 NAT 的 UDP 是单向的——
	// 客户端 KCP 首帧能出方向到达 relay，但 relay 的 KCP 回包穿不回 NAT。relay 光凭
	// "收到 KCP 首帧" 无法区分 "KCP 双向可用" 与 "KCP 仅出方向、回程已死"；只有客户端
	// (等到端到端 ACK 才算数) 才知道。故 "KCP 优先" 只放在客户端 (见 Dialers.go
	// kcpPriorityWindow)：客户端 200ms 内 KCP 握手成功才 preferred=KCP。relay 这边谁先到
	// 谁建桥，靠桥接的 DualFrameRelayEndpoint 跟随客户端实际可用的 leg。
	// 若在此等 KCP，家庭 NAT 下会把桥建在死 KCP leg 上 → 端到端握手 reset/EOF
	// (见记忆 natclient-relay-kcp-preferred-bug)。
	if entry.bridging {
		// 另一条同 connID leg 正在建桥（并发到达）：等它建成后本 leg 转 failover splice。
		kcpReady := entry.kcpReady
		n.mu.Unlock()
		<-kcpReady
		n.mu.Lock()
		br := entry.bridge
		bridged := entry.bridged
		n.mu.Unlock()
		if bridged && br != nil {
			return n.spliceFailoverLeg(br, stream, firstMsg, target, connID)
		}
		// 建桥失败（对端不可达等）：不在此重建（会撞 kcpReady 双关、orphan entry）。
		// 直接关本 leg，交由客户端重试（客户端本就重试 12 次）。
		_ = stream.Close()
		return fmt.Errorf("relaynode: 并发建桥的另一条 leg 失败, 关闭本 leg 待客户端重试 (target=%.16s connId=%s)", target, connID)
	}
	_ = leg               // leg 类型不影响建桥决策，先到先得
	entry.bridging = true // 认领建桥
	n.mu.Unlock()
	return n.doBridge(stream, firstMsg, entry, target, connID)
}

// doBridge 用给定 leg 建立跨中继桥接。建成后置 entry.bridged 并关闭 kcpReady 通知等待方。
func (n *RelayNode) doBridge(stream network.Stream, firstMsg *network.Message, entry *localBridgeEntry, target, connID string) error {
	cleanup := func() {
		n.mu.Lock()
		// 建桥失败：清除认领标记并关闭 kcpReady，唤醒并发等待的另一条 leg（否则它永久阻塞）。
		// 该 leg 醒来见 bridged=false，会顶上重建。
		entry.bridging = false
		select {
		case <-entry.kcpReady: // 已关闭
		default:
			close(entry.kcpReady)
		}
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

	// 跨中继桥接：两侧均按完整 Frame 聚合并隔离 MessageId 命名空间，避免多 leg
	// 故障切换时发生半帧拼接；E2E payload 仍保持透明。透传 local1 的 hello 与原始 connID。
	//
	// 连接池版（Phase B+）：桥接不再每会话独占一条物理 TCP, 而是从到 hostAddr 的连接池
	// 开一条 mux 逻辑会话（多路复用到共享物理连接上）。会话结束 Close 只关该逻辑会话。
	br := networkFrameWork.NewCrossRelayBridge(n.ctx, hostAddr, target, string(firstMsg.Payload), connID)
	legFlags := firstMsg.Header.LegFlags
	br.SetDialFunc(func(addr, targetNodeId, originPubKeyHex, cid string) (net.Conn, error) {
		return n.openBridgeStream(addr, targetNodeId, originPubKeyHex, cid, legFlags)
	})
	if err := br.SpliceLegWithFlags(stream,
		firstMsg.Header.LegFlags&network.LegFlagExtra != 0,
		firstMsg.Header.LegFlags&network.LegFlagResume != 0,
	); err != nil {
		cleanup()
		return fmt.Errorf("relaynode: 建立跨中继桥接失败: %w", err)
	}
	n.mu.Lock()
	entry.bridge = br
	if !entry.bridged {
		entry.bridged = true
		close(entry.kcpReady) // 通知等待中的 TCP leg: 已建桥
	}
	n.mu.Unlock()
	go n.releaseLocalBridgeWhenDone(connID, entry, br)
	logx.Infof("[relaynode] 跨中继桥接建立: target=%.16s via relay=%s connId=%s leg=%s",
		target, hostAddr, connID, networkFrameWork.LegTransport(stream))
	return nil
}

func (n *RelayNode) releaseLocalBridgeWhenDone(connID string, expected *localBridgeEntry, bridge *networkFrameWork.CrossRelayBridge) {
	<-bridge.Done()
	bridge.Close()
	n.mu.Lock()
	if n.localLegs[connID] == expected && expected.bridge == bridge {
		delete(n.localLegs, connID)
	}
	n.mu.Unlock()
}

// spliceFailoverLeg 把一条同 connID 的多余 leg 作为 failover leg 接入已建好的桥接。
// 替代旧的「关闭多余 leg」行为：客户端 dual/双TCP failover 保留的备用 leg 不再被 relay 关闭，
// 从而消除「客户端重连备用 leg → relay 关闭 → 无限重连」的风暴。
// br 为 nil（极端竞态：bridged 已置但 bridge 尚未可见）或 splice 失败时，回退为关闭该 leg。
func (n *RelayNode) spliceFailoverLeg(br *networkFrameWork.CrossRelayBridge, stream network.Stream, firstMsg *network.Message, target, connID string) error {
	if br == nil {
		_ = stream.Close()
		return nil
	}
	coexist := firstMsg != nil && firstMsg.Header != nil && firstMsg.Header.LegFlags&network.LegFlagExtra != 0
	resume := firstMsg != nil && firstMsg.Header != nil && firstMsg.Header.LegFlags&network.LegFlagResume != 0
	if err := br.SpliceLegWithFlags(stream, coexist, resume); err != nil {
		logx.Warnf("[relaynode] failover leg splice 失败, 关闭该 leg: target=%.16s connId=%s err=%v",
			target, connID, err)
		_ = stream.Close()
		return nil
	}
	logx.Infof("[relaynode] failover leg 已并入桥接: target=%.16s connId=%s leg=%s",
		target, connID, networkFrameWork.LegTransport(stream))
	return nil
}

// findHostRelay 向所有已建立的控制链路并发 FIND, 返回首个声称托管 target 的「控制链路」。
// 调用方用该链路的 dialHostAddr() 得到可路由的桥接地址（而非对端自报的可能不可路由的 Addr）。
// 全部未命中或超时则返回错误（需求 3）。
func (n *RelayNode) findHostRelay(target string) (*peerLink, error) {
	if links := n.routeNextHops(target, ""); len(links) > 0 {
		return links[0], nil
	}
	baseCtx := n.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	findCtx, cancel := context.WithTimeout(baseCtx, 5*time.Second)
	defer cancel()

	n.mu.RLock()
	links := make([]*peerLink, 0, len(n.peerLinks)+len(n.inboundLinks))
	seen := make(map[*peerLink]struct{}, cap(links))
	for _, pl := range n.peerLinks {
		if pl == nil {
			continue
		}
		seen[pl] = struct{}{}
		links = append(links, pl)
	}
	for _, pl := range n.inboundLinks {
		if pl == nil {
			continue
		}
		if _, ok := seen[pl]; ok {
			continue
		}
		seen[pl] = struct{}{}
		links = append(links, pl)
	}
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

	type sendResult struct {
		link *peerLink
		err  error
	}
	find := &controlMessage{Type: ctrlFind, ReqID: reqID, Target: target}
	sendResults := make(chan sendResult, len(links))
	unresolved := make(map[*peerLink]struct{}, len(links))
	for _, pl := range links {
		unresolved[pl] = struct{}{}
		go func(link *peerLink) {
			sendResults <- sendResult{link: link, err: link.sendContext(findCtx, find)}
		}(pl)
	}

	for len(unresolved) > 0 {
		select {
		case <-findCtx.Done():
			if n.ctx != nil && n.ctx.Err() != nil {
				return nil, errors.New("relaynode 已关闭")
			}
			return nil, errors.New("FIND 超时, 无 relay 托管目标节点")
		case result := <-sendResults:
			if result.err != nil {
				delete(unresolved, result.link)
			}
		case ans := <-pf.respCh:
			if _, ok := unresolved[ans.link]; !ok {
				continue
			}
			if ans.cm != nil && ans.cm.Hosts {
				return ans.link, nil
			}
			delete(unresolved, ans.link)
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
			LastSeen:  time.Unix(node.LastSeen(), 0),
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
			info := p2pnode.PeerInfo{ID: id, LastSeen: time.Unix(node.LastSeen(), 0)}
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
		if n.hostRouteBroadcastDone != nil {
			<-n.hostRouteBroadcastDone
		}
		n.mu.RLock()
		pipeline := n.billingPipeline
		n.mu.RUnlock()
		if pipeline != nil {
			_ = pipeline.close()
		}
		n.closePeerLinks()
		// 关闭跨中继连接池(Phase B)：closeBridgePools 内部自取 n.mu，必须在解锁后调用。
		n.closeBridgePools()
		n.starter.Close()
	})
	return nil
}

func (n *RelayNode) closePeerLinks() {
	n.mu.Lock()
	links := make([]*peerLink, 0, len(n.peerLinks)+len(n.inboundLinks))
	for _, link := range n.peerLinks {
		links = append(links, link)
	}
	links = append(links, n.inboundLinks...)
	n.peerLinks = nil
	n.inboundLinks = nil
	n.inboundByPeerID = nil
	n.inboundSessionGens = nil
	n.mu.Unlock()

	// peerLink.close 会回调 relayLinkDown 并获取 n.mu，必须在释放 n.mu 后执行。
	for _, link := range links {
		link.close()
	}
}

// 确保 RelayNode 实现 p2pnode.Node 接口。
var _ p2pnode.Node = (*RelayNode)(nil)
