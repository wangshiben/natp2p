package natnode

import (
	"bnfs_p2p/DHTable"
	"bnfs_p2p/admission"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/interfaces"
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"bnfs_p2p/p2pnode"

	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// relayEntry 跟踪一条活跃的 relay 注册信息。
type relayEntry struct {
	addr   string
	stream network.Stream
}

// NATNode 实现 p2pnode.Node 接口，代表一个 NAT 后节点。
// 所有连接均通过 relay 服务器中转，无直接 IP:port 连通。
type NATNode struct {
	identity *DHTable.Node
	privKey  *ecdh.PrivateKey

	allNodes   interfaces.DHTTable
	relayNodes interfaces.DHTTable

	transport p2pnode.Transport
	handshake p2pnode.HandshakeHandler

	registeredRelays  map[string]*relayEntry
	registrationLocks map[string]*sync.Mutex
	knownRelays       map[string]struct{}
	// entryRelays 是本节点自己「已注册/可经其收发」的入口 relay 地址列表（含 bootstrap）。
	// Connect 只会经这些自己的入口 relay 拨号, 由入口 relay 负责跨中继查找并连接到 target 的 relay。
	// 绝不直接拨向 target 所在的 relay —— 在复杂网络里那条路径未经验证、可能根本不通。
	entryRelays   map[string]struct{}
	relayFailover *relayFailoverState
	peerAddrIndex map[p2pnode.NodeID][]p2pnode.PeerAddr
	conns         map[p2pnode.NodeID]*NATConnection

	onConnection         p2pnode.OnConnectionCallback
	seenRequests         map[uint64]struct{}
	reqIDCounter         atomic.Uint64
	billingMeter         *natBillingMeter
	billingControlActive map[string]network.Stream

	mu               sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	closeOnce        sync.Once
	relayManagerOnce sync.Once
}

// NewNATNode 创建一个 NAT 后节点。
// privKey 为 nil 时自动生成 ECDH 密钥对。
// bootstrapRelay 是初始 relay 地址（如 "127.0.0.1:9000"），用于启动。
func NewNATNode(privKey *ecdh.PrivateKey, bootstrapRelay string) (*NATNode, error) {
	if privKey == nil {
		var err error
		privKey, err = crypoto.MakeKeyPair()
		if err != nil {
			return nil, fmt.Errorf("natnode: 生成密钥对失败: %w", err)
		}
	}

	identity, err := DHTable.NewNodeWithKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("natnode: 创建节点身份失败: %w", err)
	}

	allNodes, err := DHTable.NewDHTTable(identity.PeerID(), 20)
	if err != nil {
		return nil, fmt.Errorf("natnode: 创建全节点 DHT 失败: %w", err)
	}

	relayNodes, err := DHTable.NewDHTTable(identity.PeerID(), 20)
	if err != nil {
		return nil, fmt.Errorf("natnode: 创建中继节点 DHT 失败: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	relayFailover := newRelayFailoverState(bootstrapRelay)
	n := &NATNode{
		identity:             identity,
		privKey:              privKey,
		allNodes:             allNodes,
		relayNodes:           relayNodes,
		transport:            NewNATTransport(identity.Pubkey(), relayFailover),
		handshake:            NewNATHandshakeHandler(privKey),
		registeredRelays:     make(map[string]*relayEntry),
		registrationLocks:    make(map[string]*sync.Mutex),
		knownRelays:          make(map[string]struct{}),
		entryRelays:          make(map[string]struct{}),
		relayFailover:        relayFailover,
		peerAddrIndex:        make(map[p2pnode.NodeID][]p2pnode.PeerAddr),
		conns:                make(map[p2pnode.NodeID]*NATConnection),
		seenRequests:         make(map[uint64]struct{}),
		billingControlActive: make(map[string]network.Stream),
		ctx:                  ctx,
		cancel:               cancel,
	}
	billingMeter, err := newNatBillingMeter(privKey)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("natnode: initialize secure billing: %w", err)
	}
	n.billingMeter = billingMeter

	n.knownRelays[bootstrapRelay] = struct{}{}
	// bootstrap relay 即本节点的初始入口 relay。
	n.entryRelays[bootstrapRelay] = struct{}{}
	relayFailover.onActivated = n.relayActivated

	return n, nil
}

func (n *NATNode) relayActivated(address string) {
	n.mu.Lock()
	n.entryRelays = map[string]struct{}{address: {}}
	n.knownRelays[address] = struct{}{}
	for oldAddress, entry := range n.registeredRelays {
		delete(n.registeredRelays, oldAddress)
		entry.addr = address
		n.registeredRelays[address] = entry
		break
	}
	n.mu.Unlock()
	n.startBillingControl(address)
	logx.Infof("[natnode] 注册到 relay: %s", address)
}

func (n *NATNode) currentBillingRelay(fallback string) string {
	if n.relayFailover != nil {
		if target, err := n.relayFailover.currentTarget(); err == nil && target.address != "" {
			return target.address
		}
	}
	return fallback
}

func (n *NATNode) resetBillingControl(relayAddr string) {
	n.mu.RLock()
	stream := n.billingControlActive[relayAddr]
	n.mu.RUnlock()
	if stream != nil {
		_ = stream.Close()
	}
}

// ID 返回本节点 NodeID。
func (n *NATNode) ID() p2pnode.NodeID {
	return p2pnode.NodeID(n.identity.PeerID())
}

// SetIndexSign 设置本节点向 relay 注册时携带的 CA 准入证书(indexSign, admission.SignedCert JSON)。
// 空则不携带（无准入模式）。必须在 Listen/注册之前调用。证书里的 Role 决定本节点被 relay
// 视作 client 还是 server（计费方向据此区分）。
func (n *NATNode) SetIndexSign(signJSON []byte) {
	if t, ok := n.transport.(*NATTransport); ok {
		t.SetIndexSign(signJSON)
	}
	if len(signJSON) == 0 {
		return
	}
	var signedCert admission.SignedCert
	if err := json.Unmarshal(signJSON, &signedCert); err != nil {
		logx.Warnf("[natnode] 无法解析计费准入证书: %v", err)
		return
	}
	if signedCert.Cert.Role == admission.RoleServer {
		if err := n.billingMeter.enable(&signedCert); err != nil {
			logx.Warnf("[natnode] 无法启用双签计费: %v", err)
		}
	}
}

// SetBillingPrivateSnapshotPath enables a local, redacted billing-meter JSON
// snapshot. The parent directory must be private (0700); snapshots are
// atomically replaced with mode 0600. An empty path leaves this feature off.
func (n *NATNode) SetBillingPrivateSnapshotPath(path string) error {
	return n.billingMeter.setPrivateSnapshotPath(path)
}

// PubKeyHex 返回本节点公钥 hex（申请 indexSign 时作为 subject 公钥提交给 CA）。
func (n *NATNode) PubKeyHex() string { return n.identity.Pubkey() }

// OnConnection 设置入站连接握手完成后的回调。
func (n *NATNode) OnConnection(cb p2pnode.OnConnectionCallback) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onConnection = cb
}

// Listen 向指定 relay 注册并阻塞等待入站连接。
// 每条入站 hello 触发 Noise E2E 握手 → 元数据交换 → DHT 更新 → 回调。
// ctx 取消时返回。
func (n *NATNode) Listen(ctx context.Context, addr string) error {
	// 合并外部 ctx 与节点生命周期。
	mergedCtx, mergedCancel := context.WithCancel(ctx)
	defer mergedCancel()

	go func() {
		select {
		case <-n.ctx.Done():
			mergedCancel()
		case <-mergedCtx.Done():
		}
	}()

	// relayManager 属于节点生命周期；同一节点可在上一条入站连接结束后再次
	// Listen，但不能因此重复启动后台注册管理器。
	n.relayManagerOnce.Do(func() {
		go n.relayManager()
	})

	// 注册到初始 relay 并开始 accept 循环。
	return n.registerAndServe(addr)
}

func (n *NATNode) registrationLock(addr string) *sync.Mutex {
	n.mu.Lock()
	defer n.mu.Unlock()
	lock := n.registrationLocks[addr]
	if lock == nil {
		lock = &sync.Mutex{}
		n.registrationLocks[addr] = lock
	}
	return lock
}

func (n *NATNode) removeRegistrationEntry(entry *relayEntry) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for addr, current := range n.registeredRelays {
		if current == entry {
			delete(n.registeredRelays, addr)
		}
	}
}

// registerAndServe 向单个 relay 注册，并在拿到的注册流上处理入站 hello。
// 注册流故障后返回；relay 管理器会按需创建新的注册。
func (n *NATNode) registerAndServe(addr string) error {
	lock := n.registrationLock(addr)
	lock.Lock()
	defer lock.Unlock()

	stream, err := n.transport.Register(n.ctx, addr, n.identity.Pubkey())
	if err != nil {
		return fmt.Errorf("natnode: 向 %s 注册失败: %w", addr, err)
	}
	networkFrameWork.EnableReconnectSurvival(stream)

	entry := &relayEntry{addr: addr, stream: stream}
	n.mu.Lock()
	if err := n.ctx.Err(); err != nil || n.registeredRelays == nil {
		n.mu.Unlock()
		_ = stream.Close()
		if err == nil {
			err = context.Canceled
		}
		return fmt.Errorf("natnode: node closed before registration to %s completed: %w", addr, err)
	}
	n.registeredRelays[addr] = entry
	// 已成功注册的 relay 即为本节点的入口 relay, 可经它发起跨中继连接。
	n.entryRelays[addr] = struct{}{}
	n.mu.Unlock()
	n.startBillingControl(addr)
	if n.billingMeter.certificate() != nil {
		billingCtx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
		err = n.billingMeter.waitRelaySession(billingCtx, addr)
		cancel()
		if err != nil {
			n.removeRegistrationEntry(entry)
			_ = stream.Close()
			n.resetBillingControl(addr)
			return fmt.Errorf("natnode: 等待 Relay 安全计费会话失败: %w", err)
		}
	}

	return n.handleInboundHello(addr, entry)
}

// handleInboundHello 在已注册的流上等待 hello，完成 Noise E2E 握手与元数据交换，
// 更新路由表，触发 onConnection 回调。
// 一次握手后该流被加密并专属于该对端；后续连接走其他注册流。
func (n *NATNode) handleInboundHello(relayAddr string, entry *relayEntry) (err error) {
	stream := entry.stream
	defer func() {
		if err == nil {
			return
		}

		n.removeRegistrationEntry(entry)
		_ = stream.Close()
	}()

	// 读取对端经 relay 发来的首条消息（hello）。
	firstMsg, err := stream.NextMessage(n.ctx)
	if err != nil {
		return err
	}

	// 从 hello payload 获取对端公钥 hex，构造远程节点条目。
	peerPubKeyHex := string(firstMsg.Payload)
	remoteNode, err := DHTable.NewNodeFromPubKeyHex(peerPubKeyHex)
	if err != nil {
		return fmt.Errorf("natnode: 解析对端公钥失败: %w", err)
	}

	// 先在原始流上绑定对端身份（必须在 StreamClient 包装之前）。
	if !networkFrameWork.SetStreamIdentity(stream, remoteNode.PeerID(), firstMsg.Header.ConnectionId) {
		return fmt.Errorf("natnode: SetStreamIdentity 失败, peer: %s", remoteNode.PeerID())
	}

	peerID := p2pnode.NodeID(remoteNode.PeerID())

	// 用 StreamClient 包装，提供心跳过滤与 ConnectionId 自填充。
	sc := client.NewStreamClient(stream)

	// 执行 Noise responder 握手。
	peerInfo, err := n.handshake.HandshakeIncoming(n.ctx, sc, firstMsg)
	if err != nil {
		return fmt.Errorf("natnode: 与 %s 握手失败: %w", peerID, err)
	}

	// 交换元数据：发送己方 NodeID + relay 列表，接收对方。
	peerRelays, err := n.exchangeMetadata(sc, peerID)
	if err != nil {
		return fmt.Errorf("natnode: 与 %s 元数据交换失败: %w", peerID, err)
	}

	// 更新路由表。
	n.mu.Lock()
	n.peerAddrIndex[peerID] = addrListToPeerAddrs(peerRelays)

	// 将对端加入全节点 DHT。
	n.allNodes.AddNode(remoteNode)

	// 将新获知的 relay 地址加入已知集合。
	for _, r := range peerRelays {
		n.knownRelays[r] = struct{}{}
	}
	n.knownRelays[relayAddr] = struct{}{}

	conn := newNATConnection(peerInfo, sc, func() { n.allNodes.Touch(string(peerID), time.Now()) }, n.billingMeter,
		func() string { return n.currentBillingRelay(relayAddr) }, n.resetBillingControl)
	n.conns[peerID] = conn
	// 注：不删除 registeredRelays 中的 entry。
	// 此注册流已"消费"成 peer 连接，但保留 entry 作为「该 relay 已被占用」的标记，
	// 避免 relayManager 在 30s tick 时认为 count=0 而再次向同一 relay 注册——
	// 那会让 relay 端同 NodeId 的 StreamGroup 把现有 peer 连接的 legs 替换掉，
	// 引发 EOF + 死循环重连级联。要接受新入站连接需通过其他 relay 地址。
	cb := n.onConnection
	n.mu.Unlock()

	// 触发连接回调，上层可开始使用此连接。
	if cb != nil {
		cb(conn)
	}

	return nil
}

// exchangeMetadata 向对端发送己方 NodeID 与已注册 relay 地址，
// 然后读取对端的元数据。返回对端的 relay 地址列表。
func (n *NATNode) exchangeMetadata(sc *client.StreamClient, expectedPeerID p2pnode.NodeID) ([]string, error) {
	n.mu.RLock()
	myRelays := make([]string, 0, len(n.registeredRelays))
	for addr := range n.registeredRelays {
		myRelays = append(myRelays, addr)
	}
	n.mu.RUnlock()

	// 发送己方握手信息。
	hsMsg := newHandshakeMessage(string(n.ID()), sc.ConnectionId(), myRelays)
	hsPayloadPreview := string(hsMsg.Payload)
	if len(hsPayloadPreview) > 80 {
		hsPayloadPreview = hsPayloadPreview[:80] + "..."
	}
	logx.Debugf("[exchangeMetadata] 发送 metadata: peerID=%.16s connId=%s payloadLen=%d preview=%q",
		expectedPeerID, sc.ConnectionId(), len(hsMsg.Payload), hsPayloadPreview)
	if err := sc.SendMessage(n.ctx, hsMsg); err != nil {
		return nil, fmt.Errorf("发送元数据: %w", err)
	}

	// 接收对端握手信息。
	msg, err := sc.NextMessage(n.ctx)
	if err != nil {
		return nil, fmt.Errorf("接收元数据: %w", err)
	}

	// 诊断日志：打印接收到的 payload 前 80 字节（用 hex 编码避免乱码）和 ASCII 预览。
	previewLen := len(msg.Payload)
	if previewLen > 80 {
		previewLen = 80
	}
	rawPreview := msg.Payload[:previewLen]
	asciiPreview := string(rawPreview)
	for i, b := range rawPreview {
		if b < 0x20 || b > 0x7E {
			asciiPreview = string(rawPreview[:i]) + fmt.Sprintf("\\x%02x", b)
			break
		}
	}
	logx.Debugf("[exchangeMetadata] 收到 metadata: peerID=%.16s headerNodeId=%.16s headerConnId=%s headerRoute=%s payloadLen=%d hexPreview=%x asciiPreview=%q",
		expectedPeerID, msg.Header.NodeId, msg.Header.ConnectionId, msg.Header.RouteName,
		len(msg.Payload), rawPreview, asciiPreview)

	peerIDStr, peerRelays, err := decodeHandshakePayload(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("解码元数据: %w", err)
	}

	if p2pnode.NodeID(peerIDStr) != expectedPeerID {
		return nil, fmt.Errorf("对端 ID 不匹配: 期望 %s, 收到 %s", expectedPeerID, peerIDStr)
	}

	return peerRelays, nil
}

func addrListToPeerAddrs(addrs []string) []p2pnode.PeerAddr {
	res := make([]p2pnode.PeerAddr, len(addrs))
	for i, a := range addrs {
		res[i] = p2pnode.PeerAddr{Relay: a}
	}
	return res
}

// Connect 查找 target 并通过本节点自己的入口 relay 建立连接。
//
// 重要拓扑约束：NAT 节点**只**经自己的入口 relay（entryRelays，即已注册/bootstrap 的 relay）拨号,
// 由入口 relay 负责跨中继查找 target 所在的 relay 并完成 relay→relay 的桥接。
// NAT 节点**绝不**直接拨向 target 所在的 relay —— 在复杂网络里 "natNode→对方 relay" 这条路径
// 未经验证、可能根本不通（例如 natNode1→relayNode0 不通, 只能 natNode1→relayNode1→relayNode0）。
// 因此这里不再使用 peerAddrIndex[target] 或任意 knownRelays 作为拨号目标。
func (n *NATNode) Connect(ctx context.Context, target p2pnode.NodeID) (p2pnode.Connection, error) {
	// 快速路径：已连接则直接返回。
	n.mu.RLock()
	if conn, ok := n.conns[target]; ok {
		n.mu.RUnlock()
		return conn, nil
	}

	n.mu.RUnlock()
	targetRelay, relayErr := n.relayFailover.currentTarget()
	if relayErr != nil {
		return nil, fmt.Errorf("natnode: 无可用的入口 relay, 无法连接 %s", target)
	}
	return n.connectViaEntryRelay(ctx, targetRelay.address, target)
}

// connectViaEntryRelay 经指定的本节点入口 relay 拨号到 target 并完成握手/元数据交换/入表。
func (n *NATNode) connectViaEntryRelay(ctx context.Context, relayAddr string, target p2pnode.NodeID) (p2pnode.Connection, error) {
	// 经入口 relay 拨号。
	rawStream, _, err := n.transport.Dial(ctx, relayAddr, target)
	if err != nil {
		return nil, fmt.Errorf("natnode: 经入口 relay %s 拨号 %s 失败: %w", relayAddr, target, err)
	}

	// 用 StreamClient 包装。
	sc := client.NewStreamClient(rawStream)

	// 执行 Noise initiator 握手。
	peerInfo, err := n.handshake.HandshakeOutgoing(ctx, sc, target)
	if err != nil {
		sc.Close()
		return nil, fmt.Errorf("natnode: 与 %s 握手失败: %w", target, err)
	}
	networkFrameWork.EnableReconnectSurvival(rawStream)

	// 交换元数据。
	peerRelays, err := n.exchangeMetadata(sc, target)
	if err != nil {
		sc.Close()
		return nil, fmt.Errorf("natnode: 与 %s 元数据交换失败: %w", target, err)
	}

	// 更新路由表。
	n.mu.Lock()
	n.peerAddrIndex[target] = addrListToPeerAddrs(peerRelays)

	// 将对端加入全节点 DHT（出站时仅知 NodeID，无公钥）。
	n.allNodes.AddNode(DHTable.NewNodeFromPeerID(string(target)))

	for _, r := range peerRelays {
		n.knownRelays[r] = struct{}{}
	}
	n.knownRelays[relayAddr] = struct{}{}
	conn := newNATConnection(peerInfo, sc, func() { n.allNodes.Touch(string(target), time.Now()) }, n.billingMeter,
		func() string { return n.currentBillingRelay(relayAddr) }, n.resetBillingControl)
	n.conns[target] = conn
	n.mu.Unlock()

	return conn, nil
}

// Broadcast 向所有已知邻居泛洪消息，带 TTL 传播。
func (n *NATNode) Broadcast(ctx context.Context, msg *p2pnode.Message) error {
	msg.RequestID = n.reqIDCounter.Add(1)
	msg.Sender = n.ID()

	n.mu.Lock()
	peers := n.neighborSetLocked()
	n.mu.Unlock()

	if len(peers) == 0 {
		return errors.New("natnode: 无可广播的邻居")
	}

	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(peer p2pnode.PeerInfo) {
			defer wg.Done()
			n.mu.RLock()
			conn := n.conns[peer.ID]
			n.mu.RUnlock()
			if conn == nil {
				return
			}
			clone := *msg
			conn.Send(ctx, &clone)
		}(p)
	}
	wg.Wait()
	return nil
}

func (n *NATNode) neighborSetLocked() []p2pnode.PeerInfo {
	buckets := n.allNodes.GetBuckets()
	seen := make(map[p2pnode.NodeID]bool)
	var result []p2pnode.PeerInfo

	for _, b := range buckets {
		// KBucketImpl 有 GetNodes() 方法，但接口层未暴露。
		// 通过具体类型断言获取。
		if bucket, ok := b.(interface{ GetNodes() []interfaces.Node }); ok {
			for _, node := range bucket.GetNodes() {
				id := p2pnode.NodeID(node.PeerID())
				if id == n.ID() || seen[id] {
					continue
				}
				seen[id] = true
				result = append(result, p2pnode.PeerInfo{
					ID:        id,
					Addresses: n.peerAddrIndex[id],
					LastSeen:  time.Unix(node.LastSeen(), 0),
				})
			}
		}
	}
	return result
}

// Neighbors 返回路由表中所有已知节点，按与本节点的 XOR 距离升序排列。
func (n *NATNode) Neighbors() []p2pnode.PeerInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.neighborSetLocked()
}

// ClosestPeers 返回离 target 最近的 k 个节点。
func (n *NATNode) ClosestPeers(target p2pnode.NodeID, k int) []p2pnode.PeerInfo {
	closest := n.allNodes.FindClosest(string(target), k)

	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make([]p2pnode.PeerInfo, 0, len(closest))
	for _, node := range closest {
		id := p2pnode.NodeID(node.PeerID())
		if id == n.ID() {
			continue
		}
		result = append(result, p2pnode.PeerInfo{
			ID:        id,
			Addresses: n.peerAddrIndex[id],
			LastSeen:  time.Unix(node.LastSeen(), 0),
		})
	}
	return result
}

// Close 关闭节点，取消所有 goroutine 并关闭所有流。
func (n *NATNode) Close() error {
	var errs []error
	n.closeOnce.Do(func() {
		n.cancel()

		n.mu.Lock()
		for _, entry := range n.registeredRelays {
			if entry.stream != nil {
				if err := entry.stream.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		for _, conn := range n.conns {
			if err := conn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		n.conns = nil
		n.registeredRelays = nil
		n.mu.Unlock()
		if err := n.billingMeter.closePrivateSnapshot(); err != nil {
			errs = append(errs, fmt.Errorf("natnode: close private billing snapshot: %w", err))
		}
	})
	return errors.Join(errs...)
}

// relayManager 定期检查活跃 relay 注册数，维持本节点对**自己的入口 relay**的注册。
//
// 关键约束：候选只来自 entryRelays（本节点显式配置/bootstrap 的入口 relay），
// **绝不**用 knownRelays——后者包含从元数据交换里学到的「对端的 relay」, 直接去注册它们
// 会让本 NAT 节点与多个公网 relay 建立直连, 违背「只连自己入口 relay」的拓扑约束。
func (n *NATNode) relayManager() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}

		n.mu.Lock()
		// 候选 = 本节点入口 relay 中尚未注册的那些。
		var candidates []string
		for addr := range n.entryRelays {
			if _, exists := n.registeredRelays[addr]; !exists {
				candidates = append(candidates, addr)
			}
		}
		n.mu.Unlock()

		for _, addr := range candidates {
			select {
			case <-n.ctx.Done():
				return
			default:
			}

			n.mu.RLock()
			_, alreadyRegistered := n.registeredRelays[addr]
			n.mu.RUnlock()
			if alreadyRegistered {
				continue
			}

			// 每条注册在独立 goroutine 中服务。
			go func(a string) {
				if err := n.registerAndServe(a); err != nil {
					// registerAndServe 已在错误时做清理。
				}
			}(addr)
		}
	}
}
