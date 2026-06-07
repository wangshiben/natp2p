package natnode

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
	"errors"
	"fmt"
	"log"
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

	registeredRelays map[string]*relayEntry
	knownRelays      map[string]struct{}
	peerAddrIndex    map[p2pnode.NodeID][]p2pnode.PeerAddr
	conns            map[p2pnode.NodeID]*NATConnection

	onConnection p2pnode.OnConnectionCallback
	seenRequests map[uint64]struct{}
	reqIDCounter atomic.Uint64

	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
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

	n := &NATNode{
		identity:         identity,
		privKey:          privKey,
		allNodes:         allNodes,
		relayNodes:       relayNodes,
		transport:        NewNATTransport(identity.Pubkey()),
		handshake:        NewNATHandshakeHandler(privKey),
		registeredRelays: make(map[string]*relayEntry),
		knownRelays:      make(map[string]struct{}),
		peerAddrIndex:    make(map[p2pnode.NodeID][]p2pnode.PeerAddr),
		conns:            make(map[p2pnode.NodeID]*NATConnection),
		seenRequests:     make(map[uint64]struct{}),
		ctx:              ctx,
		cancel:           cancel,
	}

	n.knownRelays[bootstrapRelay] = struct{}{}

	return n, nil
}

// ID 返回本节点 NodeID。
func (n *NATNode) ID() p2pnode.NodeID {
	return p2pnode.NodeID(n.identity.PeerID())
}

// OnConnection 设置入站连接握手完成后的回调。
func (n *NATNode) OnConnection(cb p2pnode.OnConnectionCallback) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onConnection = cb
}

// Listen 向指定 relay 注册并阻塞等待入站连接。
// 每条入站 hello 触发 TLS 握手 → 元数据交换 → DHT 更新 → 回调。
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

	// 启动 relay 自动注册管理器。
	go n.relayManager()

	// 注册到初始 relay 并开始 accept 循环。
	return n.registerAndServe(addr)
}

// registerAndServe 向单个 relay 注册，并在拿到的注册流上处理入站 hello。
// 注册流故障后返回；relay 管理器会按需创建新的注册。
func (n *NATNode) registerAndServe(addr string) error {
	stream, err := n.transport.Register(n.ctx, addr, n.identity.Pubkey())
	if err != nil {
		return fmt.Errorf("natnode: 向 %s 注册失败: %w", addr, err)
	}

	n.mu.Lock()
	n.registeredRelays[addr] = &relayEntry{addr: addr, stream: stream}
	n.mu.Unlock()

	return n.handleInboundHello(addr, stream)
}

// handleInboundHello 在已注册的流上等待 hello，完成 TLS 握手与元数据交换，
// 更新路由表，触发 onConnection 回调。
// 一次握手后该流被加密并专属于该对端；后续连接走其他注册流。
func (n *NATNode) handleInboundHello(relayAddr string, stream network.Stream) error {
	// 读取对端经 relay 发来的首条消息（hello）。
	firstMsg, err := stream.NextMessage(n.ctx)
	if err != nil {
		n.mu.Lock()
		delete(n.registeredRelays, relayAddr)
		n.mu.Unlock()
		return err
	}

	// 从 hello payload 获取对端公钥 hex，构造远程节点条目。
	peerPubKeyHex := string(firstMsg.Payload)
	remoteNode, err := DHTable.NewNodeFromPubKeyHex(peerPubKeyHex)
	if err != nil {
		n.mu.Lock()
		delete(n.registeredRelays, relayAddr)
		n.mu.Unlock()
		return fmt.Errorf("natnode: 解析对端公钥失败: %w", err)
	}

	// 先在原始流上绑定对端身份（必须在 StreamClient 包装之前）。
	if !networkFrameWork.SetStreamIdentity(stream, remoteNode.PeerID(), firstMsg.Header.ConnectionId) {
		n.mu.Lock()
		delete(n.registeredRelays, relayAddr)
		n.mu.Unlock()
		return fmt.Errorf("natnode: SetStreamIdentity 失败, peer: %s", remoteNode.PeerID())
	}

	peerID := p2pnode.NodeID(remoteNode.PeerID())

	// 用 StreamClient 包装，提供心跳过滤与 ConnectionId 自填充。
	sc := client.NewStreamClient(stream)

	// 执行服务端 TLS 握手。
	peerInfo, err := n.handshake.HandshakeIncoming(n.ctx, sc, firstMsg)
	if err != nil {
		n.mu.Lock()
		delete(n.registeredRelays, relayAddr)
		n.mu.Unlock()
		return fmt.Errorf("natnode: 与 %s 握手失败: %w", peerID, err)
	}

	// 交换元数据：发送己方 NodeID + relay 列表，接收对方。
	peerRelays, err := n.exchangeMetadata(sc, peerID)
	if err != nil {
		n.mu.Lock()
		delete(n.registeredRelays, relayAddr)
		n.mu.Unlock()
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

	conn := newNATConnection(peerInfo, sc)
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
	log.Printf("[exchangeMetadata] 发送 metadata: peerID=%.16s connId=%s payloadLen=%d preview=%q",
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
	log.Printf("[exchangeMetadata] 收到 metadata: peerID=%.16s headerNodeId=%.16s headerConnId=%s headerRoute=%s payloadLen=%d hexPreview=%x asciiPreview=%q",
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

// Connect 查找 target 并通过 relay 建立连接。
func (n *NATNode) Connect(ctx context.Context, target p2pnode.NodeID) (p2pnode.Connection, error) {
	// 快速路径：已连接则直接返回。
	n.mu.RLock()
	if conn, ok := n.conns[target]; ok {
		n.mu.RUnlock()
		return conn, nil
	}

	// 查 target 的已知 relay 地址。
	addrs := n.peerAddrIndex[target]
	known := make([]string, 0, len(n.knownRelays))
	for r := range n.knownRelays {
		known = append(known, r)
	}
	n.mu.RUnlock()

	var relayAddr string
	if len(addrs) > 0 {
		relayAddr = addrs[0].Relay
	} else if len(known) > 0 {
		// 无 target 专用 relay 地址，尝试任一已知 relay。
		relayAddr = known[0]
	} else {
		return nil, fmt.Errorf("natnode: 无 target %s 的 relay 地址", target)
	}

	// 经 relay 拨号。
	rawStream, _, err := n.transport.Dial(ctx, relayAddr, target)
	if err != nil {
		return nil, fmt.Errorf("natnode: 经 %s 拨号 %s 失败: %w", relayAddr, target, err)
	}

	// 用 StreamClient 包装。
	sc := client.NewStreamClient(rawStream)

	// 执行客户端 TLS 握手。
	peerInfo, err := n.handshake.HandshakeOutgoing(ctx, sc, target)
	if err != nil {
		sc.Close()
		return nil, fmt.Errorf("natnode: 与 %s 握手失败: %w", target, err)
	}

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
	conn := newNATConnection(peerInfo, sc)
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
					LastSeen:  time.Unix(node.LastCalled(), 0),
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
			LastSeen:  time.Unix(node.LastCalled(), 0),
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
	})
	return errors.Join(errs...)
}

// relayManager 定期检查活跃 relay 注册数，维持至少 3 个。
// 不足时从 knownRelays 中选取未注册 relay 尝试注册。
func (n *NATNode) relayManager() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}

		n.mu.RLock()
		count := len(n.registeredRelays)
		n.mu.RUnlock()

		if count >= 3 {
			continue
		}

		n.mu.Lock()
		var candidates []string
		for addr := range n.knownRelays {
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
			currentCount := len(n.registeredRelays)
			n.mu.RUnlock()

			if alreadyRegistered || currentCount >= 3 {
				break
			}

			// 每条注册在独立 goroutine 中服务。
			go func(a string) {
				if err := n.registerAndServe(a); err != nil {
					// registerAndServe 已在错误时做清理。
					// 生产环境可在此处加日志。
				}
			}(addr)
		}
	}
}
