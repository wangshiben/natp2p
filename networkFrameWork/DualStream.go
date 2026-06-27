package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"errors"
	"fmt"
	"github.com/xtaci/kcp-go/v5"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	maxReconnectAttempts    = 10
	initialReconnectBackoff = 200 * time.Millisecond
	maxReconnectBackoff     = 5 * time.Second
)

// streamReconnectDialer 在某条协议 leg 失效后被 DualStream 用来重新建立一条同协议的底层流。
// 实现需要响应 ctx 取消并在失败时清理资源，不需要自己实现退避。
type streamReconnectDialer func(ctx context.Context) (network.Stream, error)

// markExtraLeg 给首帧打上"额外并存 leg"标记（编码在固定头部的 LegFlags 字节，可上线传输）。
func markExtraLeg(msg *network.Message) {
	if msg != nil && msg.Header != nil {
		msg.Header.LegFlags |= network.LegFlagExtra
	}
}

// isExtraLegMarked 判断首帧是否带"额外并存 leg"标记。
func isExtraLegMarked(msg *network.Message) bool {
	if msg == nil || msg.Header == nil {
		return false
	}
	return msg.Header.LegFlags&network.LegFlagExtra != 0
}

// streamTransport 标识一条 leg 的唯一 ID。
//
// 历史上它只表示协议种类（"tcp"/"kcp"），DualStream 也只支持 KCP+TCP 两条固定 leg。
// 现在它升级为 leg 的唯一标识：基础 leg 用 "tcp"/"kcp"，同协议的额外 leg 追加 "#2"/"#3"
// 后缀（如 "tcp#2"）。这样 DualStream 可容纳 N 条 leg（含多条同协议 leg），
// 从根上解决"两条 TCP leg 在 relay 侧因同键互相顶替"的问题。
//
// 物理协议族(kcp/tcp)由 legFamily() 从 ID 中提取，用于日志与重连拨号器选择。
type streamTransport string

const (
	streamTransportUnknown streamTransport = ""
	streamTransportTCP     streamTransport = "tcp"
	streamTransportKCP     streamTransport = "kcp"
)

// legEntry 记录一条现役 leg 的底层流与其物理协议族。
type legEntry struct {
	id        streamTransport // 唯一 leg ID（"tcp" / "kcp" / "tcp#2" ...）
	family    streamTransport // 物理协议族：streamTransportKCP / streamTransportTCP
	stream    network.Stream
}

// legFamily 从 leg ID 提取物理协议族（去掉 "#n" 后缀）。
// "tcp"->"tcp", "tcp#2"->"tcp", "kcp"->"kcp"。
func legFamily(id streamTransport) streamTransport {
	s := string(id)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	switch streamTransport(s) {
	case streamTransportKCP:
		return streamTransportKCP
	case streamTransportTCP:
		return streamTransportTCP
	default:
		return streamTransportUnknown
	}
}

// identitySetter / tcpStreamAccessor / messageIDSender 是 DualStream 在内部
// 探测底层 leg 能力时用到的可选接口。任何实现了它们的具体流类型都能被透明利用，
// 既支持 *TcpStream，也方便单测里塞 mock。
type identitySetter interface {
	SetIdentity(nodeId, connectionId string)
}

type tcpStreamAccessor interface {
	TCPStream() *TcpStream
}

type messageIDSender interface {
	sendMessageWithMessageID(ctx context.Context, message *network.Message, messageID []byte) error
}

// DualStream 把同一逻辑连接下的 KCP/TCP 两条底层流聚合成一个 network.Stream。
// SendMessage 默认优先走 KCP，KCP 发送失败后切换到 TCP；NextMessage 汇聚两条底层流的入站消息。
// 该结构体也被 relay 侧复用，用来把同一逻辑会话的多条 leg 收拢成一个逻辑流。
type DualStream struct {
	mu             sync.RWMutex
	preferred      streamTransport
	nodeId         string
	connectionId   string
	crypto         network.EncrypSuite
	collectInbound bool

	// legs 保存所有现役 leg，键为唯一 leg ID。legOrder 维护稳定的主备优先级顺序
	// （先 attach 的排前面），preferred 指向当前主 leg 的 ID。
	legs     map[streamTransport]*legEntry
	legOrder []streamTransport

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	inbox     chan *network.Message

	frameEndpoint *DualFrameRelayEndpoint

	reconnectMu       sync.Mutex
	reconnectDialers  map[streamTransport]streamReconnectDialer
	reconnectActive   map[streamTransport]bool
	reconnectDisabled map[streamTransport]bool
}

func newDualStream(nodeId, connectionId string) *DualStream {
	return newDualStreamWithPump(nodeId, connectionId, true)
}

func newDualStreamWithPump(nodeId, connectionId string, collectInbound bool) *DualStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &DualStream{
		preferred:         streamTransportUnknown,
		nodeId:            nodeId,
		connectionId:      connectionId,
		collectInbound:    collectInbound,
		ctx:               ctx,
		cancel:            cancel,
		inbox:             make(chan *network.Message, inboxBufferSize),
		legs:              make(map[streamTransport]*legEntry),
		reconnectDialers:  make(map[streamTransport]streamReconnectDialer),
		reconnectActive:   make(map[streamTransport]bool),
		reconnectDisabled: make(map[streamTransport]bool),
	}
}

func newDualStreamFromStreams(nodeId, connectionId string, kcpStream, tcpStream network.Stream) *DualStream {
	res := newDualStream(nodeId, connectionId)
	if kcpStream != nil {
		_ = res.attach(streamTransportKCP, kcpStream)
	}
	if tcpStream != nil {
		_ = res.attach(streamTransportTCP, tcpStream)
	}
	if kcpStream == nil {
		res.preferred = streamTransportTCP
	}
	return res
}

func (d *DualStream) Close() error {
	d.closeOnce.Do(func() {
		d.cancel()
		d.mu.Lock()
		streams := make([]network.Stream, 0, len(d.legs))
		for _, entry := range d.legs {
			streams = append(streams, entry.stream)
		}
		d.legs = make(map[streamTransport]*legEntry)
		d.legOrder = nil
		d.mu.Unlock()
		closed := make(map[network.Stream]bool, len(streams))
		for _, s := range streams {
			if s == nil || closed[s] {
				continue
			}
			closed[s] = true
			_ = s.Close()
		}
	})
	return nil
}

func (d *DualStream) NextMessage(ctx context.Context) (*network.Message, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.ctx.Done():
			return nil, errors.New("stream closed")
		case msg := <-d.inbox:
			if msg == nil {
				continue
			}
			// 兜底解密：startPump 在 crypto 未装时可能把密文消息推入 d.inbox。
			// 在应用读取时按当下 d.crypto 再尝试解密一次（成功覆盖、失败原样返回）。
			// 这彻底消除了 TLS 握手 / 元数据交换期间的解密竞态。
			d.mu.RLock()
			crypto := d.crypto
			d.mu.RUnlock()
			if crypto != nil && len(msg.Payload) > 0 {
				if identitySuite, ok := crypto.(network.MessageIdentitySuite); ok {
					decrypted, messageID, hasMessageID, err := identitySuite.DecryptWithMessageID(msg.Payload)
					if err == nil {
						previewLen := len(msg.Payload)
						if previewLen > 16 {
							previewLen = 16
						}
						logx.Debugf("[DualStream] NextMessage 兜底解密成功(E2E): nodeId=%.16s connId=%s 原密文前16字节=%x → 明文长度=%d",
							d.NodeId(), d.ConnectionId(), msg.Payload[:previewLen], len(decrypted))
						msg.Payload = decrypted
						if hasMessageID {
							_ = messageID
						}
					}
					// 解密失败则保留原样（多半因为消息已经在 TcpStream 解过了/或本来就是明文）
				} else {
					if decrypted, err := crypto.Decrypt(msg.Payload); err == nil {
						msg.Payload = decrypted
					}
				}
			}
			return msg, nil
		}
	}
}

// SendMessageAsync 异步发送消息，立即返回。发送结果通过回调通知。
// 内部会自动重试 primary/backup，回调中的 MessageResult 包含最终结果。
// 兼容老代码：如果 callback 为 nil，行为退化为同步阻塞（等价于 SendMessage）。
func (d *DualStream) SendMessageAsync(ctx context.Context, message *network.Message, callback network.MessageResultCallback) error {
	if callback == nil {
		// 兼容模式：同步发送
		return d.SendMessage(ctx, message)
	}

	// 异步模式：立即返回，后台发送
	go func() {
		err := d.SendMessage(ctx, message)

		// 生成消息标识（使用ConnectionId+NodeId前缀）
		msgID := ""
		if message.Header != nil {
			msgID = message.Header.ConnectionId[:8] + "-" + message.Header.NodeId[:8]
		}

		result := network.MessageResult{
			MessageID: msgID,
			Success:   err == nil,
			Error:     err,
			Attempts:  1, // SendMessage 内部已处理 primary/backup 切换
		}

		// 判断使用的传输协议（按当前 preferred leg 的物理族）
		d.mu.RLock()
		switch legFamily(d.preferred) {
		case streamTransportKCP:
			result.UsedTransport = "KCP"
		case streamTransportTCP:
			result.UsedTransport = "TCP"
		default:
			result.UsedTransport = "Unknown"
		}
		d.mu.RUnlock()

		callback(result)
	}()

	return nil
}

// SendMessage 选定 primary/backup 后发送。任一方向写失败会立刻关闭并 detach 失败 leg、
// 调度该协议重连，然后用同一条消息在 backup 上重发，实现实时切换。
// 若两条 leg 都失败或都不存在，关闭整个逻辑流并返回错误。
func (d *DualStream) SendMessage(ctx context.Context, message *network.Message) error {
	primaryKind, primary, backupKind, backup := d.sendOrder()
	if primary == nil && backup == nil {
		logx.Errorf("[DualStream] SendMessage 失败: 双 leg 均不可用, nodeId=%.16s connId=%s",
			d.NodeId(), d.ConnectionId())
		return errors.New("stream closed")
	}
	if primary == nil {
		primaryKind, primary = backupKind, backup
		backupKind, backup = streamTransportUnknown, nil
	}

	messageID := d.newOutgoingMessageID()
	if err := sendMessageWithIdentity(ctx, primary, cloneMessage(message), messageID); err == nil {
		return nil
	} else {
		if ctx.Err() != nil {
			return err
		}
		primaryKindStr := "KCP"
		if primaryKind == streamTransportTCP {
			primaryKindStr = "TCP"
		}
		// 仅当 primary 仍是该 kind 的现役 leg 时才触发失败重连。
		// 否则说明 leg 已被新连接替换，本次写到的是已被关闭的旧 leg，
		// 写失败是路由陈旧而非真实故障，避免触发级联重连。
		d.mu.RLock()
		stillCurrent := d.streamLocked(primaryKind) == primary
		d.mu.RUnlock()
		if stillCurrent {
			logx.Warnf("[DualStream] SendMessage primary %s 失败, 尝试 backup: nodeId=%.16s connId=%s err=%v",
				primaryKindStr, d.NodeId(), d.ConnectionId(), err)
			d.handleLegFailure(primaryKind, primary)
		}
		if backup == nil {
			logx.Errorf("[DualStream] SendMessage 无 backup leg, 返回错误: nodeId=%.16s connId=%s",
				d.NodeId(), d.ConnectionId())
			return err
		}
		if retryErr := sendMessageWithIdentity(ctx, backup, cloneMessage(message), messageID); retryErr != nil {
			backupKindStr := "KCP"
			if backupKind == streamTransportTCP {
				backupKindStr = "TCP"
			}
			if ctx.Err() == nil {
				d.mu.RLock()
				stillCurrentBackup := d.streamLocked(backupKind) == backup
				d.mu.RUnlock()
				if stillCurrentBackup {
					logx.Warnf("[DualStream] SendMessage backup %s 也失败: nodeId=%.16s connId=%s err=%v",
						backupKindStr, d.NodeId(), d.ConnectionId(), retryErr)
					d.handleLegFailure(backupKind, backup)
				}
			}
			return retryErr
		}
		d.setPreferred(backupKind)
		return nil
	}
}

func (d *DualStream) newOutgoingMessageID() []byte {
	d.mu.RLock()
	crypto := d.crypto
	d.mu.RUnlock()
	if suite, ok := crypto.(network.MessageIdentitySuite); ok {
		return suite.NewMessageID()
	}
	return nil
}

func sendMessageWithIdentity(ctx context.Context, stream network.Stream, message *network.Message, messageID []byte) error {
	if sender, ok := stream.(messageIDSender); ok {
		return sender.sendMessageWithMessageID(ctx, message, messageID)
	}
	return stream.SendMessage(ctx, message)
}

func (d *DualStream) NodeId() string {
	d.mu.RLock()
	if d.nodeId != "" {
		defer d.mu.RUnlock()
		return d.nodeId
	}
	streams := make([]network.Stream, 0, len(d.legs))
	for _, id := range d.legOrder {
		if entry := d.legs[id]; entry != nil {
			streams = append(streams, entry.stream)
		}
	}
	d.mu.RUnlock()
	for _, s := range streams {
		if s != nil && s.NodeId() != "" {
			return s.NodeId()
		}
	}
	return ""
}

func (d *DualStream) ConnectionId() string {
	d.mu.RLock()
	if d.connectionId != "" {
		defer d.mu.RUnlock()
		return d.connectionId
	}
	streams := make([]network.Stream, 0, len(d.legs))
	for _, id := range d.legOrder {
		if entry := d.legs[id]; entry != nil {
			streams = append(streams, entry.stream)
		}
	}
	d.mu.RUnlock()
	for _, s := range streams {
		if s != nil && s.ConnectionId() != "" {
			return s.ConnectionId()
		}
	}
	return ""
}

func (d *DualStream) SetCryptoSuite(suite network.EncrypSuite) {
	d.mu.Lock()
	d.crypto = suite
	streams := make([]network.Stream, 0, len(d.legs))
	for _, entry := range d.legs {
		streams = append(streams, entry.stream)
	}
	d.mu.Unlock()
	for _, s := range streams {
		if s != nil {
			s.SetCryptoSuite(suite)
		}
	}
}

func (d *DualStream) SetIdentity(nodeId, connectionId string) {
	d.mu.Lock()
	d.nodeId = nodeId
	d.connectionId = connectionId
	streams := make([]network.Stream, 0, len(d.legs))
	for _, entry := range d.legs {
		streams = append(streams, entry.stream)
	}
	d.mu.Unlock()
	for _, s := range streams {
		applyIdentity(s, nodeId, connectionId)
	}
}

func (d *DualStream) TCPStream() *TcpStream {
	d.mu.RLock()
	defer d.mu.RUnlock()
	// 返回任一 TCP 物理族 leg 的 TcpStream（优先 legOrder 顺序）。
	for _, id := range d.legOrder {
		if entry := d.legs[id]; entry != nil && entry.family == streamTransportTCP {
			if tcp := tcpStreamFromStream(entry.stream); tcp != nil {
				return tcp
			}
		}
	}
	// 兜底：任意 leg 的 TcpStream（KCP leg 底层也是 TcpStream 封装）。
	for _, id := range d.legOrder {
		if entry := d.legs[id]; entry != nil {
			if tcp := tcpStreamFromStream(entry.stream); tcp != nil {
				return tcp
			}
		}
	}
	return nil
}

func (d *DualStream) preferredTransport() streamTransport {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.preferred
}

func (d *DualStream) EnableFrameRelay() *DualFrameRelayEndpoint {
	d.mu.Lock()
	if d.frameEndpoint != nil {
		endpoint := d.frameEndpoint
		d.mu.Unlock()
		return endpoint
	}
	endpoint := NewDualFrameRelayEndpoint(d)
	d.frameEndpoint = endpoint
	type legSnapshot struct {
		id     streamTransport
		stream network.Stream
	}
	snapshot := make([]legSnapshot, 0, len(d.legs))
	for _, id := range d.legOrder {
		if entry := d.legs[id]; entry != nil {
			snapshot = append(snapshot, legSnapshot{id: entry.id, stream: entry.stream})
		}
	}
	d.mu.Unlock()

	attached := false
	for _, s := range snapshot {
		if s.stream != nil && endpoint.AttachStream(s.id, s.stream) == nil {
			attached = true
		}
	}
	if !attached {
		return nil
	}
	return endpoint
}

func (d *DualStream) AttachStream(stream network.Stream) error {
	return d.attachStreamCoexist(stream, false)
}

// AttachStreamCoexist 接入一条 leg；coexist=true 时强制并存（用于双 TCP 的额外 leg，
// 即首帧带 legExtraMarker 的那条），不顶替同协议族已有 leg。
func (d *DualStream) AttachStreamCoexist(stream network.Stream, coexist bool) error {
	return d.attachStreamCoexist(stream, coexist)
}

func (d *DualStream) attachStreamCoexist(stream network.Stream, coexist bool) error {
	family := detectStreamTransport(stream)
	if family == streamTransportUnknown {
		return errors.New("unknown stream transport")
	}
	if coexist {
		// 并存：分配新唯一 ID，不顶替同族 leg。
		_, err := d.attachLeg(family, stream)
		return err
	}
	// 顶替：复用同族现有 leg 的 ID，关闭旧流。
	d.mu.Lock()
	targetID := family
	var oldStream network.Stream
	for _, lid := range d.legOrder {
		if entry := d.legs[lid]; entry != nil && entry.family == family {
			targetID = lid
			oldStream = entry.stream
			break
		}
	}
	d.mu.Unlock()
	if err := d.attachWithID(targetID, family, stream); err != nil {
		return err
	}
	if oldStream != nil && oldStream != stream {
		_ = oldStream.Close()
	}
	return nil
}

func (d *DualStream) HasStream(kind streamTransport) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.streamLocked(kind) != nil
}

// attach 把一条底层流作为新 leg 接入。family 是该 leg 的物理协议族
// (streamTransportKCP / streamTransportTCP)。函数为其分配唯一 leg ID
// （族名占用时追加 "#2"...），存入 legs map 并加入 legOrder 尾部。
//
// 与旧实现不同：不再按"槽位"覆盖同类 leg —— 多条同协议 leg 可共存，
// 这从根上解决了两条 TCP leg 在 relay 侧互相顶替的问题。
func (d *DualStream) attach(family streamTransport, stream network.Stream) error {
	_, err := d.attachLeg(family, stream)
	return err
}

// attachLeg 同 attach，但返回分配到的唯一 leg ID（供调用方按 leg ID 注册重连器）。
func (d *DualStream) attachLeg(family streamTransport, stream network.Stream) (streamTransport, error) {
	if family == streamTransportUnknown {
		return streamTransportUnknown, errors.New("unknown stream transport")
	}
	d.mu.Lock()
	id := d.allocLegIDLocked(family)
	d.mu.Unlock()
	if err := d.attachWithID(id, family, stream); err != nil {
		return streamTransportUnknown, err
	}
	return id, nil
}

// attachWithID 用指定的 leg ID 接入一条 leg。用于重连：保持与失败前相同的 leg ID，
// 使 reconnectDialers / frame adapter 等按 ID 索引的结构保持一致。
func (d *DualStream) attachWithID(id, family streamTransport, stream network.Stream) error {
	if stream == nil {
		return errors.New("stream is nil")
	}
	if id == streamTransportUnknown || family == streamTransportUnknown {
		return errors.New("unknown stream transport")
	}

	d.mu.Lock()
	d.legs[id] = &legEntry{id: id, family: family, stream: stream}
	// 避免重复加入 legOrder（重连复用同 ID 时它可能已被移除，正常追加；若仍在则不重复）。
	present := false
	for _, v := range d.legOrder {
		if v == id {
			present = true
			break
		}
	}
	if !present {
		d.legOrder = append(d.legOrder, id)
	}
	if d.crypto != nil {
		stream.SetCryptoSuite(d.crypto)
	}
	nodeId := d.nodeId
	connectionId := d.connectionId
	frameEndpoint := d.frameEndpoint
	if d.preferred == streamTransportUnknown {
		d.preferred = id
	}
	d.mu.Unlock()

	applyIdentity(stream, nodeId, connectionId)
	if frameEndpoint != nil {
		_ = frameEndpoint.AttachStream(id, stream)
	}
	if d.collectInbound {
		d.startPump(id, stream)
	}
	return nil
}

func (d *DualStream) startPump(id streamTransport, stream network.Stream) {
	kindStr := transportName(legFamily(id))
	go func() {
		for {
			msg, err := stream.NextMessage(d.ctx)
			if err != nil {
				if d.ctx.Err() != nil || isContextError(err) {
					return
				}
				// 关键：仅当本 stream 仍是该 leg ID 的现役 leg 时才触发重连。
				// 否则说明本 leg 已被替换/移除，NextMessage 是因旧流关闭而唤醒退出的，
				// 此时不应再次 handleLegFailure，避免与正常重连流程竞态导致级联重连。
				d.mu.RLock()
				current := d.streamLocked(id)
				d.mu.RUnlock()
				if current != stream {
					return
				}
				logx.Warnf("[DualStream] %s startPump NextMessage 失败: nodeId=%.16s connId=%s leg=%s err=%v",
					kindStr, d.NodeId(), d.ConnectionId(), id, err)
				d.handleLegFailure(id, stream)
				return
			}
			select {
			case <-d.ctx.Done():
				return
			case d.inbox <- msg:
			}
		}
	}()
}

func (d *DualStream) detach(id streamTransport, stream network.Stream) {
	d.mu.Lock()
	var frameEndpoint *DualFrameRelayEndpoint
	if entry := d.legs[id]; entry != nil && entry.stream == stream {
		delete(d.legs, id)
		d.removeLegOrderLocked(id)
		if d.preferred == id {
			d.preferred = d.nextPreferredLocked()
		}
		frameEndpoint = d.frameEndpoint
	}
	empty := len(d.legs) == 0
	d.mu.Unlock()
	// 通知 frame relay 摘除该 leg 的 adapter 并把回写路由切到存活 leg。
	if frameEndpoint != nil {
		frameEndpoint.onLegDetached(id)
	}
	if empty {
		d.Close()
	}
}

// handleLegFailure 在某条 leg 失败时被调用：关闭并 detach 失败 leg。
// 仅在本端为该 leg ID 注册了重连 dialer 时才尝试重连——relay 端没有 dialer（也不该有，
// 因为对端是 NAT 后节点，relay 无法主动拨向它），所以 relay 端只做"关闭+detach"。
func (d *DualStream) handleLegFailure(id streamTransport, stream network.Stream) {
	if stream == nil {
		return
	}
	kindStr := transportName(legFamily(id))

	// 探测是否有注册的重连 dialer（典型为 client 拨号方有，relay 端无）。
	d.reconnectMu.Lock()
	hasDialer := d.reconnectDialers[id] != nil && !d.reconnectDisabled[id]
	d.reconnectMu.Unlock()

	if hasDialer {
		logx.Warnf("[DualStream] %s leg 失败, 关闭并触发重连: nodeId=%.16s connId=%s",
			kindStr, d.NodeId(), d.ConnectionId())
	} else {
		logx.Warnf("[DualStream] %s leg 失败, 关闭(relay 端不重连): nodeId=%.16s connId=%s",
			kindStr, d.NodeId(), d.ConnectionId())
	}

	_ = stream.Close()
	d.detach(id, stream)
	if hasDialer {
		d.scheduleReconnect(id)
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// SetReconnectDialer 为某一种协议设置重连工厂。dialer 必须能从零拉起一条新的同协议底层流，
// 包括首包发送；DualStream 负责按指数退避调用并把成功结果 attach 到自己。
func (d *DualStream) SetReconnectDialer(kind streamTransport, dial streamReconnectDialer) {
	if kind == streamTransportUnknown {
		return
	}
	d.reconnectMu.Lock()
	defer d.reconnectMu.Unlock()
	if dial == nil {
		delete(d.reconnectDialers, kind)
		return
	}
	d.reconnectDialers[kind] = dial
	d.reconnectDisabled[kind] = false
}

func (d *DualStream) hasReconnectChance() bool {
	d.reconnectMu.Lock()
	defer d.reconnectMu.Unlock()
	for kind, dial := range d.reconnectDialers {
		if dial == nil {
			continue
		}
		if d.reconnectDisabled[kind] {
			continue
		}
		return true
	}
	return false
}

// scheduleReconnect 按需启动一个 goroutine，对失败协议按指数退避重新拨号最多 10 次。
// 若 DualStream 已关闭、没有 dialer、该协议已被标记永久失败或已有重连在进行，则不重复启动。
func (d *DualStream) scheduleReconnect(kind streamTransport) {
	if kind == streamTransportUnknown {
		return
	}
	select {
	case <-d.ctx.Done():
		return
	default:
	}
	d.reconnectMu.Lock()
	dial := d.reconnectDialers[kind]
	if dial == nil || d.reconnectDisabled[kind] || d.reconnectActive[kind] {
		d.reconnectMu.Unlock()
		return
	}
	d.reconnectActive[kind] = true
	d.reconnectMu.Unlock()

	go d.runReconnect(kind, dial)
}

func transportName(kind streamTransport) string {
	switch kind {
	case streamTransportKCP:
		return "KCP"
	case streamTransportTCP:
		return "TCP"
	default:
		return "UNKNOWN"
	}
}

func (d *DualStream) runReconnect(id streamTransport, dial streamReconnectDialer) {
	defer func() {
		d.reconnectMu.Lock()
		d.reconnectActive[id] = false
		d.reconnectMu.Unlock()
	}()

	family := legFamily(id)
	kindStr := transportName(family)
	backoff := initialReconnectBackoff
	for attempt := 1; attempt <= maxReconnectAttempts; attempt++ {
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(backoff):
		}

		if d.HasStream(id) {
			return
		}

		stream, err := dial(d.ctx)
		if err == nil && stream != nil {
			if attachErr := d.attachWithID(id, family, stream); attachErr == nil {
				logx.Infof("[DualStream] %s 重连成功: nodeId=%.16s connId=%s leg=%s 第%d次尝试",
					kindStr, d.nodeId, d.connectionId, id, attempt)
				return
			} else {
				logx.Warnf("[DualStream] %s 重连 attach 失败: nodeId=%.16s connId=%s leg=%s 第%d次尝试 err=%v",
					kindStr, d.nodeId, d.connectionId, id, attempt, attachErr)
			}
			_ = stream.Close()
		} else {
			logx.Warnf("[DualStream] %s 重连拨号失败: nodeId=%.16s connId=%s leg=%s 第%d/%d次尝试 err=%v",
				kindStr, d.nodeId, d.connectionId, id, attempt, maxReconnectAttempts, err)
		}

		backoff *= 2
		if backoff > maxReconnectBackoff {
			backoff = maxReconnectBackoff
		}
	}

	d.reconnectMu.Lock()
	d.reconnectDisabled[id] = true
	d.reconnectMu.Unlock()

	d.mu.RLock()
	empty := len(d.legs) == 0
	d.mu.RUnlock()
	logx.Errorf("[DualStream] %s 重连彻底失败(已达%d次上限, 标记永久禁用): nodeId=%.16s connId=%s leg=%s 是否已无现役leg=%v",
		kindStr, maxReconnectAttempts, d.nodeId, d.connectionId, id, empty)
	if empty {
		d.Close()
	}
}

// sendOrder 选出 primary/backup 两条 leg。
// preferred 决定 primary；legOrder 中下一条健康 leg 作 backup。
// 若 preferred 当前不存在，自动用 legOrder 中第一条作为 primary。
// （N-leg 下只取一条 backup —— SendMessage 的主备重试语义保持二元，足够 failover。）
func (d *DualStream) sendOrder() (streamTransport, network.Stream, streamTransport, network.Stream) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	primaryID := d.preferred
	if primaryID == streamTransportUnknown || d.legs[primaryID] == nil {
		primaryID = d.nextPreferredLocked()
	}
	if primaryID == streamTransportUnknown || d.legs[primaryID] == nil {
		return streamTransportUnknown, nil, streamTransportUnknown, nil
	}
	primary := d.legs[primaryID].stream

	// backup：legOrder 中第一条不等于 primary 的现役 leg。
	for _, id := range d.legOrder {
		if id == primaryID {
			continue
		}
		if entry := d.legs[id]; entry != nil {
			return primaryID, primary, id, entry.stream
		}
	}
	return primaryID, primary, streamTransportUnknown, nil
}

func (d *DualStream) setPreferred(kind streamTransport) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.streamLocked(kind) != nil {
		d.preferred = kind
	}
}

// streamLocked 返回指定 leg ID 的现役流（调用方持锁）。
func (d *DualStream) streamLocked(id streamTransport) network.Stream {
	if entry := d.legs[id]; entry != nil {
		return entry.stream
	}
	return nil
}

// hasFamilyLocked 报告是否存在某物理协议族(kcp/tcp)的现役 leg（调用方持锁）。
func (d *DualStream) hasFamilyLocked(family streamTransport) bool {
	for _, entry := range d.legs {
		if entry.family == family {
			return true
		}
	}
	return false
}

// allocLegIDLocked 为新 leg 分配唯一 ID：优先用协议族名("tcp"/"kcp")，
// 若已被现役 leg 占用则追加 "#2"/"#3"... 直到唯一（调用方持锁）。
func (d *DualStream) allocLegIDLocked(family streamTransport) streamTransport {
	if _, ok := d.legs[family]; !ok {
		return family
	}
	for n := 2; ; n++ {
		candidate := streamTransport(fmt.Sprintf("%s#%d", family, n))
		if _, ok := d.legs[candidate]; !ok {
			return candidate
		}
	}
}

// nextPreferredLocked 在当前 preferred 失效后，按 legOrder 选下一条健康 leg 作主 leg
// （调用方持锁）。无可用 leg 时返回 streamTransportUnknown。
func (d *DualStream) nextPreferredLocked() streamTransport {
	for _, id := range d.legOrder {
		if entry := d.legs[id]; entry != nil {
			return id
		}
	}
	return streamTransportUnknown
}

// removeLegOrderLocked 从 legOrder 中移除指定 leg ID（调用方持锁）。
func (d *DualStream) removeLegOrderLocked(id streamTransport) {
	for i, v := range d.legOrder {
		if v == id {
			d.legOrder = append(d.legOrder[:i], d.legOrder[i+1:]...)
			return
		}
	}
}

// legStreams 返回当前所有现役 leg 的底层流快照。
func (d *DualStream) legStreams() []network.Stream {
	d.mu.RLock()
	defer d.mu.RUnlock()
	res := make([]network.Stream, 0, len(d.legs))
	for _, id := range d.legOrder {
		if entry := d.legs[id]; entry != nil {
			res = append(res, entry.stream)
		}
	}
	return res
}

// legIDOrder 返回现役 leg ID 的稳定顺序快照（供 frame relay 按序选回程 leg）。
func (d *DualStream) legIDOrder() []streamTransport {
	d.mu.RLock()
	defer d.mu.RUnlock()
	res := make([]streamTransport, 0, len(d.legOrder))
	for _, id := range d.legOrder {
		if d.legs[id] != nil {
			res = append(res, id)
		}
	}
	return res
}

func applyIdentity(stream network.Stream, nodeId, connectionId string) bool {
	if stream == nil {
		return false
	}
	if setter, ok := stream.(identitySetter); ok {
		setter.SetIdentity(nodeId, connectionId)
		return true
	}
	return false
}

// SetStreamIdentity 是 applyIdentity 的导出别名，提供给外部包（client/relay 等）
// 在握手阶段把 nodeId / connectionId 注入到任意 network.Stream 实现里。
func SetStreamIdentity(stream network.Stream, nodeId, connectionId string) bool {
	return applyIdentity(stream, nodeId, connectionId)
}

func (d *DualStream) PreferTCP() {
	d.mu.Lock()
	defer d.mu.Unlock()
	// 切到 legOrder 中第一条 TCP 物理族 leg。
	for _, id := range d.legOrder {
		if entry := d.legs[id]; entry != nil && entry.family == streamTransportTCP {
			d.preferred = id
			return
		}
	}
}

// PreferTCPStream 只对 *DualStream 生效，把它的 preferred leg 切到 TCP；
// 对其它 stream 类型返回 false，无副作用。
func PreferTCPStream(stream network.Stream) bool {
	dual, ok := stream.(*DualStream)
	if !ok {
		return false
	}
	dual.PreferTCP()
	return true
}

// ensureDualStream 把任意 network.Stream 包装成 *DualStream：
//   - nil       -> 一个空壳 DualStream（无 leg、无 preferred）；
//   - *DualStream -> 直接返回，不重复包装；
//   - 其他      -> 探测协议类型后 attach 进新建的 DualStream。
//
// 方便调用方在统一抽象下处理 leg 切换 / 重连，而不必关心传入的具体类型。
func ensureDualStream(stream network.Stream) *DualStream {
	if stream == nil {
		return newDualStream("", "")
	}
	if dual, ok := stream.(*DualStream); ok {
		return dual
	}
	dual := newDualStream(stream.NodeId(), stream.ConnectionId())
	_ = dual.attach(detectStreamTransport(stream), stream)
	return dual
}

// EnsureDualStream 是 ensureDualStream 的导出版本，供外部包（relaynode 等）把一条底层流
// 收拢成 *DualStream，以便在同一逻辑连接上聚合多条 leg（KCP/TCP）并享受 leg 切换/重连。
func EnsureDualStream(stream network.Stream) *DualStream {
	return ensureDualStream(stream)
}

// detectStreamTransport 返回流的物理协议族：DualStream 取它现役 leg 的族
// （优先 KCP）；普通 carrier 看底层 net.Conn 是不是 *kcp.UDPSession，否则当 TCP。
func detectStreamTransport(stream network.Stream) streamTransport {
	if dual, ok := stream.(*DualStream); ok {
		dual.mu.RLock()
		defer dual.mu.RUnlock()
		if dual.hasFamilyLocked(streamTransportKCP) {
			return streamTransportKCP
		}
		if dual.hasFamilyLocked(streamTransportTCP) {
			return streamTransportTCP
		}
		return streamTransportUnknown
	}
	carrier, ok := stream.(interface{ Connection() net.Conn })
	if !ok {
		return streamTransportUnknown
	}
	if _, ok := carrier.Connection().(*kcp.UDPSession); ok {
		return streamTransportKCP
	}
	return streamTransportTCP
}

// tcpStreamFromStream 抽出底层的 *TcpStream（如果有）。
// 支持三种来源：实现 tcpStreamAccessor 接口的包装类型、原生 *TcpStream，或返回 nil。
func tcpStreamFromStream(stream network.Stream) *TcpStream {
	if stream == nil {
		return nil
	}
	if accessor, ok := stream.(tcpStreamAccessor); ok {
		return accessor.TCPStream()
	}
	if tcpStream, ok := stream.(*TcpStream); ok {
		return tcpStream
	}
	return nil
}

// TCPStreamOf 是 tcpStreamFromStream 的导出别名，给 relay / client 包用。
func TCPStreamOf(stream network.Stream) *TcpStream {
	return tcpStreamFromStream(stream)
}

// cloneMessage 深拷贝一条消息，避免重发 / 重写时改坏调用方原始数据。
func cloneMessage(message *network.Message) *network.Message {
	if message == nil {
		return nil
	}
	clone := &network.Message{
		Payload: append([]byte(nil), message.Payload...),
	}
	if message.Header != nil {
		header := *message.Header
		header.OriginData = append([]byte(nil), message.Header.OriginData...)
		clone.Header = &header
	}
	return clone
}
