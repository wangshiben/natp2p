package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"errors"
	"net"
	"os"
	"sync"
)

var bridgeDebug = os.Getenv("BRIDGE_DEBUG") != ""

func logBridge(format string, args ...interface{}) {
	logx.Debugf("[BRIDGE] "+format, args...)
}

var errInvalidBridgeLeg = errors.New("relaynode bridge: leg 非 TcpStream")

// CrossRelayBridge 实现 relay→relay 的逐帧跨中继桥接。
//
// local 侧可能同时存在 KCP/TCP 或双 TCP 多条 leg。每条 leg 先独立解析完整 Frame，
// 再由 DualFrameRelayEndpoint 汇聚、去重和重放，避免旧 leg 的半帧与新 leg 的重传
// 在 peer 字节流中拼接。peer 侧也必须经过独立的 DualFrameRelayEndpoint：它隔离远端
// 入站 MessageId 与本端分配的出站 MessageId，frameRouteRegistry 再负责两侧命名空间映射。
type CrossRelayBridge struct {
	connID         string
	hostAddr       string
	targetNodeID   string
	originPubKey   string
	ctx            context.Context
	cancel         context.CancelFunc
	dialBridgeConn func(addr, targetNodeId, originPubKeyHex, connID string) (net.Conn, error)

	mu          sync.Mutex
	peerConn    net.Conn
	peerDual    *DualStream
	peerFrame   *DualFrameRelayEndpoint
	localDual   *DualStream
	localFrame  *DualFrameRelayEndpoint
	frameRoutes *frameRouteRegistry
	localConns  []net.Conn
	started     bool
}

// newCrossRelayBridge 由 relaynode 通过 NewCrossRelayBridge 构造。
func newCrossRelayBridge(parent context.Context, hostAddr, targetNodeID, originPubKey, connID string) *CrossRelayBridge {
	ctx, cancel := context.WithCancel(parent)
	return &CrossRelayBridge{
		connID:         connID,
		hostAddr:       hostAddr,
		targetNodeID:   targetNodeID,
		originPubKey:   originPubKey,
		ctx:            ctx,
		cancel:         cancel,
		dialBridgeConn: dialRawBridgeConn,
	}
}

// NewCrossRelayBridge 创建一个逐帧跨中继桥接。
//
//	hostAddr      托管目标 nat 节点的对端 relay 地址。
//	targetNodeID  目标 nat 节点 NodeId。
//	originPubKey  源节点(local1)公钥 hex, 作为裸拨连接的 hello 首包发往对端 relay。
//	connID        local1 的原始业务 connID, 透传以便对端 relay 识别。
func NewCrossRelayBridge(parent context.Context, hostAddr, targetNodeID, originPubKey, connID string) *CrossRelayBridge {
	return newCrossRelayBridge(parent, hostAddr, targetNodeID, originPubKey, connID)
}

func (b *CrossRelayBridge) Done() <-chan struct{} {
	return b.ctx.Done()
}

// SetDialFunc 覆盖桥接拨号函数。连接池（Phase B+）用它把"裸拨独占物理连接"替换为
// "从池里开一条 mux 会话"。dial 的入参与默认 dialRawBridgeConn 一致，返回的 net.Conn
// 由桥接在会话结束时 Close（对池化 stream 即关闭该逻辑会话，不影响共享物理连接）。
func (b *CrossRelayBridge) SetDialFunc(dial func(addr, targetNodeId, originPubKeyHex, connID string) (net.Conn, error)) {
	b.dialBridgeConn = dial
}

// SpliceLeg 把源节点的一条底层流接入桥接。第一次调用时建立到对端 relay 的唯一连接并启动
// 双向 frame pump；后续调用把额外 local leg 接入同一个逻辑 frame endpoint。
// stream 必须是 AcceptTcpStreamSync 得到、尚未启动 readLoop 的 *TcpStream。
func (b *CrossRelayBridge) SpliceLeg(stream network.Stream) error {
	return b.SpliceLegWithFlags(stream, false, false)
}

func (b *CrossRelayBridge) SpliceLegCoexist(stream network.Stream, coexist bool) error {
	return b.SpliceLegWithFlags(stream, coexist, false)
}

func (b *CrossRelayBridge) SpliceLegWithFlags(stream network.Stream, coexist, resume bool) error {
	tcp := TCPStreamOf(stream)
	if tcp == nil {
		return errInvalidBridgeLeg
	}
	localConn := tcp.RawConn()

	b.mu.Lock()
	select {
	case <-b.ctx.Done():
		b.mu.Unlock()
		return errors.New("relaynode bridge: bridge closed")
	default:
	}
	if !b.started {
		b.mu.Unlock()
		peerConn, err := b.dialBridgeConn(b.hostAddr, b.targetNodeID, b.originPubKey, b.connID)
		if err != nil {
			return err
		}
		b.mu.Lock()
		select {
		case <-b.ctx.Done():
			b.mu.Unlock()
			_ = peerConn.Close()
			return errors.New("relaynode bridge: bridge closed")
		default:
		}
		if b.started {
			b.mu.Unlock()
			_ = peerConn.Close()
			return b.SpliceLegWithFlags(stream, coexist, resume)
		}
		localDual := newDualStreamWithPump(b.targetNodeID, b.connID, false)
		if err := localDual.attachStreamCoexist(stream, coexist, resume); err != nil {
			b.mu.Unlock()
			_ = peerConn.Close()
			return err
		}
		localFrame := localDual.EnableFrameRelay()
		peerStream := newTcpStream(b.targetNodeID, b.connID, peerConn)
		// 对端 prefixConn 会先注入固定 MessageId=1 的合成 hello，并把它记录成
		// firstMsgID。peer carrier 必须跳过这个 ID，否则第一条真实业务帧也用 1，
		// 会被对端 pure-forwarder 当作 hello 重传 ACK 后丢弃。
		_ = peerStream.AllocMessageId()
		peerDual := newDualStreamWithPump(b.targetNodeID, b.connID, false)
		if err := peerDual.attachStreamCoexist(peerStream, false, false); err != nil {
			b.mu.Unlock()
			_ = localDual.Close()
			_ = peerConn.Close()
			return err
		}
		peerFrame := peerDual.EnableFrameRelay()
		if localFrame == nil || peerFrame == nil {
			b.mu.Unlock()
			_ = localDual.Close()
			_ = peerDual.Close()
			return errors.New("relaynode bridge: frame relay unavailable")
		}
		b.peerConn = peerConn
		b.peerDual = peerDual
		b.peerFrame = peerFrame
		b.localDual = localDual
		b.localFrame = localFrame
		b.frameRoutes = newFrameRouteRegistry()
		b.started = true
		b.localConns = append(b.localConns, localConn)
		frameRoutes := b.frameRoutes
		b.mu.Unlock()

		go b.pumpLocalFrames(localFrame, peerFrame, frameRoutes)
		go b.pumpPeerFrames(peerFrame, localFrame, frameRoutes)
		peerStream.StartLoops()
		go peerStream.keepLive()
		// NAT 侧由端节点的 DualStream 统一发送经 E2E 封装的逻辑心跳。
		// Relay 不得在这条腿注入 TcpStream 的明文 /ping，否则会破坏已建立的 Noise 会话。
		tcp.StartLoops()
		return nil
	}
	localDual := b.localDual
	if localDual == nil {
		b.mu.Unlock()
		return errors.New("relaynode bridge: local frame relay unavailable")
	}
	b.mu.Unlock()
	if err := localDual.attachStreamCoexist(stream, coexist, resume); err != nil {
		return err
	}
	if detectStreamTransport(stream) == streamTransportTCP {
		localDual.retireStaleKCPWhenDualTCPReady()
	}
	b.mu.Lock()
	b.localConns = append(b.localConns, localConn)
	b.mu.Unlock()
	// 后续 NAT 腿同样只接收端节点的 E2E 逻辑心跳，不启动物理层明文心跳。
	tcp.StartLoops()
	return nil
}

func (b *CrossRelayBridge) pumpLocalFrames(local, peer FrameRelayEndpoint, routes *frameRouteRegistry) {
	pumpClientToRelay(b.ctx, local, peer, routes, nil, b.targetNodeID)
	b.cancel()
}

func (b *CrossRelayBridge) pumpPeerFrames(peer, local FrameRelayEndpoint, routes *frameRouteRegistry) {
	pumpRelayToClients(b.ctx, peer, func(connectionID string) FrameRelayEndpoint {
		if connectionID != b.connID {
			return nil
		}
		return local
	}, routes, nil, b.targetNodeID, func(string, FrameRelayEndpoint) {
		b.cancel()
	})
	b.cancel()
}

// Close 关闭桥接的所有连接。
func (b *CrossRelayBridge) Close() {
	b.cancel()
	b.mu.Lock()
	peerDual := b.peerDual
	peerConn := b.peerConn
	localDual := b.localDual
	localConns := append([]net.Conn(nil), b.localConns...)
	b.mu.Unlock()
	if localDual != nil {
		_ = localDual.Close()
	}
	if peerDual != nil {
		_ = peerDual.Close()
	} else if peerConn != nil {
		_ = peerConn.Close()
	}
	for _, c := range localConns {
		_ = c.Close()
	}
}

// dialRawBridgeConn 建立一条到对端 relay 的「跨中继会话」连接。
//
// 多路复用版：为每个会话单拨一条物理 TCP + 物理握手 + 在其上开一条 mux stream，
// 返回该 muxStream（实现 net.Conn）。会话结束关闭 muxStream 时一并关闭其独占的物理连接。
// 注意：这是 Phase A 的"每会话独立物理连接"形态；连接池（Phase B）会改为
// 复用共享物理连接，届时 CrossRelayBridge 不再走本函数，而由池注入 muxStream。
func dialRawBridgeConn(addr, targetNodeId, originPubKeyHex, connID string) (net.Conn, error) {
	sess, err := DialBridgeMuxSession(context.Background(), addr, targetNodeId)
	if err != nil {
		return nil, err
	}
	st, err := sess.OpenStream(connID, targetNodeId, originPubKeyHex)
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	// Phase A：物理连接与会话一一对应，MuxStream 关闭即关物理会话。
	return &ownedMuxConn{MuxStream: st, sess: sess}, nil
}

// ownedMuxConn 把一条独占物理会话的 MuxStream 包装成 net.Conn：
// Close 时同时关闭其独占的 MuxSession（含底层物理连接）。
type ownedMuxConn struct {
	*MuxStream
	sess *MuxSession
}

func (c *ownedMuxConn) Close() error {
	_ = c.MuxStream.Close()
	return c.sess.Close()
}

// LegTransport 返回一条流底层 leg 的传输类型字符串("kcp"/"tcp"/"")。
// relay 桥接用它来确定性地只桥接源节点 send-preferred 的那条 leg。
func LegTransport(s network.Stream) string {
	tcp := TCPStreamOf(s)
	if tcp == nil {
		return ""
	}
	if _, ok := tcp.RawConn().(interface{ SetWindowSize(int, int) }); ok {
		return "kcp" // *kcp.UDPSession 有 SetWindowSize
	}
	return "tcp"
}

// ActiveLegCount reports the currently attached physical legs of a stream.
// Service health snapshots use it to distinguish a reconnecting carrier from
// one that still has an actual TCP/KCP path.
func ActiveLegCount(stream network.Stream) int {
	if stream == nil {
		return 0
	}
	if dual, ok := stream.(*DualStream); ok {
		return len(dual.legStreams())
	}
	if tcp, ok := stream.(*TcpStream); ok && tcp.IsClosed() {
		return 0
	}
	return 1
}
