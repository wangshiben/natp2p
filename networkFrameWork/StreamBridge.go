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

// CrossRelayBridge 实现 relay→relay 的「裸 TCP 字节级」跨中继桥接。
//
// 设计定论（见 relaynode-crossrelay-design 记忆）：relay1 退化成一根「哑字节管道」。
// 它既不重写 MessageId、不组包、不发 ACK, 只把 local1 某条底层 TCP 连接上的原始字节
// 与「拨向对端 relay 的一条 TCP 连接」之间双向 io.Copy。
//
// 因此 local1↔local2 之间的 MessageId / ACK / 分帧 / E2E 去重全部端到端,
// relay1 完全透明, 不会出现帧级方案里的 MessageId 命名空间撞车 / ACK 错配。
//
// 多条 leg：local1 经 dual 拨号会有 KCP+TCP 两条 leg, 都在 relay1 触发接入。
// 本桥接只维持「一条」到对端 relay 的连接(peerConn)：
//   - 每条 local leg 读到的字节都写到同一个 peerConn（DualStream 每条逻辑消息只在一条 leg 上发,
//     不会两条 leg 同时发同一消息, 故不会交叉）；
//   - peerConn 读到的对端字节写到「最近活跃的」local leg（local1 的 DualStream 会从所有 leg 读取,
//     写任一条它都能收到）。
//
// 这样既容忍 local1 的 dual leg / failover, 又对对端 relay 表现为单条普通客户端连接。
type CrossRelayBridge struct {
	connID         string
	hostAddr       string
	targetNodeID   string
	originPubKey   string
	ctx            context.Context
	cancel         context.CancelFunc
	dialBridgeConn func(addr, targetNodeId, originPubKeyHex, connID string) (net.Conn, error)

	mu         sync.Mutex
	peerConn   net.Conn
	localConns []net.Conn
	active     net.Conn // 最近活跃的 local leg, peer→local 往它写
	started    bool
	liveLegs   int // 仍在运行的 local leg 数；归零时关闭 peerConn(释放池中逻辑会话)
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

// NewCrossRelayBridge 创建一个裸字节级跨中继桥接。
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
// peer→local 泵；每次调用都为这条 local leg 启动 local→peer 泵。
// stream 必须是 AcceptTcpStreamSync 得到、尚未启动 readLoop 的 *TcpStream。
func (b *CrossRelayBridge) SpliceLeg(stream network.Stream) error {
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
		peerConn, err := b.dialBridgeConn(b.hostAddr, b.targetNodeID, b.originPubKey, b.connID)
		if err != nil {
			b.mu.Unlock()
			return err
		}
		b.peerConn = peerConn
		b.started = true
		go b.pumpPeerToLocal()
	}
	b.localConns = append(b.localConns, localConn)
	// 只有第一条 leg 设为 active；后续 splice 进来的 failover/standby leg 不抢 active。
	// 否则静默 standby 会成为 active，回程(含握手响应)被写到它而非客户端正在收发的数据 leg，
	// 把帧流劈到两条各自独立组帧的 leg 上 → 握手/数据损坏。standby 真正开始发数据时，
	// pumpLocalToPeer 的 Read 会把 active 切到它（见下方 b.active = localConn）。
	if b.active == nil {
		b.active = localConn
	}
	b.liveLegs++
	peerConn := b.peerConn
	b.mu.Unlock()

	if bridgeDebug {
		logBridge("splice leg connID=%s local=%s -> peer=%s", b.connID, localConn.RemoteAddr(), peerConn.RemoteAddr())
	}
	go b.pumpLocalToPeer(localConn)
	return nil
}

// pumpLocalToPeer 把一条 local leg 的字节写到唯一的 peerConn, 并把它标记为当前活跃 leg。
func (b *CrossRelayBridge) pumpLocalToPeer(localConn net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}
		n, err := localConn.Read(buf)
		if n > 0 {
			b.mu.Lock()
			b.active = localConn
			peer := b.peerConn
			b.mu.Unlock()
			if bridgeDebug {
				logBridge("L->P %d bytes (connID=%s)", n, b.connID)
			}
			if _, werr := peer.Write(buf[:n]); werr != nil {
				b.cancel()
				return
			}
		}
		if err != nil {
			// 一条 local leg 结束（含 client 异常断开的 EOF/RST）。仅当所有 leg 都结束时,
			// 才关闭对端 mux stream, 让 CLOSE 帧传播、对端 activeStreams 递减,
			// 池中该逻辑会话得以释放（否则会把仍存活的 failover leg 一起切断）。
			// 池化下 peerConn 是一条 *MuxStream, Close 只关该逻辑会话, 不影响共享物理连接。
			b.mu.Lock()
			b.liveLegs--
			last := b.liveLegs <= 0
			peer := b.peerConn
			b.mu.Unlock()
			if last && peer != nil {
				_ = peer.Close()
			}
			return
		}
	}
}

// pumpPeerToLocal 把对端 relay 的字节写到「最近活跃的」local leg。
// local1 的 DualStream 每条逻辑消息只在一条 leg 上收发, 把回程写到它最近发数据的那条 leg
// 即可被正确读到; 不向多条 leg 重复写, 避免非 E2E 帧（如握手明文）被重复投递。
func (b *CrossRelayBridge) pumpPeerToLocal() {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}
		n, err := b.peerConn.Read(buf)
		if n > 0 {
			b.mu.Lock()
			dst := b.active
			b.mu.Unlock()
			if bridgeDebug {
				logBridge("P->L %d bytes (connID=%s active=%v)", n, b.connID, dst != nil)
			}
			if dst != nil {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					b.cancel()
					return
				}
			}
		}
		if err != nil {
			b.cancel()
			return
		}
	}
}

// Close 关闭桥接的所有连接。
func (b *CrossRelayBridge) Close() {
	b.cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.peerConn != nil {
		_ = b.peerConn.Close()
	}
	for _, c := range b.localConns {
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
