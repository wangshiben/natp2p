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
	b.active = localConn
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

// dialRawBridgeConn 裸拨一条到对端 relay 的 TCP 连接, 并把 local1 的 hello 作为首帧发出。
// 返回的 net.Conn 之后只做裸字节转发, 不再有任何 TcpStream 逻辑。
func dialRawBridgeConn(addr, targetNodeId, originPubKeyHex, connID string) (net.Conn, error) {
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		return nil, err
	}
	// 首帧：把 local1 的 hello（Header.NodeId=target, Payload=local1 公钥, ConnectionId=connID）
	// 按帧格式发出, 与普通客户端连 relay 的首包一致, 触发对端 relay 的 StreamOn。
	header := &network.Header{
		RouteName:     "",
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		ConnectionId:  connID,
	}
	msg := &network.Message{Header: header, Payload: []byte(originPubKeyHex)}
	frames, err := msg.ToFrames(1)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	for _, f := range frames {
		bs, err := f.ParseToBytes()
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := conn.Write(bs); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
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
