package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/xtaci/kcp-go/v5"
	"net"
	"time"
)

const (
	tcpMode              = "tcp"
	udpMode              = "udp"
	dialHandshakeTimeout = 1500 * time.Millisecond
)

// TryConnectTCPStream 客户端主动连指定 relay 并把首条消息送出去，
// 拿到一个已绑定 targetNodeId / connectionId 的逻辑流。
//
// 行为：
//   - 生成一个新的 uuid 作为 connectionId；
//   - 默认走 dual（KCP+TCP 同时拨号，任一成功即返回）；
//   - 首条消息的 Header 用调用方传入的 targetNodeId 标识对端身份，
//     Payload 是发起方自己的 hex 公钥，供对端推导 NodeId。
func TryConnectTCPStream(addr, targetNodeId, originalPubkeyHex string) (network.Stream, string, error) {
	return TryConnectTCPStreamWithConnID(addr, targetNodeId, originalPubkeyHex, uuid.New().String())
}

// TryConnectTCPStreamWithConnID 与 TryConnectTCPStream 相同, 但使用调用方指定的 connectionId
// 而不是新生成一个。
//
// relayNode 跨中继转发时必须用它：把 local1 的原始 connectionId 一路透传到对端 relay,
// 使端到端 connectionId 在 local1↔local2 之间保持一致。否则 relay1 另起新 connId 会让
// 对端节点用不同 connId 应答, 破坏帧路由表 / E2E messageId 去重的一致性。
func TryConnectTCPStreamWithConnID(addr, targetNodeId, originalPubkeyHex, connectionId string) (network.Stream, string, error) {
	header := &network.Header{
		RouteName:     "",
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	stream, err := clientStream(body, addr, targetNodeId, connectionId, true)
	return stream, connectionId, err
}

// TryConnectControlStream 建立一条「带 RouteName 标记」的业务连接。
//
// 与 TryConnectTCPStream 唯一的区别是首条 hello 消息的 Header.RouteName 由调用方指定，
// 而不是固定为空。relayNode 用它建立 relay→relay 控制链路：把 routeName 设为
// RelayControlRoute，对端 relay 在 MissingGroupHandler 里据此识别"这是控制链路接入，
// 而不是普通客户端要连接某个本地未托管的 nat 节点"。
//
// 行为与 TryConnectTCPStream 一致：dual 拨号 + 自动重连 dialer，
// 首条消息 Payload 为发起方公钥 hex，供对端推导 NodeId。
func TryConnectControlStream(addr, targetNodeId, originalPubkeyHex, routeName string) (network.Stream, string, error) {
	connectionId := uuid.New().String()
	header := &network.Header{
		RouteName:     routeName,
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	stream, err := clientStream(body, addr, targetNodeId, connectionId, true)
	return stream, connectionId, err
}

// TryRegisterRelayStream 把本节点注册成一条可被中继的「relay 注册流」。
// 此时 ConnectionId 为空，意味着这条流不绑业务连接，专门接受其他客户端通过它中转。
// originalNodeId 由 pubKey 哈希派生，对端用它做身份校验。
func TryRegisterRelayStream(pubKey, relayAddress string) (network.Stream, error) {
	hash := sha256.Sum256([]byte(pubKey))
	originalNodeId := hex.EncodeToString(hash[:])

	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  "",
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(pubKey),
	}
	return clientStream(body, relayAddress, originalNodeId, "", true)
}

// TryRegisterRelayStreamTCP 与 TryRegisterRelayStream 相同, 但只用单条 TCP leg 注册（不走 dual KCP+TCP）。
// 用于跨中继场景下避免 relayStream 的 KCP/TCP 双 leg 在中继转发处的 failover 竞态。
func TryRegisterRelayStreamTCP(pubKey, relayAddress string) (network.Stream, error) {
	hash := sha256.Sum256([]byte(pubKey))
	originalNodeId := hex.EncodeToString(hash[:])
	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		ConnectionId:  "",
	}
	body := &network.Message{Header: header, Payload: []byte(pubKey)}
	return clientStream(body, relayAddress, originalNodeId, "", false)
}

// TryConnectTCPOnlyStream 与 TryConnectTCPStream 相同, 但只用单条 TCP leg 连接（不走 dual）。
// 用于跨中继：源节点单 leg 连入口 relay, 入口 relay 单 leg 桥接, 全链路 TCP 单 leg, 无 failover 竞态。
func TryConnectTCPOnlyStream(addr, targetNodeId, originalPubkeyHex string) (network.Stream, string, error) {
	connectionId := uuid.New().String()
	header := &network.Header{
		RouteName:     "",
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionId,
	}
	body := &network.Message{Header: header, Payload: []byte(originalPubkeyHex)}
	stream, err := clientStream(body, addr, targetNodeId, connectionId, false)
	return stream, connectionId, err
}

// TryRegisterStream : nat后设备注册Stream
// 参数:
//
//	addr: 要连接的中转服务器地址
//	originalPubkeyHex: 自己的公钥
//	streamMode: 可选: tcp/udp，默认udp，若无法连接，则使用tcp
//	targetNodeId: 目标节点的nodeId(如果不是短时连接某一特定节点，则此项可不填)
//
// 返回值:
//
//	network.Stream: 流对象
//	string: 流的connectionId(当targetNodeId不为空时有)
//	error: 错误信息
func TryRegisterStream(addr, originalPubkeyHex, targetNodeId, streamMode string) (network.Stream, string, error) {
	hash := sha256.Sum256([]byte(originalPubkeyHex))
	originalNodeId := hex.EncodeToString(hash[:])
	connectionId := ""
	if len(targetNodeId) != 0 {
		connectionId = uuid.New().String()
	}
	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	if streamMode == udpMode {
		stream, err := clientStream(body, addr, originalNodeId, connectionId, true)
		if err != nil {
			return nil, "", err
		}
		return stream, connectionId, nil
	} else if streamMode == tcpMode {
		stream, err := clientStream(body, addr, originalNodeId, connectionId, false)
		if err != nil {
			return nil, "", err
		}
		return stream, connectionId, nil
	}
	return nil, "", errors.New("wrong stream mode")
}

// clientStream 是底层拨号入口。
//
//	isDefault=false：仅 TCP，单 leg；
//	isDefault=true ：dual 模式，KCP+TCP 同时拨号，任一成功即返回；
//	                 同时为两种协议分别注入重连 dialer，后续 leg 失效会自动重拨。
func clientStream(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string, isDefault bool) (network.Stream, error) {
	if !isDefault {
		return tcpClientStream(FirstMessage, tcpAddr, originalNodeId, connectionId)
	}

	dual := newDualStream(originalNodeId, connectionId)
	template := cloneMessage(FirstMessage)
	var kcpErr error
	var tcpErr error

	kcpClient, err := kcpStream(FirstMessage, tcpAddr, originalNodeId, connectionId)
	if err != nil {
		kcpErr = err
	} else if err := dual.attach(streamTransportKCP, kcpClient); err != nil {
		_ = kcpClient.Close()
		kcpErr = err
	}

	tcpClient, err := tcpClientStream(FirstMessage, tcpAddr, originalNodeId, connectionId)
	if err != nil {
		tcpErr = err
	} else if err := dual.attach(streamTransportTCP, tcpClient); err != nil {
		_ = tcpClient.Close()
		tcpErr = err
	}

	if !dual.HasStream(streamTransportKCP) && !dual.HasStream(streamTransportTCP) {
		if tcpErr != nil {
			return nil, tcpErr
		}
		return nil, kcpErr
	}

	dual.SetReconnectDialer(streamTransportKCP, func(ctx context.Context) (network.Stream, error) {
		return kcpStreamContext(ctx, cloneMessage(template), tcpAddr, originalNodeId, connectionId)
	})
	dual.SetReconnectDialer(streamTransportTCP, func(ctx context.Context) (network.Stream, error) {
		return tcpClientStreamContext(ctx, cloneMessage(template), tcpAddr, originalNodeId, connectionId)
	})
	return dual, nil
}

func tcpClientStream(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string) (network.Stream, error) {
	return tcpClientStreamContext(context.Background(), FirstMessage, tcpAddr, originalNodeId, connectionId)
}

func tcpClientStreamContext(ctx context.Context, FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string) (network.Stream, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, dialHandshakeTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(handshakeCtx, "tcp4", tcpAddr)
	if err != nil {
		return nil, err
	}

	// TCP 优化：禁用 Nagle 算法，设置缓冲区
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(2 * 1024 * 1024)
		_ = tcpConn.SetWriteBuffer(2 * 1024 * 1024)
	}

	res := startTcpStream(originalNodeId, connectionId, conn)
	if err := res.SendMessage(handshakeCtx, cloneMessage(FirstMessage)); err != nil {
		res.Close()
		return nil, err
	}
	go res.keepLive()
	return res, nil
}

func kcpStream(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string) (network.Stream, error) {
	return kcpStreamContext(context.Background(), FirstMessage, tcpAddr, originalNodeId, connectionId)
}

func kcpStreamContext(ctx context.Context, FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string) (network.Stream, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, dialHandshakeTimeout)
	defer cancel()

	conn, err := kcp.DialWithOptions(tcpAddr, nil, 1, 1)
	if err != nil {
		return nil, err
	}
	// 调优 KCP 参数以提升吞吐：
	// - interval 从 50ms 降到 10ms，提升响应速度
	// - MTU 从 1000 提升到 1400（安全的互联网 MTU）
	// - 窗口从 128/512 提升到 256/1024，容纳更多在途数据
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetMtu(1400)
	conn.SetWriteBuffer(4 * 1024 * 1024)
	conn.SetWindowSize(256, 1024)

	res := startTcpStream(originalNodeId, connectionId, conn)
	if err := res.SendMessage(handshakeCtx, cloneMessage(FirstMessage)); err != nil {
		res.Close()
		return nil, err
	}
	go res.keepLive()
	return res, nil
}
