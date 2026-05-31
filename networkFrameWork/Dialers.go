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
	connectionId := uuid.New().String()
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
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetMtu(1000)
	conn.SetWriteBuffer(4 * 1024 * 1024)
	conn.SetWindowSize(128, 512)

	res := startTcpStream(originalNodeId, connectionId, conn)
	if err := res.SendMessage(handshakeCtx, cloneMessage(FirstMessage)); err != nil {
		res.Close()
		return nil, err
	}
	go res.keepLive()
	return res, nil
}
