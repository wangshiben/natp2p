package client

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"context"
	"crypto/ecdh"
	"errors"
	"sync"
)

// StreamClient 是用户侧最终拿到的 Stream 封装。
//
// 它不直接实现新的 relay frame 接口，只继续暴露 network.Stream 语义：
// 调用方只关心完整 Message 的收发，不需要知道底层是直连 TCP、KCP，还是通过公网 relay 转发。
//
// 字段说明：
//
//	stream  底层真实连接。当前 ConnectNodeWithTargetRelay 会通过 TryConnectTCPStream
//	        连到公网 relay，并让 relay 再转发到目标 node。
//	exit    本地关闭信号。NextMessage 会同时监听 exit、ctx 和底层 stream，
//	        任何一方结束都会让读取返回错误。
type StreamClient struct {
	stream    network.Stream
	exit      chan struct{}
	closeOnce sync.Once
}

// NewStreamClient 把一条已经完成握手/身份绑定的底层 network.Stream 包装成用户侧 StreamClient。
//
// 参数：
//
//	stream  必须是可正常收发 Message 的底层流；调用方应在包装前完成必要的身份绑定
//	        （例如 SetStreamIdentity）和加密套件安装（SetCryptoSuite）。
//
// 使用场景：
//   - client 模式通常直接调用 ConnectNodeWithTargetRelay，它内部会创建 StreamClient。
//   - relayServer 模式需要先用底层 stream 等待对端首条 hello、完成 TLS 握手，之后再调用
//     本函数统一接入 StreamClient 的心跳过滤和 ConnectionId 自动填充逻辑。
func NewStreamClient(stream network.Stream) *StreamClient {
	return &StreamClient{
		stream: stream,
		exit:   make(chan struct{}),
	}
}

// Close 关闭用户侧 StreamClient。
//
// 行为：
//  1. 先关闭底层 stream，触发底层连接、ACK 等待、NextMessage 阻塞读取退出。
//  2. 再向 exit 写入关闭信号，让 StreamClient.NextMessage 可以返回 "stream closed"。
func (s *StreamClient) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.stream.Close()
		close(s.exit)
	})
	return err
}

// NextMessage 读取下一条用户业务消息。
//
// 参数：
//
//	ctx  调用方传入的取消/超时上下文；超时、主动取消时直接返回 ctx.Err()。
//
// 处理逻辑：
//   - 若 StreamClient.Close() 发出 exit 信号，返回 "stream closed"。
//   - 若 ctx 取消，返回 ctx.Err()。
//   - 否则从底层 stream.NextMessage(ctx) 读取完整 Message。
//   - KeepAliveRoute 是底层保活包，对业务方没有意义，所以这里过滤掉并继续读下一条。
//
// 返回值：
//   - 非心跳业务 Message
//   - 或底层读取/上下文/关闭错误
func (s *StreamClient) NextMessage(ctx context.Context) (*network.Message, error) {
	for {
		select {
		case <-s.exit:
			return nil, errors.New("stream closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			message, err := s.stream.NextMessage(ctx)
			if err != nil {
				return nil, err
			}
			if message.Header.RouteName != networkFrameWork.KeepAliveRoute {
				return message, nil
			}
		}

	}
}

// SendMessage 发送一条用户业务消息。
//
// 参数：
//
//	ctx      控制本次发送的超时/取消；底层 SendMessage 是阻塞式发送，会等待 ACK 或重传完成。
//	message  调用方准备好的业务消息。这里会覆盖 message.Header.ConnectionId，
//	         强制使用底层 stream 在连接建立时分配出的 ConnectionId。
//
// 为什么要覆盖 ConnectionId：
// relay 依赖 Header.ConnectionId 把设备1回包路由回正确的 client leg。
// 用户侧不应该手动填写或复用其它连接的 ConnectionId，否则公网 relay 会找错连接。
func (s *StreamClient) SendMessage(ctx context.Context, message *network.Message) error {
	select {
	case <-s.exit:
		return errors.New("stream closed")
	default:
	}
	message.Header.ConnectionId = s.stream.ConnectionId()
	err := s.stream.SendMessage(ctx, message)
	if err != nil {
		return err
	}
	return nil
}

// NodeId 返回底层 stream 当前认为的对端 NodeId。
// 对 ConnectNodeWithTargetRelay 来说，这通常是目标 node 的 NodeId，而不是 relay 服务器本身。
func (s *StreamClient) NodeId() string {
	return s.stream.NodeId()
}

// ConnectionId 返回本次通过 relay 建立的业务连接 ID。
// 该值由 TryConnectTCPStream 生成，并在后续所有 SendMessage 中用于 relay 路由。
func (s *StreamClient) ConnectionId() string {
	return s.stream.ConnectionId()
}

// SetCryptoSuite 给底层 stream 安装加解密套件。
//
// 参数 suite：通过 TLS/ECDH 握手得到的加密实现。安装后，底层 SendMessage 会先加密 Payload，
// NextMessage 在重组完成后会解密 Payload；StreamClient 自身不直接处理加解密细节。
func (s *StreamClient) SetCryptoSuite(suite network.EncrypSuite) {
	s.stream.SetCryptoSuite(suite)
}

// ConnectNodeWithTargetRelay 通过指定公网 relay 连接到目标 node。
//
// 这是用户侧最常用的入口：设备2调用它，连到公网 relay；relay 再根据 nodeId 找到
// 已注册的设备1，并把两端流量桥接起来。
//
// 参数：
//
//	nodeId     目标 node 的 ID（也就是设备1注册到 relay 时公布的 NodeId）。
//	relayAddr  公网 relay 地址，例如 "1.2.3.4:9000"。
//	keyPair    当前客户端自己的 ECDH 私钥；本函数只读取它，不保存它。
//
// 建连流程：
//  1. 从 keyPair 取出公钥字符串 originNodeId，作为本客户端身份材料。
//  2. TryConnectTCPStream(relayAddr, nodeId, originNodeId) 连接公网 relay，
//     并发送首条 hello 消息。该函数会生成本次业务连接的 ConnectionId。
//  3. crypoto.NewTLSCrypto(stream, keyPair) 基于底层 stream 做一次握手，
//     确认对端确实持有目标 node 的私钥，并生成后续 Payload 加解密套件。
//  4. 构造 StreamClient，把加密套件安装到底层 stream。
//
// 返回值：
//
//	*StreamClient  用户后续收发业务 Message 使用的对象。
//	string         本次业务连接的 ConnectionId；可用于日志/测速统计。
//	error          任一步失败时返回错误。
func ConnectNodeWithTargetRelay(nodeId, relayAddr string, keyPair *ecdh.PrivateKey) (*StreamClient, string, error) {
	pubKey := keyPair.PublicKey()
	originNodeId := crypoto.GetPubKeyStr(pubKey)
	stream, ConnectionId, err := networkFrameWork.TryConnectTCPStream(relayAddr, nodeId, originNodeId)
	if err != nil {
		return nil, "", err
	}
	crypto, err := crypoto.NewTLSCrypto(stream, keyPair)
	if err != nil {
		return nil, "", err
	}
	res := NewStreamClient(stream)
	res.SetCryptoSuite(crypto)
	return res, ConnectionId, nil
}
