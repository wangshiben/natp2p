package p2pnode

import (
	"bnfs_p2p/network"
	"context"
)

// Transport 抽象底层传输层，解耦 Node 与具体 relay 通信机制。
//
// 所有连接都通过 relay 节点中转建立，不存在直连 IP:port 模式。
// 实现对应：
//   - RelayServer 侧：networkFrameWork.TryRegisterRelayStream
//   - Client 侧：networkFrameWork/client.ConnectNodeWithTargetRelay
type Transport interface {
	// Register 向 relay 注册本节点为可被中继的目标。
	//
	// 实现调用 networkFrameWork.TryRegisterRelayStream(publicKeyHex, relayAddr)，
	// 返回一条与 relay 之间的注册流。后续 relay 会把陌生节点的 Hello 消息转发到这条流上，
	// Node 实现通过该流读取 Hello → 握手 → 接受连接。
	Register(ctx context.Context, relayAddr string, publicKeyHex string) (network.Stream, error)

	// Dial 通过 relay 连接到 target 节点，返回已建立首条消息的可靠流。
	//
	// 实现调用 networkFrameWork/client.ConnectNodeWithTargetRelay(targetID, relayAddr, keyPair)，
	// 返回的 Stream 已发送首条 Hello 消息（含己方公钥），可立刻用于出站握手。
	//
	// 返回值：
	//   stream       — 已发送 Hello 的可靠流
	//   connectionId — relay 分配的业务连接 ID，用于后续 SetStreamIdentity
	Dial(ctx context.Context, relayAddr string, targetID NodeID) (stream network.Stream, connectionId string, err error)
}

// HandshakeHandler 定义入站/出站连接的身份验证逻辑，与现有 crypoto.TLSCrypto 兼容。
//
// 入站握手流程（参考 relayServer.RelayServer 分支）：
//  1. 从 Register 返回的 stream 上 NextMessage 拿到 firstMsg（Payload = 对端公钥 hex）
//  2. 推导对端 NodeID = hex(SHA256(firstMsg.Payload))
//  3. 调用 networkFrameWork.SetStreamIdentity(stream, nodeId, connectionId) 绑定身份
//  4. 调用 HandshakeIncoming 完成 TLS 密钥交换
//  5. 返回 PeerInfo，调用方加入 DHT 路由表
//
// 出站握手流程（参考 relayClient 端）：
//  1. Dial 返回的 stream 已发送首条消息（Payload 为己方公钥 hex）
//  2. 等待对端响应完成 TLS 密钥交换
//  3. 验证对端 NodeID 是否与 Dial 的目标一致
//  4. 返回对端 PeerInfo
type HandshakeHandler interface {
	// HandshakeIncoming 对入站连接执行服务端握手。
	//
	// 实现参考 relayServer：
	//   1. 用 stream 构造 client.NewStreamClient(stream)
	//   2. 用 streamClient + 己方密钥对创建 crypoto.NewTLSCrypto(streamClient, pair)
	//   3. Noise E2E 握手完成后推导对端 PeerInfo
	//
	// 若身份验证失败返回 error，调用方应关闭连接。
	HandshakeIncoming(ctx context.Context, stream network.Stream, firstMsg *network.Message) (PeerInfo, error)

	// HandshakeOutgoing 对出站连接执行客户端握手。
	//
	// expectedID 是期望的对端 NodeID，握手完成后验证对端身份是否匹配。
	// 不匹配则返回 error。
	HandshakeOutgoing(ctx context.Context, stream network.Stream, expectedID NodeID) (PeerInfo, error)
}

// OnConnectionCallback 是新连接建立后的通知回调。
//
// Node 实现会在握手成功、peer 加入路由表后调用此回调（若设置了的话）。
// 上层可在此回调中启动针对该连接的读写 goroutine。
type OnConnectionCallback func(conn Connection)
