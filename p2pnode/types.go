// Package p2pnode 定义 P2P 网络「节点层」的抽象接口与基础类型。
//
// 架构定位：
//
//	network          — 原始帧格式 / Header / Message 定义
//	networkFrameWork — 单流可靠性 (TcpStream/DualStream)、帧转发 relay、StreamGroup
//	p2pnode          — 节点寻址、DHT 路由表、握手、广播（本层）
//
// 本包仅定义接口和基础类型，不包含具体实现。
//
// 设计核心：
//  1. NodeID = hex(SHA256(公钥))，延续现有身份体系，保证与 relay/crypto 层互通。
//  2. 路由表复用项目已有的 interfaces.DHTTable（DHTable 包实现），XOR 距离度量统一寻址。
//  3. 所有连接都通过 relay 节点中转建立，没有直连 IP:port 模式。
//     Connect(id) 和 Listen 底层都是与 relay 交互，对上层调用方透明。
//  4. 入站连接经过握手/身份验证后自动加入路由表，无需调用方手动管理。
//  5. 广播沿路由表邻居泛洪，带 TTL 防环、RequestID 去重。
package p2pnode

import (
	"bnfs_p2p/network"
	"context"
	"math/big"
	"time"
)

// NodeID 是 P2P 网络中节点的全局唯一标识。
// 值由公钥 hex 字符串进行 SHA256 再编码为 hex 得到，与 networkFrameWork 中 nodeId 体系一致。
//
// 示例：使用运行时生成的 64 字符十六进制字符串。
type NodeID string

// XOR 计算两个 NodeID 之间的 Kademlia 距离。
// 距离 = a ^ b（按大整数异或），与 DHTable.Node.XOR 的计算方式一致。
// 距离越小表示两个节点在 DHT 环上越"接近"。
func (id NodeID) XOR(other NodeID) *big.Int {
	a, _ := new(big.Int).SetString(string(id), 16)
	b, _ := new(big.Int).SetString(string(other), 16)
	return new(big.Int).Xor(a, b)
}

// PeerAddr 描述一个对端节点的可达地址。
//
// 所有连接都通过 relay 中转，因此地址就是 relay 服务器地址。
// 一个 peer 可能在多个 relay 上注册，实现应按优先级尝试。
type PeerAddr struct {
	// Relay 是 relay 服务器地址，如 "127.0.0.1:9000"
	Relay string
}

// PeerInfo 描述路由表中一条已知节点的完整信息。
//
// 注意：Addresses 可能为空（例如只从 FIND_NODE 响应中得知 ID 但尚未尝试连接），
// Connect 实现需要处理这种情况——通过已 connect 的 closer peer 继续迭代查找。
type PeerInfo struct {
	ID        NodeID
	Addresses []PeerAddr
	LastSeen  time.Time

	// Metadata 预留扩展字段，实现可存入节点版本、支持的特性等。
	Metadata map[string]string
}

// Message 是 P2P 节点层消息信封。
//
// 与 network.Message 的关系：
//   - network.Message 是「单条可靠流上的业务消息」，负责加密/分帧/ACK；
//   - p2pnode.Message  是「节点层的逻辑消息」，可能被广播到多条流上。
//
// 实现层的 Send/Receive 负责在 network.Message.Payload 中编码/解码 Message。
type Message struct {
	// Type 标识消息语义，DHT 控制消息 vs 业务数据。
	Type MessageType

	// Path 是应用级业务标识，类似 HTTP 的 path / 主题(topic)。
	// 用于在同一条 Connection 上做多路复用：上层可按 Path 把消息分流到不同的业务处理器。
	// 形式不固定，约定即可，如：
	//   "/chat/text"
	//   "/file/chunk"
	//   "/dht/find_node"
	//   "user.profile.update"
	// 不参与 p2p 层路由(NodeID 才负责寻址)，仅作为应用层语义标签。
	// 留空字符串表示"未分类"，可被默认处理器接管。
	Path string

	// TTL 是广播剩余跳数，每经过一个节点减 1，到 0 时不再继续泛洪。
	// 对单播消息（FindNode/Store 等），TTL 无意义，设为 0。
	TTL int

	// RequestID 是端到端请求标识，用于匹配请求/响应、广播去重。
	RequestID uint64

	// Sender 是消息最初发送者的 NodeID。
	// 广播场景下保持不变，方便接收方知道真实来源。
	Sender NodeID

	// Code 是应用层状态码，语义参考 HTTP 状态码（200=成功，404=未找到，500=服务端错误等）。
	// 默认值 0 表示「不关心状态」或「框架层消息」（如 DHT 控制消息）。
	// router 层的业务消息默认填充 200 表示成功响应。
	Code int

	// Payload 是消息体，由上层业务定义格式。
	Payload []byte
}

const TransportControlPath = "/_bnfs/transport-control"

// MessageType 区分 p2p 层的消息类别。
type MessageType int

const (
	// MsgAppData 是应用层业务数据，Node 仅负责送达，不解析内容。
	MsgAppData MessageType = iota

	// —— DHT 协议消息 ——

	// MsgDHTPing 探测对端是否在线。
	// 期望响应：MsgDHTPong
	MsgDHTPing

	// MsgDHTPong 响应 Ping，同时可携带发送者已知的自身地址。
	MsgDHTPong

	// MsgDHTFindNode 查找离 target 最近的 k 个节点。
	// Payload 包含：target NodeID (64 hex chars)
	// 期望响应：MsgDHTFindNodeResp
	MsgDHTFindNode

	// MsgDHTFindNodeResp 返回已知的离 target 最近的节点列表。
	// Payload 包含：[]PeerInfo 的序列化
	MsgDHTFindNodeResp

	// —— 广播消息 ——

	// MsgBroadcast 是应用层广播，Node 沿邻居泛洪并去重。
	MsgBroadcast
)

// Node 是 P2P 节点层的核心接口。
//
// 一个 Node 实例代表本地的一个 P2P 节点身份。
// 它管理路由表、通过 relay 建立/接受连接、提供广播能力。
//
// 典型生命周期：
//  1. 创建 Node（传入私钥/身份/传输层实现）
//  2. Listen() 向 relay 注册，开始接受入站连接
//  3. 必要时 Connect() 到已知 bootstrap 节点填充路由表
//  4. 业务层通过 Connect/Broadcast/Neighbors 收发消息
//  5. Close() 优雅退出
//
// 并发安全：所有方法必须 goroutine-safe。
type Node interface {
	// ID 返回本节点的 NodeID。
	ID() NodeID

	// -- 1. 根据 NodeID 查找并建立连接 --

	// Connect 查找 target 并通过 relay 建立连接。
	//
	// 内部流程（对调用方透明）：
	//   a) 查本地路由表获取 target 的 PeerInfo（含 relay 地址）。
	//   b) 若路由表无此节点，执行 DHT 迭代查找 (FIND_NODE)：
	//      从路由表选 α 个离 target 最近的已知节点，并发请求 FIND_NODE；
	//      收到响应后把新节点加入路由表，逐步逼近 target。
	//   c) 拿到 relay 地址后，通过 Transport.Dial 经 relay 连接到 target。
	//
	// 成功时 Connection 已通过握手，可直接 Send/Receive。
	// 若遍历完所有已知节点仍不可达，返回 error。
	Connect(ctx context.Context, target NodeID) (Connection, error)

	// -- 2. 广播消息 --

	// Broadcast 将 msg 发给路由表中所有邻居。
	//
	// 行为：
	//   a) 给消息分配新的 RequestID（调用方无需预填）。
	//   b) 遍历路由表各 bucket，向 bucket 内每个 peer 发送。
	//   c) 收到广播的节点检查 RequestID：已见过则丢弃；未见过则处理后继续转发给它的邻居。
	//   d) TTL 控制广播半径（例如 TTL=3 表示最多扩散 3 跳）。
	//
	// 注意：Broadcast 是尽力而为的，不保证所有节点都能收到。
	// 返回 error 仅表示本节点发送失败（例如无邻居），不反映远端接收情况。
	Broadcast(ctx context.Context, msg *Message) error

	// -- 3. 返回相邻节点 --

	// Neighbors 返回路由表中当前所有已知节点的信息。
	// 结果按 XOR 距离（离本节点）升序排列。
	// 调用方可用于 UI 展示、调试、或手动选择中继路径。
	Neighbors() []PeerInfo

	// ClosestPeers 返回路由表中离 target 最近的 k 个节点。
	// 用于 DHT 查找迭代：调用方拿这 k 个节点继续问"你离 target 更近吗"。
	ClosestPeers(target NodeID, k int) []PeerInfo

	// -- 4. 接收陌生节点连接并加入 DHT --

	// Listen 向 relay 注册并等待陌生节点连接，流程参考 relayServer.RelayServer 分支。
	//
	// 内部流程：
	//   a) Transport.Register 向 relay 注册，拿到 relay 注册流。
	//   b) 在注册流上阻塞 NextMessage，等待 relay 转发来的 Hello 消息。
	//      Hello 的 Payload = 对端公钥 hex。
	//   c) 推导对端 NodeID = hex(SHA256(Hello.Payload))。
	//   d) 调用 networkFrameWork.SetStreamIdentity 绑定流身份。
	//   e) HandshakeHandler.HandshakeIncoming 执行 TLS 密钥交换。
	//   f) 握手成功后调用 interfaces.DHTTable.AddNode 将对端加入路由表。
	//   g) 构造 Connection 并投递给 OnConnection 回调（若设置）。
	//   h) 回到 b，继续等待下一个陌生节点的 Hello。
	//
	// addr 是 relay 服务器地址（如 "127.0.0.1:9000"）。
	// Listen 是阻塞调用，直到 ctx 被取消或发生不可恢复错误。
	// 调用方应在独立 goroutine 中调用（go node.Listen(ctx, addr)）。
	Listen(ctx context.Context, addr string) error

	// -- 生命周期 --

	// Close 关闭本节点：
	//   - 停止 Listen（若在运行）
	//   - 关闭所有活跃 Connection
	//   - 持久化路由表（若配置了持久化）
	Close() error
}

// Connection 代表一条已握手的对端连接。
//
// 上层通过它直接收发消息，无需关心底层是直连还是 relay 转发。
type Connection interface {
	// Peer 返回本次连接的对端信息。
	Peer() PeerInfo

	// Send 发送一条消息到对端。
	// 实现负责将 Message 编码并写入底层 network.Stream。
	Send(ctx context.Context, msg *Message) error

	// Receive 阻塞等待一条来自对端的消息。
	// 返回错误表示连接断开或 ctx 取消。
	// 实现负责从底层 network.Stream 读取 network.Message 并解码为 Message。
	Receive(ctx context.Context) (*Message, error)

	// Raw 返回底层 network.Stream，供需要直接操作流的场景使用。
	// 一般情况下调用方应优先使用 Send/Receive。
	Raw() network.Stream

	// Close 关闭此连接，释放底层流。
	Close() error
}
