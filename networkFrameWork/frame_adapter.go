package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
)

// FrameRelayEndpoint 是 relay 数据面专用的"逐帧桥接"接口。
//
// 设计动机：
//   - network.Stream 接口面向应用层，暴露的是完整的 Message 收发语义（NextMessage / SendMessage），
//     内部会做分帧、重组、加解密、ACK / 重传。
//   - 但 relay（公网中转节点）只是把字节从一条 TCP 连接搬到另一条 TCP 连接，
//     如果先在 relay 把所有帧重组成完整 Message 再转发，就会出现 head-of-line blocking：
//     单条大 Message 的一个帧丢了，会把同一连接上其它消息全部卡死。
//   - 所以 relay 需要一种"只看 Frame、不看 Message"的接口，把 Data/Retransmit 帧从源 leg
//     拿出来，改写 MessageId 后写到目标 leg 即可，ACK 仍由各 leg 内部独立维护。
//
// 该接口只在 relay 内部使用，应用层 / TLS 握手 / 客户端 ClientStream 仍走 network.Stream。
type FrameRelayEndpoint interface {
	// NextFrame 从底层流的"帧旁路通道"取下一帧 Data/Retransmit 原始帧。
	// 不会返回 ACK 帧（ACK 仍由 TcpStream 自己处理），不会做重组。
	// ctx 用于在 relay 关闭 / 整组取消时及时退出阻塞读取。
	NextFrame(ctx context.Context) (*network.Frame, error)

	// HandleFrame 把一帧原始数据写到底层连接。供 relay frame pump 把"从源 leg 取出的帧"
	// 改写 MessageId 后投递到目标 leg。
	// 注意：本方法绕过加密 / 分帧 / ACK 跟踪，调用方必须保证 frame 已是合法二进制结构。
	HandleFrame(ctx context.Context, frame *network.Frame) error

	// AllocMessageId 在目标 leg 上分配一个全新的 MessageId。
	// relay 必须为每条跨 leg 的消息重写 MessageId，避免与目标 leg 自己 SendMessage 时
	// 生成的 MessageId 冲突（两边的 frameIdGen 是相互独立的命名空间）。
	AllocMessageId() uint64

	// NodeId 返回该 leg 对端的 NodeId（公钥派生）。relay 用它定位会话归属。
	NodeId() string

	// ConnectionId 返回该 leg 当前绑定的业务 ConnectionId。
	// 对 relay 注册 leg 而言通常为空；对 client 连接 leg 是该业务连接的 uuid。
	ConnectionId() string

	// Close 关闭底层连接，释放该 leg 占用的资源。
	Close() error
}

// TcpFrameAdapter 是 FrameRelayEndpoint 在 *TcpStream 之上的默认实现。
//
// 职责：
//   - 在构造时给 TcpStream 安装一个"帧旁路通道"（frameTap），让 readLoop 在收到
//     Data/Retransmit 帧时除了走正常的重组路径外，再非阻塞地把该帧投递一份到本通道。
//   - 把 FrameRelayEndpoint 的所有方法直接代理到底层 TcpStream 对应方法上。
//
// 字段说明：
//
//	stream  底层被包装的 TcpStream；所有读写最终都落到它身上。
//	frames  本适配器持有的旁路通道，缓冲 64 帧，供 relay pump 通过 NextFrame 消费。
//	        通道所有权在构造期通过 stream.SetFrameTap 转交给 TcpStream，由它写入。
type TcpFrameAdapter struct {
	stream *TcpStream
	frames chan *network.Frame
}

// NewTcpFrameAdapter 创建并安装一个帧旁路适配器。
//
// 参数：
//
//	stream 必须是已经在 readLoop 中正常工作的 *TcpStream。
//	       如果传入 nil，返回 nil（调用方必须显式判空）；这样 relay 在底层不是 *TcpStream
//	       时（比如未来扩展的 KCP / UDP 流）可以安全地走老的 message 转发路径。
//
// 行为：
//   - 创建一个带缓冲（64）的 *network.Frame 通道。
//   - 调用 stream.SetFrameTap 把通道写入端交给 TcpStream，从此 readLoop 收到的
//     Data/Retransmit 帧会非阻塞地投一份到此通道；通道满则丢弃（relay 不影响主重组路径）。
//   - 必须在该流开始接收正式数据帧前调用，否则 relay 会错过先到的帧。
func NewTcpFrameAdapter(stream *TcpStream) *TcpFrameAdapter {
	if stream == nil {
		return nil
	}
	ch := make(chan *network.Frame, 64)
	stream.SetFrameTap(ch)
	return &TcpFrameAdapter{stream: stream, frames: ch}
}

// NextFrame 从底层 TcpStream 的 frameTap 通道取下一帧。
// 阻塞直到：取到一帧 / ctx 被取消 / 底层流关闭。
func (a *TcpFrameAdapter) NextFrame(ctx context.Context) (*network.Frame, error) {
	return a.stream.NextFrame(ctx)
}

// HandleFrame 把一帧原始数据写到底层 TCP 连接。
// 调用方（relay frame pump）通常已经把 frame.MessageId 改写为目标 leg 的新 ID。
func (a *TcpFrameAdapter) HandleFrame(ctx context.Context, frame *network.Frame) error {
	return a.stream.HandleFrame(ctx, frame)
}

// AllocMessageId 透传到底层流的 frameIdGen，分配目标 leg 上唯一的 MessageId。
func (a *TcpFrameAdapter) AllocMessageId() uint64 {
	return a.stream.AllocMessageId()
}

// NodeId 返回底层流当前绑定的对端 NodeId。
func (a *TcpFrameAdapter) NodeId() string {
	return a.stream.NodeId()
}

// ConnectionId 返回底层流当前绑定的业务 ConnectionId。
func (a *TcpFrameAdapter) ConnectionId() string {
	return a.stream.ConnectionId()
}

// Close 关闭底层流（同时会终止 readLoop 与所有挂起的 ACK 等待）。
func (a *TcpFrameAdapter) Close() error {
	return a.stream.Close()
}
