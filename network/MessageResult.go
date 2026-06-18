package network

// MessageResult 表示异步消息发送的结果
type MessageResult struct {
	MessageID   string // 消息ID
	Success     bool   // 是否成功
	Error       error  // 失败时的错误信息
	Attempts    int    // 尝试次数
	UsedTransport string // 使用的传输协议 (KCP/TCP)
}

// MessageResultCallback 是异步发送完成时的回调函数
type MessageResultCallback func(MessageResult)
