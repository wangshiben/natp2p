package network

import (
	"context"
)

type Stream interface {
	Close() error

	NextMessage(ctx context.Context) (*Message, error)
	SendMessage(ctx context.Context, message *Message) error
	SendMessageAsync(ctx context.Context, message *Message, callback MessageResultCallback) error
	NodeId() string
	ConnectionId() string
	SetCryptoSuite(suite EncrypSuite)
}

// InitialWriteStream 暴露消息首批帧被传输层接收的时点。
// 回调最多执行一次，发生在首次写入成功之后、等待最终 ACK 之前。
//
// 调用方可利用这一窄顺序边界保持应用全局序列，无需串行等待完整端到端 ACK。
type InitialWriteStream interface {
	SendMessageWithInitialWrite(ctx context.Context, message *Message, onInitialWrite func()) error
}

type EncrypSuite interface {
	Encrypt(Payload []byte) ([]byte, error)
	Decrypt(Payload []byte) ([]byte, error)
}

// OutboundRecordObserver 在一条带计费字段的消息完成 E2E Seal、但尚未交给任一传输 leg 前调用。
// message 是只读的密文快照，messageID 是稳定的端到端记录 ID；返回错误会阻止发送。
type OutboundRecordObserver func(message *Message, messageID []byte) error

type MessageIdentitySuite interface {
	EncrypSuite
	NewMessageID() []byte
	EncryptWithMessageID(Payload []byte, messageID []byte) (ciphertext []byte, id []byte, err error)
	DecryptWithMessageID(Payload []byte) (plaintext []byte, messageID []byte, ok bool, err error)
}

type MessageIdentityAADSuite interface {
	MessageIdentitySuite
	EncryptWithMessageIDAndAAD(Payload, aad, messageID []byte) (ciphertext []byte, id []byte, err error)
	DecryptWithMessageIDAndAAD(Payload, aad []byte) (plaintext []byte, messageID []byte, ok bool, err error)
}
