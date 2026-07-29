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

// InitialWriteStream exposes the point at which a message's initial frame batch
// has been accepted by the transport. The callback runs at most once, after the
// initial write succeeds but before the method waits for the final ACK.
//
// Callers use this narrow ordering boundary to preserve a global application
// sequence without serializing the full end-to-end ACK wait.
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
