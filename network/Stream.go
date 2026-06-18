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
type EncrypSuite interface {
	Encrypt(Payload []byte) ([]byte, error)
	Decrypt(Payload []byte) ([]byte, error)
}

type MessageIdentitySuite interface {
	EncrypSuite
	NewMessageID() []byte
	EncryptWithMessageID(Payload []byte, messageID []byte) (ciphertext []byte, id []byte, err error)
	DecryptWithMessageID(Payload []byte) (plaintext []byte, messageID []byte, ok bool, err error)
}
