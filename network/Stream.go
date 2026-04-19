package network

import (
	"context"
)

type Stream interface {
	Close() error

	NextMessage() (*Message, error)
	SendMessage(ctx context.Context, message *Message) error
	NodeId() string
	ConnectionId() string
	SetCryptoSuite(suite EncrypSuite)
}
type EncrypSuite interface {
	Encrypt(Payload []byte) ([]byte, error)
	Decrypt(Payload []byte) ([]byte, error)
}
