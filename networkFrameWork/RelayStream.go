package networkFrameWork

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"sync"
)

type RelayStream struct {
	nodeId       string
	connection   net.Conn
	lock         sync.Mutex
	publicKey    *ecdh.PublicKey
	isClosed     bool
	connectionId string
	crypto       network.EncrypSuite
}

func (r *RelayStream) Close() error {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.connection.Close()
}

func (r *RelayStream) NextMessage() (*network.Message, error) {
	headerRead := make([]byte, network.HeaderLength)
	_, err := io.ReadFull(r.connection, headerRead)
	if err != nil {
		return nil, err
	}
	header, err := network.ParseHeader(headerRead)
	if err != nil {
		return nil, err
	}
	payLoad := make([]byte, header.PayLoadLength)
	_, err = io.ReadFull(r.connection, payLoad)
	if err != nil {
		return nil, err
	}
	return &network.Message{Header: header, Payload: payLoad}, nil
}

func tryReadMessageFromConnection(conn net.Conn) (*network.Message, error) {
	headerRead := make([]byte, network.HeaderLength)
	_, err := io.ReadFull(conn, headerRead)
	if err != nil {

		return nil, err
	}
	header, err := network.ParseHeader(headerRead)
	if err != nil {

		return nil, err
	}
	payLoad := make([]byte, header.PayLoadLength)
	_, err = io.ReadFull(conn, payLoad)
	if err != nil {
		return nil, err
	}
	return &network.Message{Header: header, Payload: payLoad}, err
}
func (r *RelayStream) SendMessage(ctx context.Context, message *network.Message) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	bytes, err := message.ParseToBytes()
	if err != nil {
		return err
	}
	_, err = r.connection.Write(bytes)
	return err
}

func (r *RelayStream) NodeId() string {
	return r.nodeId
}
func (r *RelayStream) ConnectionId() string {
	return ""
}
func (r *RelayStream) SetCryptoSuite(suite network.EncrypSuite) {
	r.crypto = suite
}

func TrySetupRelayStream(conn net.Conn, message *network.Message) (network.Stream, error) {
	// TODO: 解析消息 nodeId pubKey
	payload := string(message.Payload)
	pubKey, err := crypoto.ExtractPublicKeyFromHex(payload)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(payload))
	originalNodeId := hex.EncodeToString(hash[:])
	return &RelayStream{
		nodeId:     originalNodeId,
		publicKey:  pubKey,
		connection: conn,
	}, nil
}
