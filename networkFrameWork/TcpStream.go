package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/xtaci/kcp-go/v5"
	"io"
	"net"
	"sync"
)

type TcpStream struct {
	nodeId       string
	connection   net.Conn
	lock         sync.Mutex
	connectionId string
}

const (
	tcpMode = "tcp"
	udpMode = "udp"
)

func (t *TcpStream) Close() error {
	return t.connection.Close()
}

func (t *TcpStream) NextMessage() (*network.Message, error) {
	headerRead := make([]byte, network.HeaderLength)
	_, err := io.ReadFull(t.connection, headerRead)
	if err != nil {
		return nil, err
	}
	header, err := network.ParseHeader(headerRead)
	if err != nil {
		return nil, err
	}
	payLoad := make([]byte, header.PayLoadLength)
	_, err = io.ReadFull(t.connection, payLoad)
	if err != nil {
		return nil, err
	}
	return &network.Message{Header: header, Payload: payLoad}, nil
}

func (t *TcpStream) SendMessage(ctx context.Context, message *network.Message) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	bytes, err := message.ParseToBytes()
	if err != nil {
		return err
	}
	_, err = t.connection.Write(bytes)
	return err
}

func (t *TcpStream) NodeId() string {
	return t.nodeId
}
func (t *TcpStream) ConnectionId() string {
	return t.connectionId
}
func TryConnectTCPStream(addr, targetNodeId, originalPubkeyHex string) (network.Stream, string, error) {
	connectionId := uuid.New().String()
	header := &network.Header{
		RouteName:     "",
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	stream, err := clientStream(body, addr, targetNodeId, true)
	return stream, connectionId, err
}

func TryRegisterRelayStream(pubKey, relayAddress string) (network.Stream, error) {
	hash := sha256.Sum256([]byte(pubKey))
	originalNodeId := hex.EncodeToString(hash[:])

	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  "",
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(pubKey),
	}
	return clientStream(body, relayAddress, originalNodeId, true)
}

// TryRegisterStream : nat后设备注册Stream
// 参数:
//
//	addr: 要连接的中转服务器地址
//	originalPubkeyHex: 自己的公钥
//	streamMode: 可选: tcp/udp，默认udp，若无法连接，则使用tcp
//	targetNodeId: 目标节点的nodeId(如果不是短时连接某一特定节点，则此项可不填)
//
// 返回值:
//
//	network.Stream: 流对象
//	string: 流的connectionId(当targetNodeId不为空时有)
//	error: 错误信息
func TryRegisterStream(addr, originalPubkeyHex, targetNodeId, streamMode string) (network.Stream, string, error) {
	hash := sha256.Sum256([]byte(originalPubkeyHex))
	originalNodeId := hex.EncodeToString(hash[:])
	connectionId := ""
	if len(targetNodeId) != 0 {
		connectionId = uuid.New().String()
	}
	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	if streamMode == udpMode {
		stream, err := clientStream(body, addr, originalNodeId, true)
		if err != nil {
			return nil, "", err
		}
		return stream, connectionId, nil
	} else if streamMode == tcpMode {
		stream, err := clientStream(body, addr, originalNodeId, false)
		if err != nil {
			return nil, "", err
		}
		return stream, connectionId, nil
	}
	return nil, "", errors.New("wrong stream mode")
}

func clientStream(FirstMessage *network.Message, tcpAddr, originalNodeId string, isDefault bool) (network.Stream, error) {
	if isDefault {
		// 优先创建KCP流
		stream, err := kcpStream(FirstMessage, tcpAddr, originalNodeId)
		if err == nil {
			return stream, err
		}
	}

	conn, err := net.Dial("tcp4", tcpAddr)
	if err != nil {
		return nil, err
	}
	bytes, err := FirstMessage.ParseToBytes()
	if err != nil {
		conn.Close()
		return nil, err
	}
	_, err = conn.Write(bytes)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &TcpStream{
		nodeId:     originalNodeId,
		connection: conn,
	}, nil
}

func kcpStream(FirstMessage *network.Message, tcpAddr, originalNodeId string) (network.Stream, error) {
	conn, err := kcp.Dial(tcpAddr)
	if err != nil {
		return nil, err
	}
	bytes, err := FirstMessage.ParseToBytes()
	if err != nil {
		conn.Close()
		return nil, err
	}
	_, err = conn.Write(bytes)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &TcpStream{
		nodeId:     originalNodeId,
		connection: conn,
	}, nil
}
