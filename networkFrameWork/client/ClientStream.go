package client

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"context"
	"crypto/ecdh"
	"errors"
)

// StreamClient :用户实际发起连接调用的Stream
type StreamClient struct {
	stream network.Stream
	exit   chan interface{}
}

func (s *StreamClient) Close() error {
	err := s.stream.Close()
	if err != nil {
		return err
	}
	s.exit <- true
	return nil
}

func (s *StreamClient) NextMessage() (*network.Message, error) {
	for {
		select {
		case <-s.exit:
			return nil, errors.New("stream closed")
		default:
			message, err := s.stream.NextMessage()
			if err != nil {
				return nil, err
			}
			if message.Header.RouteName != networkFrameWork.KeepAliveRoute {
				return message, nil
			}
		}

	}
}

func (s *StreamClient) SendMessage(ctx context.Context, message *network.Message) error {
	message.Header.ConnectionId = s.stream.ConnectionId()
	err := s.stream.SendMessage(ctx, message)
	if err != nil {
		return err
	}
	return nil
}

func (s *StreamClient) NodeId() string {
	return s.stream.NodeId()
}

func (s *StreamClient) ConnectionId() string {
	return s.stream.ConnectionId()
}

func (s *StreamClient) SetCryptoSuite(suite network.EncrypSuite) {
	s.stream.SetCryptoSuite(suite)
}

// ConnectNodeWithTargetRelay :用户实际连接指定Node的函数
//
// 输入参数：
//
// nodeId:目标Node的id
// relayAddr: 通过指定Relay地址连接
// keyPair: 用户的密钥对(只做读取，结构体内不保存)
//
// 返回值：
// StreamClient:用户实际使用的Stream
// error:错误信息
// string:本次连接的ConnectionId
func ConnectNodeWithTargetRelay(nodeId, relayAddr string, keyPair *ecdh.PrivateKey) (*StreamClient, string, error) {
	pubKey := keyPair.PublicKey()
	originNodeId := crypoto.GetPubKeyStr(pubKey)
	stream, ConnectionId, err := networkFrameWork.TryConnectTCPStream(relayAddr, nodeId, originNodeId)
	if err != nil {
		return nil, "", err
	}
	crypto, err := crypoto.NewTLSCrypto(stream, keyPair)
	if err != nil {
		return nil, "", err
	}
	res := &StreamClient{
		stream: stream,
		exit:   make(chan interface{}),
	}
	res.SetCryptoSuite(crypto)
	return res, ConnectionId, nil
}
