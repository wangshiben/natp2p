package natnode

import (
	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
	"context"
)

// NATConnection 在加密流上实现 p2pnode.Connection 接口。
type NATConnection struct {
	peer   p2pnode.PeerInfo
	stream network.Stream
}

func newNATConnection(peer p2pnode.PeerInfo, stream network.Stream) *NATConnection {
	return &NATConnection{
		peer:   peer,
		stream: stream,
	}
}

func (c *NATConnection) Peer() p2pnode.PeerInfo { return c.peer }

func (c *NATConnection) Send(ctx context.Context, msg *p2pnode.Message) error {
	netMsg := EncodeMessage(msg, string(c.peer.ID), c.stream.ConnectionId())
	return c.stream.SendMessage(ctx, netMsg)
}

func (c *NATConnection) Receive(ctx context.Context) (*p2pnode.Message, error) {
	netMsg, err := c.stream.NextMessage(ctx)
	if err != nil {
		return nil, err
	}
	return DecodeMessage(netMsg)
}

// Raw 返回底层 network.Stream，供需要直接操作流的场景使用。
func (c *NATConnection) Raw() network.Stream { return c.stream }

func (c *NATConnection) Close() error { return c.stream.Close() }
