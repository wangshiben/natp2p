package natnode

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"context"
	"fmt"
)

// NATConnection 在加密流上实现 p2pnode.Connection 接口。
type NATConnection struct {
	peer           p2pnode.PeerInfo
	stream         network.Stream
	touch          func()
	billing        *natBillingMeter
	billingRelay   func() string
	billingFailure func(string)
}

func newNATConnection(peer p2pnode.PeerInfo, stream network.Stream, touch func(), billing *natBillingMeter, billingRelay func() string, billingFailure func(string)) *NATConnection {
	connection := &NATConnection{
		peer:           peer,
		stream:         stream,
		touch:          touch,
		billing:        billing,
		billingRelay:   billingRelay,
		billingFailure: billingFailure,
	}
	if billing != nil {
		networkFrameWork.SetOutboundRecordObserver(stream, billing.observe)
	}
	return connection
}

func (c *NATConnection) Peer() p2pnode.PeerInfo { return c.peer }

func (c *NATConnection) Send(ctx context.Context, msg *p2pnode.Message) error {
	netMsg := EncodeMessage(msg, string(c.peer.ID), c.stream.ConnectionId())
	relayAddr := ""
	if c.billingRelay != nil {
		relayAddr = c.billingRelay()
	}
	if err := c.billing.waitRelaySession(ctx, relayAddr); err != nil {
		return err
	}
	releaseSendOrder, err := c.billing.acquireSendOrder(ctx, relayAddr)
	if err != nil {
		return err
	}
	defer releaseSendOrder()
	if err := c.billing.prepare(netMsg, relayAddr); err != nil {
		return err
	}
	if ordered, ok := c.stream.(network.InitialWriteStream); ok {
		err = ordered.SendMessageWithInitialWrite(ctx, netMsg, releaseSendOrder)
	} else {
		err = c.stream.SendMessage(ctx, netMsg)
	}
	if err != nil {
		c.billing.invalidateRelaySession(relayAddr)
		reconciliationReady := c.billing.completeSend(netMsg)
		logx.Warnf(
			"[natnode] 业务发送失败, 计费会话将在在途发送排空后重协商: peer=%.16s connId=%s relay=%s billingSequence=%d reconciliationReady=%t err=%v",
			c.peer.ID, c.stream.ConnectionId(), relayAddr, netMsg.Header.BillingSequence, reconciliationReady, err,
		)
		if reconciliationReady && c.billingFailure != nil {
			c.billingFailure(relayAddr)
		}
		return err
	}
	confirmErr := c.billing.confirm(netMsg)
	if confirmErr != nil {
		c.billing.invalidateRelaySession(relayAddr)
	}
	reconciliationReady := c.billing.completeSend(netMsg)
	if confirmErr != nil {
		logx.Warnf(
			"[natnode] 业务发送已送达但计费确认失败, 会话将在在途发送排空后重协商: peer=%.16s connId=%s relay=%s billingSequence=%d reconciliationReady=%t err=%v",
			c.peer.ID, c.stream.ConnectionId(), relayAddr, netMsg.Header.BillingSequence, reconciliationReady, confirmErr,
		)
		if reconciliationReady && c.billingFailure != nil {
			c.billingFailure(relayAddr)
		}
		return confirmErr
	}
	if reconciliationReady && c.billingFailure != nil {
		c.billingFailure(relayAddr)
	}
	if c.touch != nil {
		c.touch()
	}
	return nil
}

func (c *NATConnection) Receive(ctx context.Context) (*p2pnode.Message, error) {
	netMsg, err := c.stream.NextMessage(ctx)
	if err != nil {
		return nil, err
	}
	route := ""
	if netMsg.Header != nil {
		route = netMsg.Header.RouteName
	}
	if route != routeMessage {
		return nil, fmt.Errorf("natnode: unexpected application route %q", route)
	}
	message, err := DecodeMessage(netMsg)
	if err != nil {
		return nil, err
	}
	if c.touch != nil {
		c.touch()
	}
	return message, nil
}

// Raw 返回底层 network.Stream，供需要直接操作流的场景使用。
func (c *NATConnection) Raw() network.Stream { return c.stream }

func (c *NATConnection) Close() error { return c.stream.Close() }
