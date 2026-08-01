package natnode

import (
	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

const (
	maximumPendingBillingSendsPerConnection = 16
	maximumAutomaticBillingSendRecoveries   = 3
)

type recoverableServiceSendError struct {
	cause error
}

func (sendError *recoverableServiceSendError) Error() string {
	return sendError.cause.Error()
}

func (sendError *recoverableServiceSendError) Unwrap() error {
	return sendError.cause
}

func markRecoverableServiceSendError(err error) error {
	if err == nil || isRecoverableServiceSendError(err) {
		return err
	}
	return &recoverableServiceSendError{cause: err}
}

func isRecoverableServiceSendError(err error) bool {
	var recoverable *recoverableServiceSendError
	return errors.As(err, &recoverable)
}

// NATConnection 在加密流上实现 p2pnode.Connection 接口。
type NATConnection struct {
	peer           p2pnode.PeerInfo
	stream         network.Stream
	touch          func()
	billing        *natBillingMeter
	billingRelay   func() string
	billingFailure func(string)
	billingSends   chan struct{}
}

func newNATConnection(peer p2pnode.PeerInfo, stream network.Stream, touch func(), billing *natBillingMeter, billingRelay func() string, billingFailure func(string)) *NATConnection {
	connection := &NATConnection{
		peer:           peer,
		stream:         stream,
		touch:          touch,
		billing:        billing,
		billingRelay:   billingRelay,
		billingFailure: billingFailure,
		billingSends:   make(chan struct{}, maximumPendingBillingSendsPerConnection),
	}
	if billing != nil {
		networkFrameWork.SetOutboundRecordObserver(stream, billing.observe)
	}
	return connection
}

func (c *NATConnection) Peer() p2pnode.PeerInfo { return c.peer }

func (c *NATConnection) Send(ctx context.Context, msg *p2pnode.Message) error {
	releaseBillingSend, err := c.acquireBillingSendSlot(ctx)
	if err != nil {
		return markRecoverableServiceSendError(err)
	}
	defer releaseBillingSend()
	connectionID := c.stream.ConnectionId()
	recoveryAttempt := 0
	for {
		netMsg := EncodeMessage(msg, string(c.peer.ID), connectionID)
		relayAddr := ""
		if c.billingRelay != nil {
			relayAddr = c.billingRelay()
		}
		logx.Debugf(
			"[billing-trace] stage=nat_send_begin relay=%s connId=%s peer=%.16s payloadBytes=%d recoveryAttempt=%d",
			relayAddr, connectionID, c.peer.ID, len(netMsg.Payload), recoveryAttempt,
		)
		sendLease, prepareErr := c.prepareBillingSend(
			ctx, netMsg, relayAddr, connectionID, msg.Path == p2pnode.TransportControlPath,
		)
		if prepareErr != nil {
			return prepareErr
		}
		var initialWriteCompleted atomic.Bool
		onInitialWrite := func() {
			initialWriteCompleted.Store(true)
			sendLease.Release()
		}
		if ordered, ok := c.stream.(network.InitialWriteStream); ok {
			err = ordered.SendMessageWithInitialWrite(ctx, netMsg, onInitialWrite)
		} else {
			err = c.stream.SendMessage(ctx, netMsg)
		}
		sendLease.Release()
		if err != nil {
			callerCanceledAfterWrite := initialWriteCompleted.Load() &&
				(errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded))
			if callerCanceledAfterWrite {
				c.billing.completeSend(netMsg)
				logx.Warnf(
					"[natnode] 业务发送在初始写入后被调用方取消, 已保留共享计费会话: peer=%.16s connId=%s relay=%s billingSequence=%d err=%v",
					c.peer.ID, connectionID, relayAddr, netMsg.Header.BillingSequence, err,
				)
				return markRecoverableServiceSendError(err)
			}
			c.billing.invalidateRelaySessionForSession(
				relayAddr,
				billingvoucher.Identifier(netMsg.Header.BillingSessionID),
				"transport_send_error",
				connectionID,
			)
			reconciliationReady := c.billing.completeSend(netMsg)
			logx.Warnf(
				"[natnode] 业务发送失败, 计费会话将在在途发送排空后重协商: peer=%.16s connId=%s relay=%s billingSequence=%d reconciliationReady=%t recoveryAttempt=%d err=%v",
				c.peer.ID, connectionID, relayAddr, netMsg.Header.BillingSequence,
				reconciliationReady, recoveryAttempt, err,
			)
			if reconciliationReady && c.billingFailure != nil {
				c.billingFailure(relayAddr)
			}
			if !errors.Is(err, networkFrameWork.ErrMessageMaxRetransmits) ||
				!c.billing.sendsEnabled() || c.billingFailure == nil {
				return err
			}
			if recoveryAttempt >= maximumAutomaticBillingSendRecoveries {
				return markRecoverableServiceSendError(err)
			}
			recoveryAttempt++
			logx.Warnf(
				"[billing-trace] stage=transport_send_retry_after_session_rotation relay=%s connId=%s peer=%.16s oldSession=%x oldSequence=%d recoveryAttempt=%d",
				relayAddr, connectionID, c.peer.ID, netMsg.Header.BillingSessionID,
				netMsg.Header.BillingSequence, recoveryAttempt,
			)
			if waitErr := c.billing.waitRelaySession(ctx, relayAddr, connectionID); waitErr != nil {
				return markRecoverableServiceSendError(waitErr)
			}
			continue
		}
		confirmErr := c.billing.confirm(netMsg)
		if confirmErr != nil {
			c.billing.invalidateRelaySessionForSession(
				relayAddr,
				billingvoucher.Identifier(netMsg.Header.BillingSessionID),
				"billing_confirm_error",
				connectionID,
			)
		}
		reconciliationReady := c.billing.completeSend(netMsg)
		if confirmErr != nil {
			logx.Warnf(
				"[natnode] 业务发送已送达但计费确认失败, 会话将在在途发送排空后重协商: peer=%.16s connId=%s relay=%s billingSequence=%d reconciliationReady=%t err=%v",
				c.peer.ID, connectionID, relayAddr, netMsg.Header.BillingSequence, reconciliationReady, confirmErr,
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
}

func (c *NATConnection) acquireBillingSendSlot(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, errors.New("natnode: nil context while waiting for a billing send slot")
	}
	if !c.billing.sendsEnabled() {
		return func() {}, nil
	}
	select {
	case c.billingSends <- struct{}{}:
		return func() {
			<-c.billingSends
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf(
			"%w for connection %s: per-connection limit=%d",
			ErrBillingSendQueueFull, c.stream.ConnectionId(), maximumPendingBillingSendsPerConnection,
		)
	}
}

func (c *NATConnection) prepareBillingSend(
	ctx context.Context,
	message *network.Message,
	relayAddr,
	connectionID string,
	priority bool,
) (*natBillingSendLease, error) {
	for {
		if err := c.billing.waitRelaySession(ctx, relayAddr, connectionID); err != nil {
			logx.Warnf(
				"[billing-trace] stage=nat_send_wait_session_error relay=%s connId=%s peer=%.16s err=%v",
				relayAddr, connectionID, c.peer.ID, err,
			)
			return nil, markRecoverableServiceSendError(err)
		}
		lease, err := c.billing.acquireSendOrderWithPriority(ctx, relayAddr, connectionID, priority)
		if err != nil {
			if errors.Is(err, ErrBillingSessionReconciling) {
				continue
			}
			logx.Warnf(
				"[billing-trace] stage=nat_send_acquire_order_error relay=%s connId=%s peer=%.16s err=%v",
				relayAddr, connectionID, c.peer.ID, err,
			)
			if errors.Is(err, ErrBillingSendQueueFull) ||
				errors.Is(err, ErrBillingRelayWaitQueueFull) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				err = markRecoverableServiceSendError(err)
			}
			return nil, err
		}
		err = c.billing.prepareWithLease(message, relayAddr, lease)
		if errors.Is(err, ErrBillingSessionReconciling) {
			lease.Release()
			continue
		}
		if err != nil {
			lease.Release()
			diagnostics := c.billing.relayDiagnostics(relayAddr)
			logx.Warnf(
				"[billing-trace] stage=nat_send_prepare_error relay=%s session=%s connId=%s peer=%.16s invalid=%t sendOrderWaiters=%d relayWaiters=%d activeSends=%d nextAssigned=%d nextAdvance=%d invalidationGeneration=%d err=%v",
				relayAddr, diagnostics.sessionID.String(), connectionID, c.peer.ID, diagnostics.invalid,
				diagnostics.sendOrderWaiters, diagnostics.relaySessionWaiters, diagnostics.activeSends,
				diagnostics.nextAssigned, diagnostics.nextAdvance, diagnostics.invalidationGeneration, err,
			)
			return nil, err
		}
		return lease, nil
	}
}

func (c *NATConnection) Receive(ctx context.Context) (*p2pnode.Message, error) {
	for {
		netMsg, err := c.stream.NextMessage(ctx)
		if err != nil {
			return nil, err
		}
		route := ""
		if netMsg != nil && netMsg.Header != nil {
			route = netMsg.Header.RouteName
		}
		if route == networkFrameWork.KeepAliveRoute {
			if c.touch != nil {
				c.touch()
			}
			continue
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
}

// Raw 返回底层 network.Stream，供需要直接操作流的场景使用。
func (c *NATConnection) Raw() network.Stream { return c.stream }

func (c *NATConnection) Close() error { return c.stream.Close() }
