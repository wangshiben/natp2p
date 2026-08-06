package natnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"bnfs_p2p/billingcontrol"
	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
)

const (
	billingControlInitialBackoff = 250 * time.Millisecond
	billingControlMaximumBackoff = 5 * time.Second
	billingControlStableDuration = 30 * time.Second
)

func (n *NATNode) startBillingControl(relayAddr string) {
	if relayAddr == "" || n.billingMeter.certificate() == nil {
		return
	}
	n.mu.Lock()
	if _, exists := n.billingControlActive[relayAddr]; exists {
		n.mu.Unlock()
		return
	}
	n.billingControlActive[relayAddr] = nil
	n.mu.Unlock()
	go n.maintainBillingControl(relayAddr)
}

func (n *NATNode) maintainBillingControl(relayAddr string) {
	defer func() {
		n.mu.Lock()
		delete(n.billingControlActive, relayAddr)
		n.mu.Unlock()
	}()
	backoff := billingControlInitialBackoff
	for n.ctx.Err() == nil {
		connectedAt := time.Time{}
		stream, _, err := networkFrameWork.TryConnectControlStreamTCP(
			relayAddr, string(n.ID()), n.identity.Pubkey(), billingcontrol.Route,
		)
		if err == nil {
			connectedAt = time.Now()
			n.mu.Lock()
			n.billingControlActive[relayAddr] = stream
			n.mu.Unlock()
			err = n.serveBillingControl(relayAddr, client.NewStreamClient(stream))
			n.billingMeter.invalidateRelaySessionWithCause(relayAddr, "billing_control_disconnected", "")
		}
		if n.ctx.Err() != nil {
			return
		}
		nextBackoff := nextBillingControlBackoff(backoff, connectedAt, time.Now())
		logx.Warnf("[natnode] 双签计费控制流断开, 将重连 relay=%s: %v", relayAddr, err)
		timer := time.NewTimer(backoff)
		select {
		case <-n.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = nextBackoff
	}
}

func nextBillingControlBackoff(current time.Duration, connectedAt, now time.Time) time.Duration {
	if !connectedAt.IsZero() && now.Sub(connectedAt) >= billingControlStableDuration {
		return billingControlInitialBackoff
	}
	if current < billingControlInitialBackoff {
		current = billingControlInitialBackoff
	}
	if current >= billingControlMaximumBackoff/2 {
		return billingControlMaximumBackoff
	}
	return current * 2
}

func (n *NATNode) serveBillingControl(relayAddr string, stream *client.StreamClient) error {
	defer stream.Close()
	for {
		message, err := stream.NextMessage(n.ctx)
		if err != nil {
			return err
		}
		var request billingcontrol.Message
		if err := json.Unmarshal(message.Payload, &request); err != nil {
			return errors.New("natnode: invalid billing control message")
		}
		if request.Type == billingcontrol.TypeSession {
			relayID, err := billingcontrol.IdentityIDFromPublicKeyHex(request.RelayPublicKey)
			if err != nil {
				return fmt.Errorf("natnode: invalid billing control Relay identity: %w", err)
			}
			binding := billingcontrol.ProofBinding{
				Challenge: request.Challenge,
				SessionID: request.SessionID,
				PayerID:   string(n.ID()),
				RelayID:   relayID,
			}
			relayStateBinding := billingcontrol.RelayStateProofBinding{
				ProofBinding:       binding,
				CumulativeBytes:    request.CumulativeBytes,
				LastRecordID:       request.LastRecordID,
				LastRecordSequence: request.LastRecordSequence,
				RecordSetDigest:    request.RecordSetDigest,
			}
			if err := billingcontrol.VerifyRelayStateProof(
				request.RelayPublicKey, relayStateBinding, request.RelayStateProof,
			); err != nil {
				return fmt.Errorf("natnode: verify Relay billing watermark possession: %w", err)
			}
			relayState, err := relayBillingSnapshot(request)
			if err != nil {
				return err
			}
			status, err := n.billingMeter.activateRelaySessionWithState(
				relayAddr, request.SessionID, request.RelayPublicKey, &relayState,
			)
			if err != nil {
				return err
			}
			var recoveryVoucher []byte
			var recoveryVoucherID string
			if status.recoveryVoucher != nil {
				recoveryVoucher, err = status.recoveryVoucher.CanonicalBytes()
				if err != nil {
					return fmt.Errorf("natnode: encode recovery billing voucher: %w", err)
				}
				recoveryID, idErr := status.recoveryVoucher.ID()
				if idErr != nil {
					return fmt.Errorf("natnode: identify recovery billing voucher: %w", idErr)
				}
				recoveryVoucherID = recoveryID.String()
			}
			readyBinding := billingcontrol.ReadyStateProofBinding{
				RelayStateProofBinding: relayStateBinding,
				SessionPreexisting:     status.preexisting, SessionResetRequired: status.resetRequired,
				RecoveryVoucherID: recoveryVoucherID,
			}
			payerProof, err := billingcontrol.SignReadyStateProof(n.privKey, readyBinding)
			if err != nil {
				return fmt.Errorf("natnode: sign billing control readiness: %w", err)
			}
			payload, err := json.Marshal(billingcontrol.Message{
				Type: billingcontrol.TypeReady, SessionID: request.SessionID,
				Challenge: bytes.Clone(request.Challenge), PayerProof: payerProof,
				SessionPreexisting: status.preexisting, SessionResetRequired: status.resetRequired,
				CumulativeBytes: status.cumulative,
				LastRecordID:    status.lastRecord.String(), LastRecordSequence: status.lastRecordSequence,
				RecordSetDigest: status.recordSet.String(), Voucher: recoveryVoucher,
			})
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
			err = stream.SendMessage(ctx, &network.Message{
				Header:  &network.Header{RouteName: billingcontrol.Route, NodeId: string(n.ID()), NodeIdVersion: 1},
				Payload: payload,
			})
			cancel()
			if err != nil {
				n.billingMeter.invalidateRelaySessionWithCause(relayAddr, "billing_ready_send_error", "")
				return err
			}
			continue
		}
		if request.Type != billingcontrol.TypeClaim {
			return errors.New("natnode: invalid billing control claim")
		}
		voucher, claimErr := n.billingMeter.cosign(
			request.Body, request.RelaySignature, request.RelayPublicKey,
			request.RelayBillingPublicKey, request.RelayCert,
		)
		response := billingcontrol.Message{Type: billingcontrol.TypeReject}
		if claimErr != nil {
			response.Error = "billing_claim_rejected"
			logx.Warnf("[natnode] 拒绝 Relay 计费凭证: %v", claimErr)
		} else {
			encoded, err := voucher.CanonicalBytes()
			if err != nil {
				return err
			}
			response = billingcontrol.Message{
				Type: billingcontrol.TypeCosigned, Voucher: encoded,
				PayerPublicKey:        n.identity.Pubkey(),
				PayerBillingPublicKey: n.billingMeter.billingPublicKeyForWire(),
				PayerCert:             n.billingMeter.certificate(),
			}
		}
		payload, err := json.Marshal(response)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
		err = stream.SendMessage(ctx, &network.Message{
			Header:  &network.Header{RouteName: billingcontrol.Route, NodeId: string(n.ID()), NodeIdVersion: 1},
			Payload: payload,
		})
		cancel()
		if err != nil {
			return err
		}
	}
}

func relayBillingSnapshot(message billingcontrol.Message) (natBillingSnapshot, error) {
	if message.CumulativeBytes == 0 && message.LastRecordSequence == 0 {
		lastRecord, recordErr := billingvoucher.ParseIdentifierHex(message.LastRecordID)
		recordSet, digestErr := billingvoucher.ParseDigestHex(message.RecordSetDigest)
		if recordErr != nil || digestErr != nil || lastRecord != (billingvoucher.Identifier{}) ||
			recordSet != (billingvoucher.Digest{}) {
			return natBillingSnapshot{}, errors.New("natnode: invalid empty Relay billing watermark")
		}
		return natBillingSnapshot{}, nil
	}
	lastRecord, err := billingvoucher.ParseIdentifierHex(message.LastRecordID)
	if err != nil {
		return natBillingSnapshot{}, errors.New("natnode: invalid Relay last RecordID watermark")
	}
	recordSet, err := billingvoucher.ParseDigestHex(message.RecordSetDigest)
	if err != nil {
		return natBillingSnapshot{}, errors.New("natnode: invalid Relay record-set watermark")
	}
	snapshot := natBillingSnapshot{
		cumulative: message.CumulativeBytes, lastRecord: lastRecord,
		lastRecordSequence: message.LastRecordSequence, recordSet: recordSet,
	}
	if !billingSnapshotConsistent(snapshot) {
		return natBillingSnapshot{}, errors.New("natnode: inconsistent Relay billing watermark")
	}
	return snapshot, nil
}
