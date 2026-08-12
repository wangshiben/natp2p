package relaynode

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingcontrol"
	"bnfs_p2p/billingqueue"
	"bnfs_p2p/billingrecord"
	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
)

const (
	secureBillableRoute         = "/p2p/message"
	defaultBillingQueueItems    = uint64(65536)
	defaultBillingQueueBytes    = uint64(64 << 20)
	defaultBillingPayerItems    = uint64(4096)
	defaultBillingPayerBytes    = uint64(8 << 20)
	defaultBillingRetry         = time.Second
	billingControlTimeout       = 8 * time.Second
	maximumPendingRecordGap     = uint64(4096)
	maximumRecentBillingRecords = uint64(4096)
)

var errBillingSessionRotated = errors.New("relaynode: billing session rotated")

func retryableBillableRecordError(err error) error {
	if err == nil || errors.Is(err, networkFrameWork.ErrBillableRecordRetryable) {
		return err
	}
	return fmt.Errorf("%w: %w", networkFrameWork.ErrBillableRecordRetryable, err)
}

type relayBillingSnapshot struct {
	cumulative         uint64
	lastRecord         billingvoucher.Identifier
	lastRecordSequence uint64
	recordSet          billingvoucher.Digest
}

type relayBillingRecord struct {
	bytes    uint64
	recordID billingvoucher.Identifier
}

type relayBillingSession struct {
	mu sync.Mutex

	payerID   billingvoucher.Identifier
	sessionID billingvoucher.Identifier

	nextRecordSequence uint64
	cumulative         uint64
	lastRecord         billingvoucher.Identifier
	lastRecordSequence uint64
	recordSet          billingvoucher.Digest
	lastVoucher        billingvoucher.MutualVoucher
	hasVoucher         bool
	recent             map[uint64]relayBillingRecord
	pending            map[uint64]relayBillingRecord
	pendingBytes       uint64
	blocked            error
}

type relayBillingPipeline struct {
	node       *RelayNode
	relayID    billingvoucher.Identifier
	queue      *billingqueue.Queue
	settler    *admission.CAClient
	relayCert  *admission.SignedCert
	retryEvery time.Duration

	mu             sync.Mutex
	sessions       map[billingvoucher.Identifier]*relayBillingSession
	currentByPayer map[billingvoucher.Identifier]*relayBillingSession

	controlMu sync.Mutex
	controls  map[billingvoucher.Identifier]*relayBillingControlPeer

	errorMu  sync.RWMutex
	fatalErr error

	submitMu sync.Mutex
	wake     chan struct{}
	done     chan struct{}
	wait     sync.WaitGroup
}

type relayBillingControlPeer struct {
	stream    network.Stream
	payerID   billingvoucher.Identifier
	sessionID billingvoucher.Identifier

	requestMu sync.Mutex
	responses chan billingcontrol.Message
	done      chan struct{}
	closeOnce sync.Once
}

func newRelayBillingPipeline(node *RelayNode, queuePath string) (*relayBillingPipeline, error) {
	if node == nil {
		return nil, errors.New("relaynode: billing pipeline requires a Relay")
	}
	relayID, err := billingvoucher.NodeIDFromPublicKey(node.privKey.PublicKey())
	if err != nil {
		return nil, err
	}
	if queuePath == "" {
		queuePath, err = defaultRelayBillingQueuePath(node.idStr())
		if err != nil {
			return nil, err
		}
	}
	queue, err := billingqueue.Open(queuePath, billingqueue.Limits{
		MaxItems: defaultBillingQueueItems, MaxBytes: defaultBillingQueueBytes,
		MaxItemsPerPayer: defaultBillingPayerItems, MaxBytesPerPayer: defaultBillingPayerBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("relaynode: open durable waitSubmit queue: %w", err)
	}

	pipeline := &relayBillingPipeline{
		node: node, relayID: relayID, queue: queue, retryEvery: defaultBillingRetry,
		sessions:       make(map[billingvoucher.Identifier]*relayBillingSession),
		currentByPayer: make(map[billingvoucher.Identifier]*relayBillingSession),
		controls:       make(map[billingvoucher.Identifier]*relayBillingControlPeer),
		wake:           make(chan struct{}, 1), done: make(chan struct{}),
	}
	config := node.admissionConfig()
	if config == nil || config.Mode == AdmissionOff {
		_ = queue.Close()
		return nil, errors.New("relaynode: secure billing requires admission")
	}
	settler, ok := config.Verifier.(*admission.CAClient)
	if !ok || settler == nil {
		_ = queue.Close()
		return nil, errors.New("relaynode: secure billing requires a CA settlement client")
	}
	if config.SelfCert == nil {
		_ = queue.Close()
		return nil, errors.New("relaynode: secure billing requires the Relay certificate")
	}
	if config.SelfCert.Cert.SubjectNodeID != relayID.String() ||
		config.SelfCert.Cert.SubjectPubKey != node.pubKeyHex() || config.SelfCert.Cert.Role != admission.RoleRelay {
		_ = queue.Close()
		return nil, errors.New("relaynode: Relay billing certificate does not match identity or role")
	}
	if err := admission.ValidateBillingBinding(config.SelfCert.Cert); err != nil {
		_ = queue.Close()
		return nil, fmt.Errorf("relaynode: invalid Relay billing certificate binding: %w", err)
	}
	billingPublicKey := node.billingPublicKeyHex()
	if config.SelfCert.Cert.AuthorizationID == "" {
		if billingPublicKey != node.pubKeyHex() {
			_ = queue.Close()
			return nil, errors.New("relaynode: legacy certificate requires the identity key for billing")
		}
	} else if config.SelfCert.Cert.BillingPubKey != billingPublicKey {
		_ = queue.Close()
		return nil, errors.New("relaynode: Relay certificate does not match the configured billing private key")
	}
	if err := config.Verifier.Verify(config.SelfCert, admission.VerifyOptions{
		ExpectNodeID: relayID.String(), ExpectRole: admission.RoleRelay,
	}); err != nil {
		_ = queue.Close()
		return nil, fmt.Errorf("relaynode: verify Relay billing certificate: %w", err)
	}
	pipeline.settler = settler
	copyCert := *config.SelfCert
	pipeline.relayCert = &copyCert
	if err := pipeline.restoreQueue(); err != nil {
		_ = queue.Close()
		return nil, err
	}
	pipeline.wait.Add(1)
	go pipeline.submitLoop()
	return pipeline, nil
}

func defaultRelayBillingQueuePath(relayID string) (string, error) {
	cacheDirectory, err := os.UserCacheDir()
	if err != nil || cacheDirectory == "" {
		return "", errors.New("relaynode: resolve durable billing queue directory")
	}
	return filepath.Join(cacheDirectory, "bnfs-p2p", "billing", relayID, "wait-submit.queue"), nil
}

func (node *RelayNode) installSecureBillingPipeline() {
	node.mu.RLock()
	if node.billingPipeline != nil || node.billingPipelineErr != nil {
		node.mu.RUnlock()
		return
	}
	queuePath := node.billingQueuePath
	forwardConfig := node.forwardHookConfig
	node.mu.RUnlock()

	pipeline, pipelineErr := newRelayBillingPipeline(node, queuePath)
	node.mu.Lock()
	node.billingPipeline = pipeline
	node.billingPipelineErr = pipelineErr
	node.mu.Unlock()
	if pipelineErr != nil {
		logx.Errorf("[relaynode] 初始化双签计费失败，server 数据面将 fail-closed: %v", pipelineErr)
	}

	if forwardConfig == nil {
		forwardConfig = &networkFrameWork.ForwardHookConfig{}
	}
	previousHook := forwardConfig.BillableRecordHook
	previousRequired := forwardConfig.BillableRecordRequired
	forwardConfig.BillableRoute = secureBillableRoute
	forwardConfig.BillableRecordRequired = func(nodeID, direction string) bool {
		secureRequired := direction == "relay_to_clients" && node.accounts.role(nodeID) == admission.RoleServer
		if previousHook == nil {
			return secureRequired
		}
		if previousRequired == nil {
			return true
		}
		return secureRequired || previousRequired(nodeID, direction)
	}
	forwardConfig.BillableRecordHook = func(ctx context.Context, record *networkFrameWork.BillableRecord) error {
		secureRequired := record != nil && record.Direction == "relay_to_clients" &&
			node.accounts.role(record.NodeID) == admission.RoleServer
		if secureRequired {
			node.mu.RLock()
			activePipeline := node.billingPipeline
			activeErr := node.billingPipelineErr
			node.mu.RUnlock()
			if activeErr != nil {
				return activeErr
			}
			if activePipeline == nil {
				return errors.New("relaynode: secure billing pipeline is unavailable")
			}
			if err := activePipeline.observeRecord(ctx, record); err != nil {
				return err
			}
		}
		if previousHook != nil {
			return previousHook(ctx, record)
		}
		return nil
	}
	node.SetForwardHook(forwardConfig)
}

func (pipeline *relayBillingPipeline) restoreQueue() error {
	envelopes, err := pipeline.queue.SnapshotEnvelopes()
	if err != nil {
		return fmt.Errorf("relaynode: snapshot durable waitSubmit queue: %w", err)
	}
	for index, envelope := range envelopes {
		voucher := envelope.Voucher
		if envelope.PayerCert == nil || envelope.PayerPublicKey == "" {
			return fmt.Errorf("relaynode: waitSubmit item %d lacks its durable payer settlement identity", index)
		}
		if voucher.Body.PayeeRelayID != pipeline.relayID {
			return fmt.Errorf("relaynode: waitSubmit item %d belongs to another Relay", index)
		}
		payerSigningPublicKeyHex, payerBillingPublicKeyHex, err := certificateSigningPublicKey(
			envelope.PayerCert, envelope.PayerPublicKey,
		)
		if err != nil || payerBillingPublicKeyHex != envelope.PayerBillingPublicKey {
			return fmt.Errorf("relaynode: waitSubmit item %d has an invalid payer billing identity", index)
		}
		payerSigningPublicKey, err := parseBillingPublicKey(payerSigningPublicKeyHex)
		if err != nil {
			return fmt.Errorf("relaynode: waitSubmit item %d has an invalid payer billing key: %w", index, err)
		}
		if err := voucher.VerifyBillingSignatures(payerSigningPublicKey, pipeline.node.billingPrivateKey.PublicKey()); err != nil {
			return fmt.Errorf("relaynode: waitSubmit item %d has invalid signatures: %w", index, err)
		}
		session := pipeline.sessions[voucher.Body.SessionID]
		if session == nil {
			session = newRelayBillingSession(voucher.Body.PayerNatID, voucher.Body.SessionID)
			pipeline.sessions[voucher.Body.SessionID] = session
		}
		if session.payerID != voucher.Body.PayerNatID {
			return fmt.Errorf("relaynode: waitSubmit item %d changes the session payer", index)
		}
		if session.hasVoucher {
			if err := billingvoucher.ValidateSuccessor(session.lastVoucher, voucher); err != nil {
				return fmt.Errorf("relaynode: waitSubmit item %d breaks the voucher chain: %w", index, err)
			}
		}
		restoreSessionVoucher(session, voucher)
		pipeline.currentByPayer[session.payerID] = session
	}
	return nil
}

func newRelayBillingSession(payerID, sessionID billingvoucher.Identifier) *relayBillingSession {
	return &relayBillingSession{
		payerID: payerID, sessionID: sessionID, nextRecordSequence: 1,
		recent: make(map[uint64]relayBillingRecord), pending: make(map[uint64]relayBillingRecord),
	}
}

func restoreSessionVoucher(session *relayBillingSession, voucher billingvoucher.MutualVoucher) {
	session.lastVoucher = voucher
	session.hasVoucher = true
	session.cumulative = voucher.Body.CumulativeUniqueBytes
	session.lastRecord = voucher.Body.LastRecordID
	session.lastRecordSequence = voucher.Body.LastRecordSequence
	session.recordSet = voucher.Body.RecordSetDigest
	session.nextRecordSequence = voucher.Body.LastRecordSequence + 1
}

func (pipeline *relayBillingPipeline) operational() error {
	if pipeline == nil {
		return errors.New("relaynode: secure billing pipeline is unavailable")
	}
	pipeline.errorMu.RLock()
	defer pipeline.errorMu.RUnlock()
	return pipeline.fatalErr
}

func (pipeline *relayBillingPipeline) poison(err error) {
	if err == nil {
		return
	}
	pipeline.errorMu.Lock()
	if pipeline.fatalErr == nil {
		pipeline.fatalErr = err
		logx.Errorf("[relaynode] 双签计费流水线已 fail-closed: %v", err)
	}
	pipeline.errorMu.Unlock()
}

func (pipeline *relayBillingPipeline) sessionForPayer(payerID billingvoucher.Identifier) (*relayBillingSession, error) {
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	if current := pipeline.currentByPayer[payerID]; current != nil {
		return current, nil
	}
	var sessionID billingvoucher.Identifier
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, fmt.Errorf("relaynode: generate billing session: %w", err)
	}
	if sessionID == (billingvoucher.Identifier{}) {
		sessionID[0] = 1
	}
	session := newRelayBillingSession(payerID, sessionID)
	pipeline.sessions[sessionID] = session
	pipeline.currentByPayer[payerID] = session
	return session, nil
}

func (pipeline *relayBillingPipeline) rotateSessionForPayer(payerID billingvoucher.Identifier, previous *relayBillingSession) (*relayBillingSession, error) {
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	if current := pipeline.currentByPayer[payerID]; current != nil && current != previous {
		return current, nil
	}
	if previous == nil || previous.payerID != payerID {
		return nil, errors.New("relaynode: cannot rotate an unrelated billing session")
	}
	previous.mu.Lock()
	defer previous.mu.Unlock()
	if previous.blocked != nil {
		return nil, fmt.Errorf("relaynode: cannot rotate a blocked billing session: %w", previous.blocked)
	}
	if !billingSessionSafeToRotateLocked(previous) {
		return nil, errors.New("relaynode: billing session contains state not covered by its last voucher")
	}
	var sessionID billingvoucher.Identifier
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, fmt.Errorf("relaynode: rotate billing session: %w", err)
	}
	if sessionID == (billingvoucher.Identifier{}) {
		sessionID[0] = 1
	}
	session := newRelayBillingSession(payerID, sessionID)
	previous.blocked = errBillingSessionRotated
	pipeline.sessions[sessionID] = session
	pipeline.currentByPayer[payerID] = session
	return session, nil
}

func billingSessionSafeToRotateLocked(session *relayBillingSession) bool {
	if session == nil || session.blocked != nil || session.pendingBytes != 0 || len(session.pending) != 0 {
		return false
	}
	if !session.hasVoucher {
		return session.cumulative == 0 && session.lastRecordSequence == 0
	}
	return session.cumulative == session.lastVoucher.Body.CumulativeUniqueBytes &&
		session.lastRecordSequence == session.lastVoucher.Body.LastRecordSequence &&
		session.lastRecord == session.lastVoucher.Body.LastRecordID &&
		session.recordSet == session.lastVoucher.Body.RecordSetDigest
}

func billingSessionSafeToRotate(session *relayBillingSession) bool {
	if session == nil {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return billingSessionSafeToRotateLocked(session)
}

func billingSessionReadyMatches(session *relayBillingSession, ready billingcontrol.Message) bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	if ready.SessionResetRequired || session.blocked != nil {
		return false
	}
	if !ready.SessionPreexisting {
		return session.cumulative == 0 && session.lastRecordSequence == 0 && !session.hasVoucher
	}
	return ready.CumulativeBytes == session.cumulative &&
		ready.LastRecordSequence == session.lastRecordSequence &&
		ready.LastRecordID == session.lastRecord.String() &&
		ready.RecordSetDigest == session.recordSet.String()
}

func (pipeline *relayBillingPipeline) acceptControl(stream network.Stream, firstMessage *network.Message) error {
	if err := pipeline.operational(); err != nil {
		return err
	}
	if stream == nil || firstMessage == nil || firstMessage.Header == nil {
		return errors.New("relaynode: invalid billing control stream")
	}
	payerID, err := billingvoucher.ParseIdentifierHex(firstMessage.Header.NodeId)
	if err != nil {
		return errors.New("relaynode: billing control payer identity is invalid")
	}
	payerPublicKey := string(firstMessage.Payload)
	if admission.NodeIDFromPubKeyHex(payerPublicKey) != payerID.String() {
		return errors.New("relaynode: billing control public key does not match payer")
	}
	certificate := pipeline.node.accounts.cert(payerID.String())
	if certificate == nil || certificate.Cert.SubjectPubKey != payerPublicKey {
		return errors.New("relaynode: billing control payer has no matching registered certificate")
	}
	config := pipeline.node.admissionConfig()
	if config == nil || config.Verifier == nil {
		return errors.New("relaynode: billing certificate verifier is unavailable")
	}
	if err := config.Verifier.Verify(certificate, admission.VerifyOptions{
		ExpectNodeID: payerID.String(), ExpectRole: admission.RoleServer,
	}); err != nil {
		return fmt.Errorf("relaynode: verify billing control payer: %w", err)
	}
	payerSigningPublicKey, payerBillingPublicKey, err := certificateSigningPublicKey(
		certificate, payerPublicKey,
	)
	if err != nil {
		return fmt.Errorf("relaynode: resolve billing control payer key: %w", err)
	}
	challenge, err := billingcontrol.NewChallenge()
	if err != nil {
		return err
	}

	session, err := pipeline.sessionForPayer(payerID)
	if err != nil {
		return err
	}
	peer := &relayBillingControlPeer{
		stream: stream, payerID: payerID,
		responses: make(chan billingcontrol.Message, 1), done: make(chan struct{}),
	}
	for attempt := 0; attempt < 3; attempt++ {
		peer.sessionID = session.sessionID
		relayState, err := relayBillingControlSnapshot(session)
		if err != nil {
			peer.close()
			return err
		}
		stateBinding := billingcontrol.RelayStateProofBinding{
			ProofBinding: billingcontrol.ProofBinding{
				Challenge: challenge, SessionID: session.sessionID.String(),
				PayerID: payerID.String(), RelayID: pipeline.relayID.String(),
			},
			CumulativeBytes: relayState.cumulative, LastRecordID: relayState.lastRecord.String(),
			LastRecordSequence: relayState.lastRecordSequence, RecordSetDigest: relayState.recordSet.String(),
		}
		relayStateProof, err := billingcontrol.SignRelayStateProof(pipeline.node.privKey, stateBinding)
		if err != nil {
			peer.close()
			return fmt.Errorf("relaynode: sign billing control watermark: %w", err)
		}
		if err := peer.sendControl(pipeline.node.ctx, billingcontrol.Message{
			Type: billingcontrol.TypeSession, SessionID: session.sessionID.String(),
			Challenge: bytes.Clone(challenge), RelayPublicKey: pipeline.node.pubKeyHex(),
			RelayStateProof: relayStateProof, CumulativeBytes: relayState.cumulative,
			LastRecordID: relayState.lastRecord.String(), LastRecordSequence: relayState.lastRecordSequence,
			RecordSetDigest: relayState.recordSet.String(),
		}); err != nil {
			peer.close()
			return err
		}
		handshakeContext, cancel := context.WithTimeout(pipeline.node.ctx, billingControlTimeout)
		readyMessage, err := nextBillingControlMessage(handshakeContext, stream)
		cancel()
		if err != nil {
			peer.close()
			return fmt.Errorf("relaynode: billing session acknowledgement failed: %w", err)
		}
		var ready billingcontrol.Message
		if readyMessage == nil || json.Unmarshal(readyMessage.Payload, &ready) != nil ||
			ready.Type != billingcontrol.TypeReady || ready.SessionID != session.sessionID.String() {
			peer.close()
			return errors.New("relaynode: invalid billing session acknowledgement")
		}
		if !bytes.Equal(ready.Challenge, challenge) {
			peer.close()
			return errors.New("relaynode: billing session acknowledgement challenge mismatch")
		}
		var recoveryVoucher *billingvoucher.MutualVoucher
		var recoveryVoucherID string
		if len(ready.Voucher) != 0 {
			parsed, parseErr := billingvoucher.ParseCanonicalVoucher(ready.Voucher)
			if parseErr != nil {
				peer.close()
				return fmt.Errorf("relaynode: parse billing recovery voucher: %w", parseErr)
			}
			recoveryID, idErr := parsed.ID()
			if idErr != nil {
				peer.close()
				return fmt.Errorf("relaynode: identify billing recovery voucher: %w", idErr)
			}
			recoveryVoucher = &parsed
			recoveryVoucherID = recoveryID.String()
		}
		readyBinding := billingcontrol.ReadyStateProofBinding{
			RelayStateProofBinding: stateBinding,
			SessionPreexisting:     ready.SessionPreexisting, SessionResetRequired: ready.SessionResetRequired,
			RecoveryVoucherID: recoveryVoucherID,
		}
		if err := billingcontrol.VerifyReadyStateProof(certificate.Cert.SubjectPubKey, readyBinding, ready.PayerProof); err != nil {
			peer.close()
			return fmt.Errorf("relaynode: verify billing control payer possession: %w", err)
		}
		if recoveryVoucher != nil {
			if err := pipeline.installRecoveredVoucher(
				session, relayState, *recoveryVoucher, payerPublicKey,
				payerSigningPublicKey, payerBillingPublicKey, certificate,
			); err != nil {
				peer.close()
				return err
			}
		}
		if ready.SessionResetRequired && !billingSessionSafeToRotate(session) {
			settlementState, err := relayBillingControlSnapshot(session)
			if err != nil {
				peer.close()
				return err
			}
			voucher, err := pipeline.issueVoucherWithClaim(
				pipeline.node.ctx, session, settlementState,
				func(ctx context.Context, claim billingcontrol.Message) (billingcontrol.Message, error) {
					return claimBillingControlDirect(ctx, peer, stream, claim)
				},
			)
			if err != nil {
				peer.close()
				return fmt.Errorf("relaynode: settle billing session before rotation: %w", err)
			}
			session.mu.Lock()
			current := relayBillingSnapshot{
				cumulative: session.cumulative, lastRecord: session.lastRecord,
				lastRecordSequence: session.lastRecordSequence, recordSet: session.recordSet,
			}
			if current != settlementState || session.blocked != nil ||
				len(session.pending) != 0 || session.pendingBytes != 0 {
				session.mu.Unlock()
				peer.close()
				return errors.New("relaynode: billing session changed during rotation settlement")
			}
			session.lastVoucher = voucher
			session.hasVoucher = true
			session.mu.Unlock()
			logx.Warnf(
				"[relaynode] 计费 Session 换代前已完成最终双签 payer=%.16s sequence=%d cumulative=%d",
				payerID.String(), settlementState.lastRecordSequence, settlementState.cumulative,
			)
		}
		if billingSessionReadyMatches(session, ready) {
			break
		}
		if attempt == 2 {
			peer.close()
			return errors.New("relaynode: billing session watermarks cannot be reconciled")
		}
		logx.Warnf("[relaynode] NAT/Relay 计费水位不一致，轮换 Session payer=%.16s", payerID.String())
		session, err = pipeline.rotateSessionForPayer(payerID, session)
		if err != nil {
			peer.close()
			return err
		}
	}
	pipeline.installControl(peer)
	defer pipeline.removeControl(peer)
	defer peer.close()

	for {
		message, err := nextBillingControlMessage(pipeline.node.ctx, stream)
		if err != nil {
			return err
		}
		var response billingcontrol.Message
		if message == nil || json.Unmarshal(message.Payload, &response) != nil ||
			(response.Type != billingcontrol.TypeCosigned && response.Type != billingcontrol.TypeReject) {
			return errors.New("relaynode: invalid billing control response")
		}
		select {
		case peer.responses <- response:
		case <-peer.done:
			return errors.New("relaynode: billing control replaced")
		case <-pipeline.node.ctx.Done():
			return pipeline.node.ctx.Err()
		}
	}
}

func (pipeline *relayBillingPipeline) installRecoveredVoucher(
	session *relayBillingSession,
	advertised relayBillingSnapshot,
	voucher billingvoucher.MutualVoucher,
	payerPublicKeyHex string,
	payerSigningPublicKeyHex string,
	payerBillingPublicKeyHex string,
	payerCertificate *admission.SignedCert,
) error {
	if session == nil || payerCertificate == nil {
		return errors.New("relaynode: billing recovery identity is unavailable")
	}
	if voucher.Body.SessionID != session.sessionID || voucher.Body.PayerNatID != session.payerID ||
		voucher.Body.PayeeRelayID != pipeline.relayID || voucher.Body.Direction != billingvoucher.DirectionPayerOutbound ||
		voucher.Body.PolicyDigest != billingvoucher.CurrentPolicyDigest() ||
		voucher.Body.AuthorizedThroughBytes != billingvoucher.MaxBillableBytes {
		return errors.New("relaynode: recovery voucher changes the billing channel binding")
	}
	payerPublicKey, err := parseBillingPublicKey(payerSigningPublicKeyHex)
	if err != nil {
		return err
	}
	if err := voucher.VerifyBillingSignatures(payerPublicKey, pipeline.node.billingPrivateKey.PublicKey()); err != nil {
		return fmt.Errorf("relaynode: verify billing recovery voucher: %w", err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	current := relayBillingSnapshot{
		cumulative: session.cumulative, lastRecord: session.lastRecord,
		lastRecordSequence: session.lastRecordSequence, recordSet: session.recordSet,
	}
	if current != advertised || session.blocked != nil || len(session.pending) != 0 || session.pendingBytes != 0 {
		return errors.New("relaynode: billing session changed during voucher recovery")
	}
	if session.hasVoucher {
		lastID, lastErr := session.lastVoucher.ID()
		voucherID, voucherErr := voucher.ID()
		if lastErr != nil || voucherErr != nil {
			return errors.New("relaynode: invalid voucher identity during recovery")
		}
		if lastID == voucherID {
			if current.cumulative != voucher.Body.CumulativeUniqueBytes ||
				current.lastRecord != voucher.Body.LastRecordID ||
				current.lastRecordSequence != voucher.Body.LastRecordSequence ||
				current.recordSet != voucher.Body.RecordSetDigest {
				return errors.New("relaynode: recovered voucher conflicts with its installed watermark")
			}
			return nil
		}
		if err := billingvoucher.ValidateSuccessor(session.lastVoucher, voucher); err != nil {
			return fmt.Errorf("relaynode: invalid recovered voucher successor: %w", err)
		}
	} else if voucher.Body.Sequence != 1 || voucher.Body.PreviousMutualVoucherID != (billingvoucher.Identifier{}) {
		return errors.New("relaynode: invalid first recovered voucher")
	}
	if voucher.Body.CumulativeUniqueBytes < session.cumulative ||
		voucher.Body.LastRecordSequence < session.lastRecordSequence {
		return errors.New("relaynode: recovered voucher predates the advertised watermark")
	}
	if voucher.Body.CumulativeUniqueBytes == session.cumulative ||
		voucher.Body.LastRecordSequence == session.lastRecordSequence {
		if voucher.Body.CumulativeUniqueBytes != session.cumulative ||
			voucher.Body.LastRecordSequence != session.lastRecordSequence ||
			voucher.Body.LastRecordID != session.lastRecord || voucher.Body.RecordSetDigest != session.recordSet {
			return errors.New("relaynode: recovered voucher crosses the advertised watermark")
		}
	}
	err = pipeline.queue.EnqueueEnvelope(billingqueue.Envelope{
		Voucher: voucher, PayerPublicKey: payerPublicKeyHex,
		PayerBillingPublicKey: payerBillingPublicKeyHex, PayerCert: payerCertificate,
	})
	if err != nil && !errors.Is(err, billingqueue.ErrDuplicate) {
		if !errors.Is(err, billingqueue.ErrFull) && !errors.Is(err, billingqueue.ErrPayerFull) {
			pipeline.poison(fmt.Errorf("relaynode: persist recovered waitSubmit growth: %w", err))
		}
		return fmt.Errorf("relaynode: retain recovered billing voucher: %w", err)
	}
	delta := voucher.Body.CumulativeUniqueBytes - session.cumulative
	restoreSessionVoucher(session, voucher)
	pipeline.node.accounts.addUplink(session.payerID.String(), int64(delta))
	pipeline.signalSubmit()
	return nil
}

func relayBillingControlSnapshot(session *relayBillingSession) (relayBillingSnapshot, error) {
	if session == nil {
		return relayBillingSnapshot{}, errors.New("relaynode: billing control session is unavailable")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.blocked != nil {
		return relayBillingSnapshot{}, fmt.Errorf("relaynode: billing control session is blocked: %w", session.blocked)
	}
	if len(session.pending) != 0 || session.pendingBytes != 0 {
		return relayBillingSnapshot{}, errors.New("relaynode: billing control cannot reconcile pending records")
	}
	return relayBillingSnapshot{
		cumulative: session.cumulative, lastRecord: session.lastRecord,
		lastRecordSequence: session.lastRecordSequence, recordSet: session.recordSet,
	}, nil
}

func nextBillingControlMessage(ctx context.Context, stream network.Stream) (*network.Message, error) {
	for {
		message, err := stream.NextMessage(ctx)
		if err != nil {
			return nil, err
		}
		if message != nil && message.Header != nil && message.Header.RouteName == networkFrameWork.KeepAliveRoute {
			continue
		}
		return message, nil
	}
}

func (pipeline *relayBillingPipeline) installControl(peer *relayBillingControlPeer) {
	pipeline.controlMu.Lock()
	previous := pipeline.controls[peer.payerID]
	pipeline.controls[peer.payerID] = peer
	pipeline.controlMu.Unlock()
	if previous != nil && previous != peer {
		previous.close()
	}
}

func (pipeline *relayBillingPipeline) removeControl(peer *relayBillingControlPeer) {
	pipeline.controlMu.Lock()
	if pipeline.controls[peer.payerID] == peer {
		delete(pipeline.controls, peer.payerID)
	}
	pipeline.controlMu.Unlock()
}

func (pipeline *relayBillingPipeline) controlFor(payerID, sessionID billingvoucher.Identifier) *relayBillingControlPeer {
	pipeline.controlMu.Lock()
	defer pipeline.controlMu.Unlock()
	peer := pipeline.controls[payerID]
	if peer == nil || peer.sessionID != sessionID {
		return nil
	}
	return peer
}

func (peer *relayBillingControlPeer) sendControl(ctx context.Context, message billingcontrol.Message) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	sendContext, cancel := context.WithTimeout(ctx, billingControlTimeout)
	defer cancel()
	return peer.stream.SendMessage(sendContext, &network.Message{
		Header: &network.Header{
			RouteName: billingcontrol.Route, NodeId: peer.payerID.String(), NodeIdVersion: 1,
			ConnectionId: peer.stream.ConnectionId(),
		},
		Payload: payload,
	})
}

func (peer *relayBillingControlPeer) claim(ctx context.Context, message billingcontrol.Message) (billingcontrol.Message, error) {
	peer.requestMu.Lock()
	defer peer.requestMu.Unlock()
	select {
	case <-peer.done:
		return billingcontrol.Message{}, retryableBillableRecordError(errors.New("relaynode: billing control is unavailable"))
	default:
	}
	if err := peer.sendControl(ctx, message); err != nil {
		peer.close()
		if ctx.Err() != nil {
			return billingcontrol.Message{}, ctx.Err()
		}
		return billingcontrol.Message{}, retryableBillableRecordError(err)
	}
	waitContext, cancel := context.WithTimeout(ctx, billingControlTimeout)
	defer cancel()
	select {
	case response := <-peer.responses:
		return response, nil
	case <-peer.done:
		return billingcontrol.Message{}, retryableBillableRecordError(errors.New("relaynode: billing control disconnected"))
	case <-waitContext.Done():
		peer.close()
		if ctx.Err() != nil {
			return billingcontrol.Message{}, ctx.Err()
		}
		return billingcontrol.Message{}, retryableBillableRecordError(waitContext.Err())
	}
}

func claimBillingControlDirect(
	ctx context.Context,
	peer *relayBillingControlPeer,
	stream network.Stream,
	message billingcontrol.Message,
) (billingcontrol.Message, error) {
	if peer == nil || stream == nil {
		return billingcontrol.Message{}, errors.New("relaynode: direct billing control is unavailable")
	}
	if err := peer.sendControl(ctx, message); err != nil {
		return billingcontrol.Message{}, err
	}
	waitContext, cancel := context.WithTimeout(ctx, billingControlTimeout)
	defer cancel()
	responseMessage, err := nextBillingControlMessage(waitContext, stream)
	if err != nil {
		return billingcontrol.Message{}, err
	}
	var response billingcontrol.Message
	if responseMessage == nil || json.Unmarshal(responseMessage.Payload, &response) != nil ||
		(response.Type != billingcontrol.TypeCosigned && response.Type != billingcontrol.TypeReject) {
		return billingcontrol.Message{}, errors.New("relaynode: invalid direct billing control response")
	}
	return response, nil
}

func (peer *relayBillingControlPeer) close() {
	peer.closeOnce.Do(func() {
		close(peer.done)
		_ = peer.stream.Close()
	})
}

func (pipeline *relayBillingPipeline) observeRecord(ctx context.Context, record *networkFrameWork.BillableRecord) error {
	if err := pipeline.operational(); err != nil {
		return err
	}
	if record == nil || record.Direction != "relay_to_clients" {
		return errors.New("relaynode: invalid billable record direction")
	}
	if pipeline.node.accounts.role(record.NodeID) != admission.RoleServer {
		return errors.New("relaynode: only registered server records are billable")
	}
	payerID, err := billingvoucher.ParseIdentifierHex(record.NodeID)
	if err != nil {
		return errors.New("relaynode: invalid billable payer identity")
	}
	if pipeline.node.accounts.isCutoff(record.NodeID) {
		return errors.New("relaynode: billable payer is cut off")
	}
	if record.SessionID == (billingvoucher.Identifier{}) || record.Sequence == 0 || record.Bytes == 0 ||
		record.Bytes > billingvoucher.CumulativeWindowBytes || record.RecordID == (billingvoucher.Identifier{}) {
		return errors.New("relaynode: invalid authenticated billable record")
	}
	pipeline.mu.Lock()
	session := pipeline.sessions[record.SessionID]
	pipeline.mu.Unlock()
	if session == nil || session.payerID != payerID {
		return errors.New("relaynode: billable record uses an unnegotiated session")
	}
	if pipeline.controlFor(payerID, record.SessionID) == nil {
		return retryableBillableRecordError(errors.New("relaynode: payer billing control is unavailable"))
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.blocked != nil {
		if errors.Is(session.blocked, errBillingSessionRotated) {
			return retryableBillableRecordError(session.blocked)
		}
		return session.blocked
	}
	candidate := relayBillingRecord{bytes: record.Bytes, recordID: record.RecordID}
	if record.Sequence < session.nextRecordSequence {
		existing, ok := session.recent[record.Sequence]
		if ok && existing == candidate {
			return nil
		}
		return errors.New("relaynode: stale or conflicting billing record sequence")
	}
	if record.Sequence > session.nextRecordSequence {
		if record.Sequence-session.nextRecordSequence > maximumPendingRecordGap {
			return errors.New("relaynode: billing record sequence gap exceeds safety limit")
		}
		// 返回 nil 会让 holdback 把这条乱序记录提前转发，从而把尚未连续签认的字节变成
		// 真实未签风险。返回可重试哨兵使 holdback 不写目标、不回 ACK；源端会在前序
		// 记录补齐后按既有传输重试重新提交。
		return fmt.Errorf("%w: next=%d received=%d",
			networkFrameWork.ErrBillableRecordDeferred, session.nextRecordSequence, record.Sequence)
	}
	if err := pipeline.advanceRecordLocked(ctx, session, record.NodeID, record.Sequence, candidate); err != nil {
		return err
	}
	return nil
}

func (pipeline *relayBillingPipeline) advanceRecordLocked(
	ctx context.Context,
	session *relayBillingSession,
	payerNodeID string,
	sequence uint64,
	record relayBillingRecord,
) error {
	windowBase := uint64(0)
	if session.hasVoucher {
		windowBase = session.lastVoucher.Body.CumulativeUniqueBytes
	}
	windowBytes := session.cumulative - windowBase
	if windowBytes > 0 && record.bytes > billingvoucher.CumulativeWindowBytes-windowBytes {
		voucher, err := pipeline.issueVoucher(ctx, session, relayBillingSnapshot{
			cumulative: session.cumulative, lastRecord: session.lastRecord,
			lastRecordSequence: session.lastRecordSequence, recordSet: session.recordSet,
		})
		if err != nil {
			return err
		}
		session.lastVoucher = voucher
		session.hasVoucher = true
		windowBytes = 0
	}
	if session.cumulative > billingvoucher.MaxBillableBytes-record.bytes {
		return errors.New("relaynode: cumulative billing bytes overflow")
	}
	cumulative := session.cumulative + record.bytes
	recordSet, err := billingrecord.Advance(session.recordSet, record.recordID, sequence, record.bytes)
	if err != nil {
		return err
	}
	candidate := relayBillingSnapshot{
		cumulative: cumulative, lastRecord: record.recordID,
		lastRecordSequence: sequence, recordSet: recordSet,
	}
	if windowBytes+record.bytes == billingvoucher.CumulativeWindowBytes {
		voucher, err := pipeline.issueVoucher(ctx, session, candidate)
		if err != nil {
			return err
		}
		session.lastVoucher = voucher
		session.hasVoucher = true
	}
	session.cumulative = cumulative
	session.lastRecord = record.recordID
	session.lastRecordSequence = sequence
	session.recordSet = recordSet
	pipeline.node.accounts.addUplink(payerNodeID, int64(record.bytes))
	session.recent[sequence] = record
	session.nextRecordSequence++
	if sequence > maximumRecentBillingRecords {
		delete(session.recent, sequence-maximumRecentBillingRecords)
	}
	return nil
}

func (pipeline *relayBillingPipeline) issueVoucher(
	ctx context.Context,
	session *relayBillingSession,
	snapshot relayBillingSnapshot,
) (billingvoucher.MutualVoucher, error) {
	peer := pipeline.controlFor(session.payerID, session.sessionID)
	if peer == nil {
		return billingvoucher.MutualVoucher{}, retryableBillableRecordError(errors.New("relaynode: payer billing control is unavailable"))
	}
	return pipeline.issueVoucherWithClaim(ctx, session, snapshot, peer.claim)
}

func (pipeline *relayBillingPipeline) issueVoucherWithClaim(
	ctx context.Context,
	session *relayBillingSession,
	snapshot relayBillingSnapshot,
	claim func(context.Context, billingcontrol.Message) (billingcontrol.Message, error),
) (billingvoucher.MutualVoucher, error) {
	if snapshot.cumulative == 0 || snapshot.lastRecord == (billingvoucher.Identifier{}) ||
		snapshot.lastRecordSequence == 0 || snapshot.recordSet == (billingvoucher.Digest{}) {
		return billingvoucher.MutualVoucher{}, errors.New("relaynode: cannot issue an empty billing voucher")
	}
	if claim == nil {
		return billingvoucher.MutualVoucher{}, errors.New("relaynode: billing claim transport is unavailable")
	}
	sequence := uint64(1)
	previousID := billingvoucher.Identifier{}
	if session.hasVoucher {
		if session.lastVoucher.Body.Sequence >= billingvoucher.MaxSequence {
			return billingvoucher.MutualVoucher{}, errors.New("relaynode: billing voucher sequence exhausted")
		}
		sequence = session.lastVoucher.Body.Sequence + 1
		var err error
		previousID, err = session.lastVoucher.ID()
		if err != nil {
			return billingvoucher.MutualVoucher{}, err
		}
	}
	body := billingvoucher.VoucherBody{
		Version:                 billingvoucher.CurrentVersion,
		SessionID:               session.sessionID,
		PayerNatID:              session.payerID,
		PayeeRelayID:            pipeline.relayID,
		Direction:               billingvoucher.DirectionPayerOutbound,
		Sequence:                sequence,
		PreviousMutualVoucherID: previousID,
		CumulativeUniqueBytes:   snapshot.cumulative,
		LastRecordID:            snapshot.lastRecord,
		LastRecordSequence:      snapshot.lastRecordSequence,
		RecordSetDigest:         snapshot.recordSet,
		PolicyDigest:            billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes:  billingvoucher.MaxBillableBytes,
	}
	bodyBytes, err := body.CanonicalBytes()
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	relaySignature, err := billingvoucher.SignRelayBilling(body, pipeline.node.billingPrivateKey)
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	response, err := claim(ctx, billingcontrol.Message{
		Type: billingcontrol.TypeClaim, Body: bodyBytes,
		RelaySignature: relaySignature, RelayPublicKey: pipeline.node.pubKeyHex(),
		RelayBillingPublicKey: pipeline.node.billingPublicKeyForWire(),
		RelayCert:             pipeline.relayCert,
	})
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	if response.Type == billingcontrol.TypeReject {
		return billingvoucher.MutualVoucher{}, errors.New("relaynode: payer rejected billing claim")
	}
	voucher, err := billingvoucher.ParseCanonicalVoucher(response.Voucher)
	if err != nil {
		return billingvoucher.MutualVoucher{}, fmt.Errorf("relaynode: invalid cosigned voucher: %w", err)
	}
	if voucher.Body != body {
		return billingvoucher.MutualVoucher{}, errors.New("relaynode: payer changed the billing voucher body")
	}
	config := pipeline.node.admissionConfig()
	if response.PayerCert == nil || response.PayerCert.Cert.SubjectPubKey != response.PayerPublicKey ||
		config == nil || config.Verifier == nil {
		return billingvoucher.MutualVoucher{}, errors.New("relaynode: cosigned voucher lacks a bound payer certificate")
	}
	if err := config.Verifier.Verify(response.PayerCert, admission.VerifyOptions{
		ExpectNodeID: session.payerID.String(), ExpectRole: admission.RoleServer,
	}); err != nil {
		return billingvoucher.MutualVoucher{}, fmt.Errorf("relaynode: verify cosigning payer certificate: %w", err)
	}
	payerSigningPublicKeyHex, payerBillingPublicKeyHex, err := certificateSigningPublicKey(
		response.PayerCert, response.PayerPublicKey,
	)
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	if response.PayerBillingPublicKey != payerBillingPublicKeyHex {
		return billingvoucher.MutualVoucher{}, errors.New("relaynode: payer billing key does not match its certificate")
	}
	payerPublicKey, err := parseBillingPublicKey(payerSigningPublicKeyHex)
	if err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	if err := voucher.VerifyBillingSignatures(payerPublicKey, pipeline.node.billingPrivateKey.PublicKey()); err != nil {
		return billingvoucher.MutualVoucher{}, err
	}
	if registered := pipeline.node.accounts.cert(session.payerID.String()); registered == nil ||
		registered.Cert.SubjectPubKey != response.PayerPublicKey ||
		registered.Cert.AuthorizationID != response.PayerCert.Cert.AuthorizationID ||
		registered.Cert.BillingPubKey != response.PayerCert.Cert.BillingPubKey {
		return billingvoucher.MutualVoucher{}, errors.New("relaynode: cosigning payer differs from the registered server")
	}
	if err := pipeline.queue.EnqueueEnvelope(billingqueue.Envelope{
		Voucher: voucher, PayerPublicKey: response.PayerPublicKey,
		PayerBillingPublicKey: response.PayerBillingPublicKey, PayerCert: response.PayerCert,
	}); err != nil {
		if errors.Is(err, billingqueue.ErrFull) || errors.Is(err, billingqueue.ErrPayerFull) {
			return billingvoucher.MutualVoucher{}, fmt.Errorf("relaynode: waitSubmit capacity rejected payer: %w", err)
		}
		pipeline.poison(fmt.Errorf("relaynode: persist waitSubmit growth: %w", err))
		return billingvoucher.MutualVoucher{}, pipeline.operational()
	}
	pipeline.signalSubmit()
	return voucher, nil
}

func parseBillingPublicKey(publicKeyHex string) (*ecdh.PublicKey, error) {
	encoded, err := hex.DecodeString(publicKeyHex)
	if err != nil || hex.EncodeToString(encoded) != publicKeyHex {
		return nil, errors.New("relaynode: invalid payer public key encoding")
	}
	publicKey, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil, errors.New("relaynode: invalid payer public key")
	}
	return publicKey, nil
}

func (pipeline *relayBillingPipeline) signalSubmit() {
	select {
	case pipeline.wake <- struct{}{}:
	default:
	}
}

func (pipeline *relayBillingPipeline) submitLoop() {
	defer pipeline.wait.Done()
	ticker := time.NewTicker(pipeline.retryEvery)
	defer ticker.Stop()
	pipeline.submitPending()
	for {
		select {
		case <-pipeline.done:
			return
		case <-pipeline.node.ctx.Done():
			return
		case <-pipeline.wake:
			pipeline.submitPending()
		case <-ticker.C:
			pipeline.submitPending()
		}
	}
}

func (pipeline *relayBillingPipeline) submitPending() {
	if pipeline.operational() != nil {
		return
	}
	pipeline.submitMu.Lock()
	defer pipeline.submitMu.Unlock()
	deferred := make(map[billingvoucher.Identifier]struct{})
	for {
		heads, err := pipeline.queue.ChannelHeads()
		if err == nil && len(heads) == 0 {
			return
		}
		if err != nil {
			pipeline.poison(fmt.Errorf("relaynode: read waitSubmit channel heads: %w", err))
			return
		}
		progressed := false
		for _, envelope := range heads {
			voucher := envelope.Voucher
			sessionID := voucher.Body.SessionID
			if _, skip := deferred[sessionID]; skip || pipeline.sessionSettlementBlocked(sessionID) {
				continue
			}
			payerID := voucher.Body.PayerNatID.String()
			payerCert, relayCert, certErr := pipeline.currentSettlementCertificates(envelope)
			if certErr != nil {
				pipeline.node.accounts.setCutoff(payerID, true)
				deferred[sessionID] = struct{}{}
				logx.Warnf("[relaynode] waitSubmit 等待同公钥证书续签 payer=%.16s seq=%d: %v",
					payerID, voucher.Body.Sequence, certErr)
				continue
			}
			canonical, err := voucher.CanonicalBytes()
			if err != nil {
				pipeline.poison(fmt.Errorf("relaynode: encode waitSubmit voucher: %w", err))
				return
			}
			voucherID, err := voucher.ID()
			if err != nil {
				pipeline.poison(fmt.Errorf("relaynode: derive waitSubmit voucher ID: %w", err))
				return
			}
			settleContext, cancel := context.WithTimeout(pipeline.node.ctx, billingControlTimeout)
			response, settleErr := pipeline.settler.SettleVoucher(settleContext, admission.VoucherSettleRequest{
				CanonicalVoucher: canonical,
				PayerPublicKey:   envelope.PayerPublicKey, RelayPublicKey: pipeline.node.pubKeyHex(),
				PayerBillingPubKey: envelope.PayerBillingPublicKey,
				RelayBillingPubKey: pipeline.node.billingPublicKeyForWire(),
				PayerCert:          payerCert, RelayCert: relayCert,
			})
			cancel()
			if settleErr != nil {
				deferred[sessionID] = struct{}{}
				if response == nil {
					logx.Warnf("[relaynode] waitSubmit 无法访问 CA，保留凭证等待恢复 payer=%.16s seq=%d: %v",
						payerID, voucher.Body.Sequence, settleErr)
					continue
				}
				if response.DenyDecision != nil {
					if denyErr := pipeline.node.applyDenyDecision(response.DenyDecision); denyErr != nil {
						logx.Errorf("[relaynode] CA 返回的永久拒绝未通过本地验签，保留凭证但不写 deny: payer=%.16s seq=%d err=%v",
							payerID, voucher.Body.Sequence, denyErr)
					} else {
						logx.Warnf("[relaynode] CA 签名永久拒绝已应用: payer=%.16s seq=%d code=%s",
							payerID, voucher.Body.Sequence, response.DenyDecision.ErrorCode)
					}
				}
				if response.Retryable {
					if response.ErrorCode == admission.VoucherErrorInsufficientFunds {
						pipeline.node.accounts.setCutoff(payerID, true)
					}
					logx.Warnf("[relaynode] waitSubmit 凭证暂不可结算，保留等待恢复 payer=%.16s seq=%d code=%s",
						payerID, voucher.Body.Sequence, response.ErrorCode)
					continue
				}
				pipeline.node.accounts.setCutoff(payerID, true)
				pipeline.blockSession(sessionID, fmt.Errorf("relaynode: CA rejected durable voucher: %w", settleErr))
				logx.Errorf("[relaynode] waitSubmit 凭证被 CA 拒绝并冻结通道 payer=%.16s seq=%d: %v",
					payerID, voucher.Body.Sequence, settleErr)
				continue
			}
			if response == nil || response.VoucherID != voucherID.String() {
				pipeline.blockSession(sessionID, errors.New("relaynode: CA returned a mismatched voucher decision"))
				pipeline.node.accounts.setCutoff(payerID, true)
				deferred[sessionID] = struct{}{}
				continue
			}
			pipeline.node.accounts.setCutoff(payerID, !response.Allow)
			if !response.Allow {
				deferred[sessionID] = struct{}{}
				logx.Warnf("[relaynode] payer 余额已耗尽，保留已结算凭证作为充值恢复令牌 payer=%.16s seq=%d",
					payerID, voucher.Body.Sequence)
				continue
			}
			if err := pipeline.queue.RemoveChannelHead(voucherID); err != nil {
				pipeline.poison(fmt.Errorf("relaynode: persist waitSubmit removal: %w", err))
				return
			}
			progressed = true
			logx.Infof("[relaynode] 双签凭证已提交 payer=%.16s seq=%d delta=%dB waitSubmit=%d",
				payerID, voucher.Body.Sequence, response.Delta, pipeline.queue.Len())
		}
		if !progressed {
			return
		}
	}
}

func (pipeline *relayBillingPipeline) currentSettlementCertificates(
	envelope billingqueue.Envelope,
) (*admission.SignedCert, *admission.SignedCert, error) {
	now := time.Now().Unix()
	payerID := envelope.Voucher.Body.PayerNatID.String()
	payerCert := envelope.PayerCert
	if latest := pipeline.node.accounts.cert(payerID); settlementCertificateMatches(
		latest, payerID, envelope.PayerPublicKey, envelope.PayerBillingPublicKey,
		admission.RoleServer, now,
	) {
		payerCert = latest
	}
	if !settlementCertificateMatches(
		payerCert, payerID, envelope.PayerPublicKey, envelope.PayerBillingPublicKey,
		admission.RoleServer, now,
	) {
		return nil, nil, errors.New("payer certificate is unavailable or expired")
	}

	relayID := pipeline.relayID.String()
	relayPublicKey := pipeline.node.pubKeyHex()
	relayBillingPublicKey := pipeline.node.billingPublicKeyForWire()
	relayCert := pipeline.relayCert
	if config := pipeline.node.admissionConfig(); config != nil && settlementCertificateMatches(
		config.SelfCert, relayID, relayPublicKey, relayBillingPublicKey, admission.RoleRelay, now,
	) {
		relayCert = config.SelfCert
	}
	if !settlementCertificateMatches(
		relayCert, relayID, relayPublicKey, relayBillingPublicKey, admission.RoleRelay, now,
	) {
		return nil, nil, errors.New("Relay certificate is unavailable or expired")
	}
	return payerCert, relayCert, nil
}

func settlementCertificateMatches(
	certificate *admission.SignedCert,
	nodeID string,
	publicKey string,
	billingPublicKey string,
	role admission.Role,
	now int64,
) bool {
	if certificate == nil || certificate.Cert.SubjectNodeID != nodeID ||
		certificate.Cert.SubjectPubKey != publicKey || certificate.Cert.Role != role ||
		now < certificate.Cert.NotBefore || now >= certificate.Cert.NotAfter {
		return false
	}
	_, expectedBillingPublicKey, err := certificateSigningPublicKey(certificate, publicKey)
	return err == nil && expectedBillingPublicKey == billingPublicKey
}

func certificateSigningPublicKey(
	certificate *admission.SignedCert,
	identityPublicKey string,
) (string, string, error) {
	if certificate == nil || certificate.Cert.SubjectPubKey != identityPublicKey {
		return "", "", errors.New("relaynode: certificate does not match node identity")
	}
	if err := admission.ValidateBillingBinding(certificate.Cert); err != nil {
		return "", "", fmt.Errorf("relaynode: invalid certificate billing binding: %w", err)
	}
	if certificate.Cert.AuthorizationID == "" {
		return identityPublicKey, "", nil
	}
	return certificate.Cert.BillingPubKey, certificate.Cert.BillingPubKey, nil
}

func (pipeline *relayBillingPipeline) sessionBlocked(sessionID billingvoucher.Identifier) bool {
	pipeline.mu.Lock()
	session := pipeline.sessions[sessionID]
	pipeline.mu.Unlock()
	if session == nil {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.blocked != nil
}

func (pipeline *relayBillingPipeline) sessionSettlementBlocked(sessionID billingvoucher.Identifier) bool {
	pipeline.mu.Lock()
	session := pipeline.sessions[sessionID]
	pipeline.mu.Unlock()
	if session == nil {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.blocked != nil && !errors.Is(session.blocked, errBillingSessionRotated)
}

func (pipeline *relayBillingPipeline) blockSession(sessionID billingvoucher.Identifier, err error) {
	pipeline.mu.Lock()
	session := pipeline.sessions[sessionID]
	pipeline.mu.Unlock()
	if session == nil {
		return
	}
	session.mu.Lock()
	if session.blocked == nil || errors.Is(session.blocked, errBillingSessionRotated) {
		session.blocked = err
	}
	session.mu.Unlock()
}

func (pipeline *relayBillingPipeline) blockPayers(payerIDs []string, err error) {
	if pipeline == nil || len(payerIDs) == 0 {
		return
	}
	wanted := make(map[billingvoucher.Identifier]struct{}, len(payerIDs))
	for _, payerID := range payerIDs {
		identifier, parseErr := billingvoucher.ParseIdentifierHex(payerID)
		if parseErr == nil {
			wanted[identifier] = struct{}{}
		}
	}
	pipeline.mu.Lock()
	sessions := make([]*relayBillingSession, 0, len(wanted))
	for payerID := range wanted {
		for _, session := range pipeline.sessions {
			if session.payerID == payerID {
				sessions = append(sessions, session)
			}
		}
	}
	pipeline.mu.Unlock()
	for _, session := range sessions {
		pipeline.blockSession(session.sessionID, err)
	}
	pipeline.controlMu.Lock()
	peers := make([]*relayBillingControlPeer, 0, len(wanted))
	for payerID, peer := range pipeline.controls {
		if _, ok := wanted[payerID]; ok {
			peers = append(peers, peer)
		}
	}
	pipeline.controlMu.Unlock()
	for _, peer := range peers {
		peer.close()
	}
}

func (pipeline *relayBillingPipeline) close() error {
	if pipeline == nil {
		return nil
	}
	select {
	case <-pipeline.done:
	default:
		close(pipeline.done)
	}
	pipeline.controlMu.Lock()
	peers := make([]*relayBillingControlPeer, 0, len(pipeline.controls))
	for _, peer := range pipeline.controls {
		peers = append(peers, peer)
	}
	pipeline.controls = make(map[billingvoucher.Identifier]*relayBillingControlPeer)
	pipeline.controlMu.Unlock()
	for _, peer := range peers {
		peer.close()
	}
	pipeline.wait.Wait()
	return pipeline.queue.Close()
}
