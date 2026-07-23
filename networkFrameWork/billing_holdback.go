package networkFrameWork

import (
	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	billingHandshakeInfoRoute = "/p2p/handshake-info"
	noisePreludeMaxMessages   = 4
	noisePreludeMaxBytes      = 16 << 10
	handshakeInfoMaxBytes     = 64 << 10
)

type messageHoldbackLimits struct {
	maxMessageBytes                       int64
	maxMessageFrames                      uint32
	maxConnectionBytes                    int64
	maxConnectionMessages                 int
	maxConnectionFrames                   int
	maxGlobalBytes                        int64
	maxGlobalMessages                     int
	maxGlobalFrames                       int
	maxConnections                        int
	pendingTTL                            time.Duration
	approvedTTL                           time.Duration
	maxApprovedFingerprintBytes           int64
	maxConnectionApprovedFingerprintBytes int64
	maxApprovedMessages                   int
	maxConnectionApprovedMessages         int
}

func defaultMessageHoldbackLimits() messageHoldbackLimits {
	return messageHoldbackLimits{
		maxMessageBytes:                       int64(billingvoucher.CumulativeWindowBytes) + 128<<10,
		maxMessageFrames:                      2048,
		maxConnectionBytes:                    8 << 20,
		maxConnectionMessages:                 16,
		maxConnectionFrames:                   8192,
		maxGlobalBytes:                        64 << 20,
		maxGlobalMessages:                     4096,
		maxGlobalFrames:                       65536,
		maxConnections:                        frameRouteMaxPairs,
		pendingTTL:                            30 * time.Second,
		approvedTTL:                           frameRouteTombstoneTTL,
		maxApprovedFingerprintBytes:           32 << 20,
		maxConnectionApprovedFingerprintBytes: 2 << 20,
		maxApprovedMessages:                   8192,
		maxConnectionApprovedMessages:         512,
	}
}

type messageHoldbackKey struct {
	nodeID       string
	connectionID string
	messageID    uint64
}

type messageHoldbackConnectionKey struct {
	nodeID       string
	connectionID string
}

type messageHoldbackConnection struct {
	validationMu             sync.Mutex
	pendingBytes             int64
	pendingMessages          int
	pendingFrames            int
	approvedFingerprintBytes int64
	approvedMessages         int
	noiseMask                uint8
	noiseMessages            uint8
	handshakeInfoSeen        bool
	billingEstablished       bool
}

type messageHoldbackPhase struct {
	noiseMask          uint8
	noiseMessages      uint8
	handshakeInfoSeen  bool
	billingEstablished bool
}

type messageHoldbackEntry struct {
	key              messageHoldbackKey
	totalFrames      uint32
	frames           map[uint32]*network.Frame
	digests          map[uint32][sha256.Size]byte
	bytes            int64
	pending          bool
	validating       bool
	approved         bool
	deferred         bool
	message          *network.Message
	fingerprintBytes int64
	timer            *time.Timer
	timerGeneration  uint64
	approvedItem     *list.Element
}

type messageHoldbackCompletion struct {
	entry   *messageHoldbackEntry
	frames  []*network.Frame
	message *network.Message
}

type messageHoldbackApproval struct {
	kind     uint8
	noiseBit uint8
}

const (
	holdbackApprovalNoise uint8 = iota + 1
	holdbackApprovalHandshakeInfo
	holdbackApprovalKeepAlive
	holdbackApprovalBilling
)

type messageHoldback struct {
	mu               sync.Mutex
	limits           messageHoldbackLimits
	entries          map[messageHoldbackKey]*messageHoldbackEntry
	connections      map[messageHoldbackConnectionKey]*messageHoldbackConnection
	approved         *list.List
	pendingBytes     int64
	pendingMessages  int
	pendingFrames    int
	approvedBytes    int64
	approvedMessages int
}

type messageHoldbackSnapshot struct {
	PendingBytes     int64
	PendingMessages  int
	PendingFrames    int
	ApprovedBytes    int64
	ApprovedMessages int
	Connections      int
}

func newMessageHoldback(limits messageHoldbackLimits) *messageHoldback {
	return &messageHoldback{
		limits:      limits,
		entries:     make(map[messageHoldbackKey]*messageHoldbackEntry),
		connections: make(map[messageHoldbackConnectionKey]*messageHoldbackConnection),
		approved:    list.New(),
	}
}

func (config *ForwardHookConfig) ensureMessageHoldback() *messageHoldback {
	if config == nil || config.BillableRecordHook == nil {
		return nil
	}
	config.holdbackOnce.Do(func() {
		limits := defaultMessageHoldbackLimits()
		if config.holdbackLimits != nil {
			limits = *config.holdbackLimits
		}
		config.holdback = newMessageHoldback(limits)
	})
	return config.holdback
}

func (holdback *messageHoldback) add(nodeID string, frame *network.Frame) (*messageHoldbackCompletion, error) {
	if frame == nil {
		return nil, errors.New("billing holdback: nil frame")
	}
	if frame.FrameType != network.FrameTypeData && frame.FrameType != network.FrameTypeRetransmit {
		return &messageHoldbackCompletion{frames: []*network.Frame{frame}}, nil
	}
	if frame.ConnectionId == "" {
		return nil, errors.New("billing holdback: data frame has no connection")
	}
	if frame.MessageId == 0 || frame.TotalFrames == 0 || frame.SeqId >= frame.TotalFrames {
		return nil, errors.New("billing holdback: invalid message frame coordinates")
	}
	if frame.TotalFrames > holdback.limits.maxMessageFrames {
		return nil, fmt.Errorf("billing holdback: message frame count %d exceeds limit %d", frame.TotalFrames, holdback.limits.maxMessageFrames)
	}

	key := messageHoldbackKey{nodeID: nodeID, connectionID: frame.ConnectionId, messageID: frame.MessageId}
	connectionKey := messageHoldbackConnectionKey{nodeID: nodeID, connectionID: frame.ConnectionId}
	digest := sha256.Sum256(frame.Payload)
	payloadBytes := int64(len(frame.Payload))

	holdback.mu.Lock()
	entry := holdback.entries[key]
	if entry != nil {
		if entry.totalFrames != frame.TotalFrames {
			holdback.mu.Unlock()
			return nil, errors.New("billing holdback: TotalFrames changed for existing message")
		}
		if expected, exists := entry.digests[frame.SeqId]; exists {
			if !bytes.Equal(expected[:], digest[:]) {
				holdback.mu.Unlock()
				return nil, errors.New("billing holdback: conflicting content for the same frame sequence")
			}
			if entry.approved {
				frameCopy := cloneFrame(frame)
				holdback.mu.Unlock()
				return &messageHoldbackCompletion{frames: []*network.Frame{frameCopy}}, nil
			}
			holdback.mu.Unlock()
			return nil, nil
		}
		if entry.approved || entry.validating {
			holdback.mu.Unlock()
			return nil, errors.New("billing holdback: approved message has an unknown frame sequence")
		}
	}

	connection := holdback.connections[connectionKey]
	if connection == nil {
		if len(holdback.connections) >= holdback.limits.maxConnections {
			holdback.mu.Unlock()
			return nil, errors.New("billing holdback: global connection limit reached")
		}
		connection = &messageHoldbackConnection{}
		holdback.connections[connectionKey] = connection
	}
	newMessage := entry == nil
	if newMessage {
		if connection.pendingMessages >= holdback.limits.maxConnectionMessages {
			holdback.removeIdleConnectionLocked(connectionKey, connection)
			holdback.mu.Unlock()
			return nil, errors.New("billing holdback: per-connection message limit reached")
		}
		if holdback.pendingMessages >= holdback.limits.maxGlobalMessages {
			holdback.removeIdleConnectionLocked(connectionKey, connection)
			holdback.mu.Unlock()
			return nil, errors.New("billing holdback: global message limit reached")
		}
		entry = &messageHoldbackEntry{
			key:         key,
			totalFrames: frame.TotalFrames,
			frames:      make(map[uint32]*network.Frame),
			digests:     make(map[uint32][sha256.Size]byte),
			pending:     true,
		}
	}
	if entry.bytes > holdback.limits.maxMessageBytes-payloadBytes {
		holdback.removeIdleConnectionLocked(connectionKey, connection)
		holdback.mu.Unlock()
		return nil, errors.New("billing holdback: per-message byte limit reached")
	}
	if connection.pendingBytes > holdback.limits.maxConnectionBytes-payloadBytes {
		holdback.removeIdleConnectionLocked(connectionKey, connection)
		holdback.mu.Unlock()
		return nil, errors.New("billing holdback: per-connection byte limit reached")
	}
	if connection.pendingFrames >= holdback.limits.maxConnectionFrames {
		holdback.removeIdleConnectionLocked(connectionKey, connection)
		holdback.mu.Unlock()
		return nil, errors.New("billing holdback: per-connection frame limit reached")
	}
	if holdback.pendingBytes > holdback.limits.maxGlobalBytes-payloadBytes {
		holdback.removeIdleConnectionLocked(connectionKey, connection)
		holdback.mu.Unlock()
		return nil, errors.New("billing holdback: global byte limit reached")
	}
	if holdback.pendingFrames >= holdback.limits.maxGlobalFrames {
		holdback.removeIdleConnectionLocked(connectionKey, connection)
		holdback.mu.Unlock()
		return nil, errors.New("billing holdback: global frame limit reached")
	}
	if newMessage {
		holdback.entries[key] = entry
		holdback.pendingMessages++
		connection.pendingMessages++
	}
	entry.frames[frame.SeqId] = cloneFrame(frame)
	entry.digests[frame.SeqId] = digest
	entry.bytes += payloadBytes
	holdback.pendingBytes += payloadBytes
	holdback.pendingFrames++
	connection.pendingBytes += payloadBytes
	connection.pendingFrames++
	holdback.scheduleLocked(entry, holdback.limits.pendingTTL)
	if uint32(len(entry.frames)) != entry.totalFrames {
		holdback.mu.Unlock()
		return nil, nil
	}
	entry.validating = true
	holdback.stopTimerLocked(entry)
	frames := orderedFrames(entry.frames)
	holdback.mu.Unlock()

	message, err := network.AssembleFrames(frames)
	if err != nil {
		holdback.reject(entry)
		return nil, fmt.Errorf("billing holdback: assemble message: %w", err)
	}
	return &messageHoldbackCompletion{entry: entry, frames: frames, message: message}, nil
}

func (holdback *messageHoldback) phase(entry *messageHoldbackEntry) (messageHoldbackPhase, bool) {
	if holdback == nil || entry == nil {
		return messageHoldbackPhase{}, false
	}
	holdback.mu.Lock()
	defer holdback.mu.Unlock()
	if holdback.entries[entry.key] != entry || !entry.validating {
		return messageHoldbackPhase{}, false
	}
	connection := holdback.connections[messageHoldbackConnectionKey{nodeID: entry.key.nodeID, connectionID: entry.key.connectionID}]
	if connection == nil {
		return messageHoldbackPhase{}, false
	}
	return messageHoldbackPhase{
		noiseMask: connection.noiseMask, noiseMessages: connection.noiseMessages,
		handshakeInfoSeen: connection.handshakeInfoSeen, billingEstablished: connection.billingEstablished,
	}, true
}

func (holdback *messageHoldback) validationMutex(entry *messageHoldbackEntry) (*sync.Mutex, bool) {
	if holdback == nil || entry == nil {
		return nil, false
	}
	holdback.mu.Lock()
	defer holdback.mu.Unlock()
	if holdback.entries[entry.key] != entry || !entry.validating {
		return nil, false
	}
	connection := holdback.connections[messageHoldbackConnectionKey{
		nodeID: entry.key.nodeID, connectionID: entry.key.connectionID,
	}]
	if connection == nil {
		return nil, false
	}
	return &connection.validationMu, true
}

func (holdback *messageHoldback) deferCompletion(completion *messageHoldbackCompletion) bool {
	if holdback == nil || completion == nil || completion.entry == nil || completion.message == nil {
		return false
	}
	entry := completion.entry
	holdback.mu.Lock()
	defer holdback.mu.Unlock()
	if holdback.entries[entry.key] != entry || !entry.validating || !entry.pending {
		return false
	}
	entry.deferred = true
	entry.message = completion.message
	holdback.scheduleLocked(entry, holdback.limits.pendingTTL)
	return true
}

func (holdback *messageHoldback) nextDeferred(key messageHoldbackKey) *messageHoldbackCompletion {
	if holdback == nil {
		return nil
	}
	holdback.mu.Lock()
	defer holdback.mu.Unlock()
	var selected *messageHoldbackEntry
	for _, entry := range holdback.entries {
		if !entry.deferred || !entry.validating || !entry.pending || entry.message == nil ||
			entry.key.nodeID != key.nodeID || entry.key.connectionID != key.connectionID {
			continue
		}
		if selected == nil ||
			entry.message.Header.BillingSequence < selected.message.Header.BillingSequence ||
			entry.message.Header.BillingSequence == selected.message.Header.BillingSequence &&
				entry.key.messageID < selected.key.messageID {
			selected = entry
		}
	}
	if selected == nil {
		return nil
	}
	holdback.stopTimerLocked(selected)
	return &messageHoldbackCompletion{
		entry: selected, frames: orderedFrames(selected.frames), message: selected.message,
	}
}

func (holdback *messageHoldback) approve(entry *messageHoldbackEntry, approval messageHoldbackApproval) bool {
	if holdback == nil || entry == nil {
		return false
	}
	holdback.mu.Lock()
	defer holdback.mu.Unlock()
	if holdback.entries[entry.key] != entry || !entry.validating || !entry.pending {
		return false
	}
	connectionKey := messageHoldbackConnectionKey{nodeID: entry.key.nodeID, connectionID: entry.key.connectionID}
	connection := holdback.connections[connectionKey]
	if connection == nil {
		return false
	}

	holdback.pendingBytes -= entry.bytes
	holdback.pendingMessages--
	holdback.pendingFrames -= len(entry.digests)
	connection.pendingBytes -= entry.bytes
	connection.pendingMessages--
	connection.pendingFrames -= len(entry.digests)
	entry.frames = nil
	entry.bytes = 0
	entry.pending = false
	entry.validating = false
	entry.approved = true
	entry.deferred = false
	entry.message = nil
	entry.fingerprintBytes = int64(len(entry.digests) * sha256.Size)

	switch approval.kind {
	case holdbackApprovalNoise:
		connection.noiseMask |= approval.noiseBit
		connection.noiseMessages++
	case holdbackApprovalHandshakeInfo:
		connection.handshakeInfoSeen = true
	case holdbackApprovalKeepAlive:
	case holdbackApprovalBilling:
		connection.billingEstablished = true
	}

	holdback.approvedBytes += entry.fingerprintBytes
	holdback.approvedMessages++
	connection.approvedFingerprintBytes += entry.fingerprintBytes
	connection.approvedMessages++
	entry.approvedItem = holdback.approved.PushBack(entry)
	holdback.evictApprovedLocked(connectionKey)
	if holdback.entries[entry.key] == entry {
		holdback.scheduleLocked(entry, holdback.limits.approvedTTL)
	}
	return true
}

func (holdback *messageHoldback) reject(entry *messageHoldbackEntry) {
	if holdback == nil || entry == nil {
		return
	}
	holdback.mu.Lock()
	holdback.removeEntryLocked(entry)
	holdback.mu.Unlock()
}

func (holdback *messageHoldback) acknowledge(nodeID, connectionID string, messageID uint64) {
	if holdback == nil || connectionID == "" || messageID == 0 {
		return
	}
	holdback.mu.Lock()
	entry := holdback.entries[messageHoldbackKey{nodeID: nodeID, connectionID: connectionID, messageID: messageID}]
	if entry != nil && entry.approved {
		holdback.removeEntryLocked(entry)
	}
	holdback.mu.Unlock()
}

func (holdback *messageHoldback) forgetConnection(nodeID, connectionID string) {
	if holdback == nil || connectionID == "" {
		return
	}
	holdback.mu.Lock()
	for _, entry := range holdback.entries {
		if entry.key.nodeID == nodeID && entry.key.connectionID == connectionID {
			holdback.removeEntryLocked(entry)
		}
	}
	delete(holdback.connections, messageHoldbackConnectionKey{nodeID: nodeID, connectionID: connectionID})
	holdback.mu.Unlock()
}

func (holdback *messageHoldback) snapshot() messageHoldbackSnapshot {
	if holdback == nil {
		return messageHoldbackSnapshot{}
	}
	holdback.mu.Lock()
	defer holdback.mu.Unlock()
	return messageHoldbackSnapshot{
		PendingBytes: holdback.pendingBytes, PendingMessages: holdback.pendingMessages, PendingFrames: holdback.pendingFrames,
		ApprovedBytes: holdback.approvedBytes, ApprovedMessages: holdback.approvedMessages,
		Connections: len(holdback.connections),
	}
}

func (holdback *messageHoldback) scheduleLocked(entry *messageHoldbackEntry, timeout time.Duration) {
	holdback.stopTimerLocked(entry)
	entry.timerGeneration++
	generation := entry.timerGeneration
	if timeout <= 0 {
		timeout = time.Nanosecond
	}
	entry.timer = time.AfterFunc(timeout, func() {
		holdback.mu.Lock()
		if holdback.entries[entry.key] == entry && entry.timerGeneration == generation {
			holdback.removeEntryLocked(entry)
		}
		holdback.mu.Unlock()
	})
}

func (holdback *messageHoldback) stopTimerLocked(entry *messageHoldbackEntry) {
	if entry.timer != nil {
		entry.timer.Stop()
		entry.timer = nil
	}
}

func (holdback *messageHoldback) evictApprovedLocked(connectionKey messageHoldbackConnectionKey) {
	for holdback.approvedMessages > holdback.limits.maxApprovedMessages ||
		holdback.approvedBytes > holdback.limits.maxApprovedFingerprintBytes {
		item := holdback.approved.Front()
		if item == nil {
			break
		}
		holdback.removeEntryLocked(item.Value.(*messageHoldbackEntry))
	}
	for {
		connection := holdback.connections[connectionKey]
		if connection == nil || (connection.approvedMessages <= holdback.limits.maxConnectionApprovedMessages &&
			connection.approvedFingerprintBytes <= holdback.limits.maxConnectionApprovedFingerprintBytes) {
			break
		}
		var candidate *messageHoldbackEntry
		for item := holdback.approved.Front(); item != nil; item = item.Next() {
			entry := item.Value.(*messageHoldbackEntry)
			if entry.key.nodeID == connectionKey.nodeID && entry.key.connectionID == connectionKey.connectionID {
				candidate = entry
				break
			}
		}
		if candidate == nil {
			break
		}
		holdback.removeEntryLocked(candidate)
	}
}

func (holdback *messageHoldback) removeEntryLocked(entry *messageHoldbackEntry) {
	if entry == nil || holdback.entries[entry.key] != entry {
		return
	}
	delete(holdback.entries, entry.key)
	holdback.stopTimerLocked(entry)
	connectionKey := messageHoldbackConnectionKey{nodeID: entry.key.nodeID, connectionID: entry.key.connectionID}
	connection := holdback.connections[connectionKey]
	if entry.pending {
		holdback.pendingBytes -= entry.bytes
		holdback.pendingMessages--
		holdback.pendingFrames -= len(entry.digests)
		if connection != nil {
			connection.pendingBytes -= entry.bytes
			connection.pendingMessages--
			connection.pendingFrames -= len(entry.digests)
		}
	}
	if entry.approved {
		holdback.approvedBytes -= entry.fingerprintBytes
		holdback.approvedMessages--
		if connection != nil {
			connection.approvedFingerprintBytes -= entry.fingerprintBytes
			connection.approvedMessages--
		}
		if entry.approvedItem != nil {
			holdback.approved.Remove(entry.approvedItem)
			entry.approvedItem = nil
		}
	}
	holdback.removeIdleConnectionLocked(connectionKey, connection)
}

func (holdback *messageHoldback) removeIdleConnectionLocked(key messageHoldbackConnectionKey, connection *messageHoldbackConnection) {
	if connection == nil || connection.pendingMessages != 0 || connection.pendingFrames != 0 || connection.approvedMessages != 0 ||
		connection.noiseMessages != 0 || connection.handshakeInfoSeen || connection.billingEstablished {
		return
	}
	delete(holdback.connections, key)
}

func (state *forwardHookState) framesForForward(ctx context.Context, frame *network.Frame, direction string) ([]*network.Frame, error) {
	if state == nil || state.config == nil || frame == nil ||
		frame.FrameType != network.FrameTypeData && frame.FrameType != network.FrameTypeRetransmit ||
		direction != "relay_to_clients" || !state.billableRecordRequired(direction) {
		if frame == nil {
			return nil, nil
		}
		return []*network.Frame{frame}, nil
	}
	holdback := state.config.ensureMessageHoldback()
	completion, err := holdback.add(state.nodeID, frame)
	if err != nil || completion == nil {
		return nil, err
	}
	if completion.entry == nil {
		return completion.frames, nil
	}
	validationMu, ok := holdback.validationMutex(completion.entry)
	if !ok {
		holdback.reject(completion.entry)
		return nil, errors.New("billing holdback: message expired before validation")
	}
	validationMu.Lock()
	defer validationMu.Unlock()

	var authorized []*network.Frame
	for completion != nil {
		phase, phaseOK := holdback.phase(completion.entry)
		if !phaseOK {
			holdback.reject(completion.entry)
			return authorized, errors.New("billing holdback: message expired before validation")
		}
		approval, validateErr := state.validateHeldMessage(
			ctx, completion.message, completion.entry.key.connectionID, direction, phase,
		)
		if validateErr != nil {
			if errors.Is(validateErr, ErrBillableRecordDeferred) {
				if !holdback.deferCompletion(completion) {
					return authorized, errors.New("billing holdback: deferred message expired before retention")
				}
				return authorized, nil
			}
			holdback.reject(completion.entry)
			return authorized, validateErr
		}
		key := completion.entry.key
		if !holdback.approve(completion.entry, approval) {
			return authorized, nil
		}
		authorized = append(authorized, completion.frames...)
		completion = holdback.nextDeferred(key)
	}
	return authorized, nil
}

func (state *forwardHookState) validateHeldMessage(ctx context.Context, message *network.Message, connectionID, direction string, phase messageHoldbackPhase) (messageHoldbackApproval, error) {
	if message == nil || message.Header == nil {
		return messageHoldbackApproval{}, errors.New("billing holdback: assembled message has no header")
	}
	header := message.Header
	if header.ConnectionId == "" || header.ConnectionId != connectionID {
		return messageHoldbackApproval{}, errors.New("billing holdback: message and frame connection IDs differ")
	}
	if uint64(header.PayLoadLength) != uint64(len(message.Payload)) {
		return messageHoldbackApproval{}, errors.New("billing holdback: message payload length mismatch")
	}
	presentFields := 0
	if header.BillingSessionID != ([32]byte{}) {
		presentFields++
	}
	if header.BillingSequence != 0 {
		presentFields++
	}
	if header.BillingBytes != 0 {
		presentFields++
	}
	if presentFields != 0 && presentFields != 3 {
		return messageHoldbackApproval{}, errors.New("billing holdback: partial billing metadata")
	}

	switch {
	case header.RouteName == "":
		if presentFields != 0 || phase.billingEstablished || phase.handshakeInfoSeen {
			return messageHoldbackApproval{}, errors.New("billing holdback: Noise prelude is not allowed in the current phase")
		}
		noiseBit, ok := classifyNoisePrelude(message.Payload)
		if !ok || phase.noiseMask&noiseBit != 0 || phase.noiseMessages >= noisePreludeMaxMessages {
			return messageHoldbackApproval{}, errors.New("billing holdback: invalid or repeated Noise prelude")
		}
		return messageHoldbackApproval{kind: holdbackApprovalNoise, noiseBit: noiseBit}, nil
	case header.RouteName == KeepAliveRoute:
		if presentFields != 0 || !phase.handshakeInfoSeen {
			return messageHoldbackApproval{}, errors.New("billing holdback: keepalive is not allowed in the current phase")
		}
		metadata, err := crypoto.InspectE2ERecord(message.Payload)
		if err != nil {
			return messageHoldbackApproval{}, fmt.Errorf("billing holdback: keepalive is not an E2E record: %w", err)
		}
		if metadata.PlaintextBytes != 0 {
			return messageHoldbackApproval{}, errors.New("billing holdback: keepalive plaintext is not empty")
		}
		return messageHoldbackApproval{kind: holdbackApprovalKeepAlive}, nil
	case header.RouteName == billingHandshakeInfoRoute:
		if presentFields != 0 || phase.billingEstablished || phase.handshakeInfoSeen || len(message.Payload) > handshakeInfoMaxBytes {
			return messageHoldbackApproval{}, errors.New("billing holdback: handshake metadata is not allowed in the current phase")
		}
		if _, err := crypoto.InspectE2ERecord(message.Payload); err != nil {
			return messageHoldbackApproval{}, fmt.Errorf("billing holdback: handshake metadata is not an E2E record: %w", err)
		}
		return messageHoldbackApproval{kind: holdbackApprovalHandshakeInfo}, nil
	case state.config.BillableRoute != "" && header.RouteName == state.config.BillableRoute:
		if presentFields != 3 {
			return messageHoldbackApproval{}, errors.New("billing holdback: authenticated data is missing billing metadata")
		}
		if err := state.observeBillableRecord(ctx, message, direction); err != nil {
			return messageHoldbackApproval{}, err
		}
		return messageHoldbackApproval{kind: holdbackApprovalBilling}, nil
	default:
		return messageHoldbackApproval{}, fmt.Errorf("billing holdback: route %q is not allowed on a billable connection", header.RouteName)
	}
}

func classifyNoisePrelude(payload []byte) (uint8, bool) {
	if len(payload) < 9 || len(payload) > noisePreludeMaxBytes {
		return 0, false
	}
	switch string(payload[:8]) {
	case "BNFSN2H1":
		if len(payload) != 8+1+65 || payload[8] != 2 {
			return 0, false
		}
		return 1, true
	case "BNFSN2M1":
		sequence := payload[8]
		if sequence < 1 || sequence > 3 {
			return 0, false
		}
		return 1 << sequence, true
	case "BNFSN2C1":
		kind := payload[8]
		if kind < 1 || kind > 2 || len(payload) < 9+16 {
			return 0, false
		}
		return 1 << (3 + kind), true
	default:
		return 0, false
	}
}

func (state *forwardHookState) acknowledgeHeldMessage(connectionID string, messageID uint64) {
	if state == nil || state.config == nil {
		return
	}
	holdback := state.config.ensureMessageHoldback()
	if holdback != nil {
		holdback.acknowledge(state.nodeID, connectionID, messageID)
	}
}

func (config *ForwardHookConfig) forgetHeldConnection(nodeID, connectionID string) {
	if config == nil {
		return
	}
	holdback := config.ensureMessageHoldback()
	if holdback != nil {
		holdback.forgetConnection(nodeID, connectionID)
	}
}
