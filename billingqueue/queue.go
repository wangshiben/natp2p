package billingqueue

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingvoucher"
)

const (
	fileDomain              = "BNFS/BILLING-WAIT-SUBMIT/WAL/V3\n"
	legacyFileDomain        = "BNFS/BILLING-WAIT-SUBMIT/V2"
	envelopeDomain          = "BNFS/BILLING-SETTLEMENT-ENVELOPE/V1"
	frameEnqueue       byte = 1
	frameRemove        byte = 2
	framePrefixSize         = 4
	frameFixedBodySize      = 1 + sha256.Size + sha256.Size
	compactionFloor         = uint64(1 << 20)
	compactionCeiling       = uint64(8 << 20)
)

var (
	ErrClosed       = errors.New("billingqueue: queue is closed")
	ErrEmpty        = errors.New("billingqueue: queue is empty")
	ErrFull         = errors.New("billingqueue: queue capacity exceeded")
	ErrHeadMismatch = errors.New("billingqueue: voucher is not at queue head")
	ErrDuplicate    = errors.New("billingqueue: voucher is already queued")
	ErrPayerFull    = errors.New("billingqueue: payer queue capacity exceeded")
	ErrCorrupt      = errors.New("billingqueue: persistent queue is corrupt")
	ErrPoisoned     = errors.New("billingqueue: queue requires reopen after persistence failure")
)

type Limits struct {
	MaxItems         uint64
	MaxBytes         uint64
	MaxItemsPerPayer uint64
	MaxBytesPerPayer uint64
}

type payerUsage struct {
	items uint64
	bytes uint64
}

type Queue struct {
	mu           sync.Mutex
	path         string
	limits       Limits
	items        []entry
	liveIDs      map[billingvoucher.Identifier]struct{}
	payerUsage   map[billingvoucher.Identifier]payerUsage
	bytes        uint64
	lastHash     billingvoucher.Digest
	logBytes     uint64
	garbageBytes uint64
	closed       bool
	poisoned     error
}

// Envelope 保存 Relay 与 NAT 重启后继续提交持久化凭证所需的全部付款方控制材料。
type Envelope struct {
	Voucher               billingvoucher.MutualVoucher
	PayerPublicKey        string
	PayerBillingPublicKey string
	PayerCert             *admission.SignedCert
}

type entry struct {
	envelope   Envelope
	id         billingvoucher.Identifier
	encoded    []byte
	frameBytes uint64
}

type channelKey struct {
	session   billingvoucher.Identifier
	payer     billingvoucher.Identifier
	relay     billingvoucher.Identifier
	direction billingvoucher.Direction
}

type diskEnvelope struct {
	CanonicalVoucher      []byte                `json:"canonical_voucher"`
	PayerPublicKey        string                `json:"payer_public_key,omitempty"`
	PayerBillingPublicKey string                `json:"payer_billing_public_key,omitempty"`
	PayerCert             *admission.SignedCert `json:"payer_cert,omitempty"`
}

type replayEntry struct {
	entry   entry
	removed bool
}

type replayResult struct {
	items        []entry
	bytes        uint64
	lastHash     billingvoucher.Digest
	logBytes     uint64
	garbageBytes uint64
	validBytes   int
}

func Open(path string, limits Limits) (*Queue, error) {
	maximumFileSize, err := validateLimits(limits)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, errors.New("billingqueue: persistent queue path is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("billingqueue: resolve persistent queue path: %w", err)
	}
	directory := filepath.Dir(absolutePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("billingqueue: create persistent queue directory: %w", err)
	}

	queue := &Queue{
		path: absolutePath, limits: limits,
		liveIDs: make(map[billingvoucher.Identifier]struct{}), payerUsage: make(map[billingvoucher.Identifier]payerUsage),
	}
	encoded, exists, err := readFile(absolutePath, maximumFileSize)
	if err != nil {
		return nil, err
	}
	if !exists {
		installed, writeErr := writeAtomic(absolutePath, []byte(fileDomain))
		if writeErr != nil {
			if installed {
				return nil, fmt.Errorf("billingqueue: sync new persistent queue: %w", writeErr)
			}
			return nil, fmt.Errorf("billingqueue: create persistent queue: %w", writeErr)
		}
		queue.logBytes = uint64(len(fileDomain))
		return queue, nil
	}

	switch {
	case bytes.HasPrefix(encoded, []byte(fileDomain)):
		replayed, replayErr := replayWAL(encoded, limits)
		if replayErr != nil {
			return nil, replayErr
		}
		queue.items = replayed.items
		queue.bytes = replayed.bytes
		queue.lastHash = replayed.lastHash
		queue.logBytes = replayed.logBytes
		queue.garbageBytes = replayed.garbageBytes
		if replayed.validBytes != len(encoded) {
			if err := truncateTail(absolutePath, int64(replayed.validBytes)); err != nil {
				return nil, fmt.Errorf("billingqueue: truncate incomplete WAL tail: %w", err)
			}
		}
	case bytes.HasPrefix(encoded, []byte(legacyFileDomain)):
		items, payloadBytes, decodeErr := decodeLegacyFile(encoded, limits)
		if decodeErr != nil {
			return nil, decodeErr
		}
		queue.items = items
		queue.bytes = payloadBytes
		if err := queue.compactLocked(); err != nil {
			return nil, fmt.Errorf("billingqueue: migrate legacy queue: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: invalid file domain", ErrCorrupt)
	}
	for _, item := range queue.items {
		if _, duplicate := queue.liveIDs[item.id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate live voucher", ErrCorrupt)
		}
		queue.liveIDs[item.id] = struct{}{}
		payerID := item.envelope.Voucher.Body.PayerNatID
		usage := queue.payerUsage[payerID]
		usage.items++
		usage.bytes += uint64(len(item.encoded))
		queue.payerUsage[payerID] = usage
		if usage.items > queue.maxItemsPerPayer() || usage.bytes > queue.maxBytesPerPayer() {
			return nil, errors.New("billingqueue: persisted payer backlog exceeds configured capacity")
		}
	}
	return queue, nil
}

func (queue *Queue) Enqueue(voucher billingvoucher.MutualVoucher) error {
	return queue.enqueue(Envelope{Voucher: voucher}, false)
}

func (queue *Queue) EnqueueEnvelope(envelope Envelope) error {
	return queue.enqueue(envelope, true)
}

func (queue *Queue) enqueue(envelope Envelope, requireSettlementIdentity bool) error {
	encoded, canonicalEnvelope, err := encodeEnvelope(envelope, requireSettlementIdentity)
	if err != nil {
		return err
	}
	voucherID, err := canonicalEnvelope.Voucher.ID()
	if err != nil {
		return fmt.Errorf("billingqueue: derive mutual voucher ID: %w", err)
	}

	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.operationalLocked(); err != nil {
		return err
	}
	if _, exists := queue.liveIDs[voucherID]; exists {
		return ErrDuplicate
	}
	payerID := canonicalEnvelope.Voucher.Body.PayerNatID
	usage := queue.payerUsage[payerID]
	encodedSize := uint64(len(encoded))
	if uint64(len(queue.items)) >= queue.limits.MaxItems {
		return ErrFull
	}
	if encodedSize > queue.limits.MaxBytes-queue.bytes {
		return ErrFull
	}
	payerByteLimit := queue.maxBytesPerPayer()
	if usage.items >= queue.maxItemsPerPayer() || usage.bytes >= payerByteLimit ||
		encodedSize > payerByteLimit-usage.bytes {
		return ErrPayerFull
	}
	frame, frameHash, err := encodeFrame(frameEnqueue, encoded, queue.lastHash)
	if err != nil {
		return err
	}
	installed, appendErr := appendFrame(queue.path, frame)
	if installed {
		queue.items = append(queue.items, entry{
			envelope:   canonicalEnvelope,
			id:         voucherID,
			encoded:    bytes.Clone(encoded),
			frameBytes: uint64(len(frame)),
		})
		queue.liveIDs[voucherID] = struct{}{}
		usage.items++
		usage.bytes += encodedSize
		queue.payerUsage[payerID] = usage
		queue.bytes += encodedSize
		queue.lastHash = frameHash
		queue.logBytes += uint64(len(frame))
	}
	if appendErr != nil {
		queue.poisoned = appendErr
		return fmt.Errorf("billingqueue: persist enqueue: %w", appendErr)
	}
	return nil
}

func (queue *Queue) Peek() (billingvoucher.MutualVoucher, error) {
	envelope, err := queue.PeekEnvelope()
	return envelope.Voucher, err
}

func (queue *Queue) PeekEnvelope() (Envelope, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.operationalLocked(); err != nil {
		return Envelope{}, err
	}
	if len(queue.items) == 0 {
		return Envelope{}, ErrEmpty
	}
	return cloneEnvelope(queue.items[0].envelope), nil
}

// ChannelHeads 返回每个独立通道中最早的活动凭证。
// 结果保持全局入队顺序，同时允许跳过被阻断的付款方且不破坏通道前驱链。
func (queue *Queue) ChannelHeads() ([]Envelope, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.operationalLocked(); err != nil {
		return nil, err
	}
	heads := make([]Envelope, 0)
	seen := make(map[channelKey]struct{})
	for _, item := range queue.items {
		key := voucherChannel(item.envelope.Voucher)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		heads = append(heads, cloneEnvelope(item.envelope))
	}
	return heads, nil
}

func (queue *Queue) Snapshot() ([]billingvoucher.MutualVoucher, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.operationalLocked(); err != nil {
		return nil, err
	}
	vouchers := make([]billingvoucher.MutualVoucher, len(queue.items))
	for index := range queue.items {
		vouchers[index] = cloneVoucher(queue.items[index].envelope.Voucher)
	}
	return vouchers, nil
}

func (queue *Queue) SnapshotEnvelopes() ([]Envelope, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.operationalLocked(); err != nil {
		return nil, err
	}
	envelopes := make([]Envelope, len(queue.items))
	for index := range queue.items {
		envelopes[index] = cloneEnvelope(queue.items[index].envelope)
	}
	return envelopes, nil
}

func (queue *Queue) Remove(expectedID billingvoucher.Identifier) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.operationalLocked(); err != nil {
		return err
	}
	if len(queue.items) == 0 {
		return ErrEmpty
	}
	if queue.items[0].id != expectedID {
		return ErrHeadMismatch
	}
	return queue.removeIndexLocked(0)
}

// RemoveChannelHead 仅当凭证是所属通道最早的活动项时才持久删除；
// 其他通道中更早的项目可以继续保留。
func (queue *Queue) RemoveChannelHead(expectedID billingvoucher.Identifier) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.operationalLocked(); err != nil {
		return err
	}
	if len(queue.items) == 0 {
		return ErrEmpty
	}
	index := -1
	var key channelKey
	for candidateIndex := range queue.items {
		if queue.items[candidateIndex].id == expectedID {
			index = candidateIndex
			key = voucherChannel(queue.items[candidateIndex].envelope.Voucher)
			break
		}
	}
	if index < 0 {
		return ErrHeadMismatch
	}
	for candidateIndex := 0; candidateIndex < index; candidateIndex++ {
		if voucherChannel(queue.items[candidateIndex].envelope.Voucher) == key {
			return ErrHeadMismatch
		}
	}
	return queue.removeIndexLocked(index)
}

func (queue *Queue) removeIndexLocked(index int) error {
	item := queue.items[index]
	frame, frameHash, err := encodeFrame(frameRemove, item.id[:], queue.lastHash)
	if err != nil {
		return err
	}
	installed, appendErr := appendFrame(queue.path, frame)
	if installed {
		copy(queue.items[index:], queue.items[index+1:])
		queue.items[len(queue.items)-1] = entry{}
		queue.items = queue.items[:len(queue.items)-1]
		delete(queue.liveIDs, item.id)
		queue.bytes -= uint64(len(item.encoded))
		payerID := item.envelope.Voucher.Body.PayerNatID
		usage := queue.payerUsage[payerID]
		usage.items--
		usage.bytes -= uint64(len(item.encoded))
		if usage.items == 0 {
			delete(queue.payerUsage, payerID)
		} else {
			queue.payerUsage[payerID] = usage
		}
		queue.lastHash = frameHash
		queue.logBytes += uint64(len(frame))
		queue.garbageBytes += item.frameBytes + uint64(len(frame))
	}
	if appendErr != nil {
		queue.poisoned = appendErr
		return fmt.Errorf("billingqueue: persist removal: %w", appendErr)
	}
	if err := queue.maybeCompactLocked(); err != nil {
		queue.poisoned = err
		return fmt.Errorf("billingqueue: compact WAL: %w", err)
	}
	return nil
}

func (queue *Queue) maxItemsPerPayer() uint64 {
	if queue.limits.MaxItemsPerPayer == 0 {
		return queue.limits.MaxItems
	}
	return queue.limits.MaxItemsPerPayer
}

func (queue *Queue) maxBytesPerPayer() uint64 {
	if queue.limits.MaxBytesPerPayer == 0 {
		return queue.limits.MaxBytes
	}
	return queue.limits.MaxBytesPerPayer
}

func (queue *Queue) Len() int {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return len(queue.items)
}

func (queue *Queue) Bytes() uint64 {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.bytes
}

func (queue *Queue) Close() error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.closed = true
	return nil
}

func (queue *Queue) operationalLocked() error {
	if queue.closed {
		return ErrClosed
	}
	if queue.poisoned != nil {
		return fmt.Errorf("%w: %v", ErrPoisoned, queue.poisoned)
	}
	return nil
}

func (queue *Queue) maybeCompactLocked() error {
	if queue.garbageBytes < compactionFloor {
		return nil
	}
	liveBytes := queue.logBytes - queue.garbageBytes
	if queue.garbageBytes < liveBytes && queue.garbageBytes < compactionCeiling {
		return nil
	}
	return queue.compactLocked()
}

func (queue *Queue) compactLocked() error {
	encoded, frameSizes, lastHash, err := encodeCompacted(queue.items)
	if err != nil {
		return err
	}
	installed, writeErr := writeAtomic(queue.path, encoded)
	if installed {
		for index := range queue.items {
			queue.items[index].frameBytes = frameSizes[index]
		}
		queue.lastHash = lastHash
		queue.logBytes = uint64(len(encoded))
		queue.garbageBytes = 0
	}
	return writeErr
}

func validateLimits(limits Limits) (int64, error) {
	if limits.MaxItems == 0 {
		return 0, errors.New("billingqueue: MaxItems must be greater than zero")
	}
	if limits.MaxBytes == 0 {
		return 0, errors.New("billingqueue: MaxBytes must be greater than zero")
	}
	if limits.MaxItemsPerPayer > limits.MaxItems {
		return 0, errors.New("billingqueue: MaxItemsPerPayer exceeds MaxItems")
	}
	if limits.MaxBytesPerPayer > limits.MaxBytes {
		return 0, errors.New("billingqueue: MaxBytesPerPayer exceeds MaxBytes")
	}
	maximumInt := uint64(^uint(0) >> 1)
	if limits.MaxItems > maximumInt {
		return 0, errors.New("billingqueue: MaxItems exceeds platform capacity")
	}
	maximumAllowed := uint64(math.MaxInt64 - 1)
	frameOverhead := uint64(framePrefixSize + frameFixedBodySize)
	if limits.MaxItems > (maximumAllowed-uint64(len(fileDomain)))/frameOverhead {
		return 0, errors.New("billingqueue: limits exceed file capacity")
	}
	liveMaximum := uint64(len(fileDomain)) + limits.MaxItems*frameOverhead
	if limits.MaxBytes > maximumAllowed-liveMaximum {
		return 0, errors.New("billingqueue: MaxBytes exceeds file capacity")
	}
	liveMaximum += limits.MaxBytes
	if liveMaximum > (maximumAllowed-(16<<20))/4 {
		return 0, errors.New("billingqueue: limits exceed WAL capacity")
	}
	return int64(liveMaximum*4 + (16 << 20)), nil
}

func readFile(path string, maximumSize int64) ([]byte, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("billingqueue: open persistent queue: %w", err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, false, fmt.Errorf("billingqueue: inspect persistent queue: %w", err)
	}
	if !fileInfo.Mode().IsRegular() {
		file.Close()
		return nil, false, fmt.Errorf("%w: path is not a regular file", ErrCorrupt)
	}
	if fileInfo.Size() > maximumSize {
		file.Close()
		return nil, false, fmt.Errorf("%w: file exceeds configured limits", ErrCorrupt)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil {
		file.Close()
		return nil, false, fmt.Errorf("billingqueue: read persistent queue: %w", err)
	}
	if int64(len(encoded)) > maximumSize {
		file.Close()
		return nil, false, fmt.Errorf("%w: file exceeds configured limits", ErrCorrupt)
	}
	if err := file.Close(); err != nil {
		return nil, false, fmt.Errorf("billingqueue: close persistent queue after read: %w", err)
	}
	return encoded, true, nil
}

func encodeFrame(frameType byte, payload []byte, previous billingvoucher.Digest) ([]byte, billingvoucher.Digest, error) {
	bodyLength := frameFixedBodySize + len(payload)
	if bodyLength < frameFixedBodySize || uint64(bodyLength) > math.MaxUint32 {
		return nil, billingvoucher.Digest{}, errors.New("billingqueue: WAL frame is too large")
	}
	hash := frameDigest(frameType, previous, payload)
	encoded := make([]byte, framePrefixSize+bodyLength)
	binary.BigEndian.PutUint32(encoded[:framePrefixSize], uint32(bodyLength))
	cursor := framePrefixSize
	encoded[cursor] = frameType
	cursor++
	copy(encoded[cursor:cursor+sha256.Size], previous[:])
	cursor += sha256.Size
	copy(encoded[cursor:cursor+len(payload)], payload)
	cursor += len(payload)
	copy(encoded[cursor:], hash[:])
	return encoded, hash, nil
}

func frameDigest(frameType byte, previous billingvoucher.Digest, payload []byte) billingvoucher.Digest {
	hasher := sha256.New()
	hasher.Write([]byte(fileDomain))
	hasher.Write([]byte{frameType})
	hasher.Write(previous[:])
	hasher.Write(payload)
	var digest billingvoucher.Digest
	copy(digest[:], hasher.Sum(nil))
	return digest
}

func replayWAL(encoded []byte, limits Limits) (replayResult, error) {
	result := replayResult{validBytes: len(fileDomain), logBytes: uint64(len(fileDomain))}
	if len(encoded) < len(fileDomain) || !bytes.Equal(encoded[:len(fileDomain)], []byte(fileDomain)) {
		return replayResult{}, fmt.Errorf("%w: invalid WAL domain", ErrCorrupt)
	}
	states := make([]*replayEntry, 0)
	live := make(map[billingvoucher.Identifier]*replayEntry)
	channels := make(map[channelKey][]billingvoucher.Identifier)
	cursor := len(fileDomain)
	maximumPayload := limits.MaxBytes
	if maximumPayload < uint64(len(billingvoucher.Identifier{})) {
		maximumPayload = uint64(len(billingvoucher.Identifier{}))
	}
	maximumFrameBody := uint64(frameFixedBodySize) + maximumPayload
	if maximumFrameBody > math.MaxUint32 {
		maximumFrameBody = math.MaxUint32
	}
	for cursor < len(encoded) {
		frameStart := cursor
		if len(encoded)-cursor < framePrefixSize {
			break
		}
		bodyLength := uint64(binary.BigEndian.Uint32(encoded[cursor : cursor+framePrefixSize]))
		if bodyLength < frameFixedBodySize || bodyLength > maximumFrameBody {
			return replayResult{}, fmt.Errorf("%w: invalid WAL frame length at offset %d", ErrCorrupt, cursor)
		}
		frameLength := uint64(framePrefixSize) + bodyLength
		if frameLength > uint64(len(encoded)-cursor) {
			break
		}
		cursor += framePrefixSize
		frameEnd := frameStart + int(frameLength)
		frameType := encoded[cursor]
		cursor++
		var previous billingvoucher.Digest
		copy(previous[:], encoded[cursor:cursor+sha256.Size])
		cursor += sha256.Size
		payloadEnd := frameEnd - sha256.Size
		payload := encoded[cursor:payloadEnd]
		var storedHash billingvoucher.Digest
		copy(storedHash[:], encoded[payloadEnd:frameEnd])
		if previous != result.lastHash || storedHash != frameDigest(frameType, previous, payload) {
			return replayResult{}, fmt.Errorf("%w: WAL hash chain mismatch at offset %d", ErrCorrupt, frameStart)
		}
		frameBytes := uint64(frameEnd - frameStart)
		switch frameType {
		case frameEnqueue:
			envelope, err := decodeEnvelope(payload)
			if err != nil {
				return replayResult{}, fmt.Errorf("%w: invalid enqueue frame at offset %d: %v", ErrCorrupt, frameStart, err)
			}
			voucherID, err := envelope.Voucher.ID()
			if err != nil {
				return replayResult{}, fmt.Errorf("%w: invalid voucher ID at offset %d: %v", ErrCorrupt, frameStart, err)
			}
			if _, duplicate := live[voucherID]; duplicate {
				return replayResult{}, fmt.Errorf("%w: duplicate live voucher at offset %d", ErrCorrupt, frameStart)
			}
			if uint64(len(live)) >= limits.MaxItems || uint64(len(payload)) > limits.MaxBytes-result.bytes {
				return replayResult{}, fmt.Errorf("%w: live queue exceeds configured limits", ErrCorrupt)
			}
			state := &replayEntry{entry: entry{
				envelope: envelope, id: voucherID, encoded: bytes.Clone(payload), frameBytes: frameBytes,
			}}
			states = append(states, state)
			live[voucherID] = state
			key := voucherChannel(envelope.Voucher)
			channels[key] = append(channels[key], voucherID)
			result.bytes += uint64(len(payload))
		case frameRemove:
			if len(payload) != len(billingvoucher.Identifier{}) {
				return replayResult{}, fmt.Errorf("%w: invalid remove frame at offset %d", ErrCorrupt, frameStart)
			}
			var voucherID billingvoucher.Identifier
			copy(voucherID[:], payload)
			state := live[voucherID]
			if state == nil {
				return replayResult{}, fmt.Errorf("%w: remove references a non-live voucher at offset %d", ErrCorrupt, frameStart)
			}
			key := voucherChannel(state.entry.envelope.Voucher)
			channel := channels[key]
			if len(channel) == 0 || channel[0] != voucherID {
				return replayResult{}, fmt.Errorf("%w: remove violates channel FIFO at offset %d", ErrCorrupt, frameStart)
			}
			channels[key] = channel[1:]
			state.removed = true
			delete(live, voucherID)
			result.bytes -= uint64(len(state.entry.encoded))
			result.garbageBytes += state.entry.frameBytes + frameBytes
		default:
			return replayResult{}, fmt.Errorf("%w: unknown WAL frame type at offset %d", ErrCorrupt, frameStart)
		}
		result.lastHash = storedHash
		cursor = frameEnd
		result.validBytes = cursor
		result.logBytes += frameBytes
	}
	result.items = make([]entry, 0, len(live))
	for _, state := range states {
		if !state.removed {
			result.items = append(result.items, state.entry)
		}
	}
	return result, nil
}

func encodeCompacted(items []entry) ([]byte, []uint64, billingvoucher.Digest, error) {
	encoded := make([]byte, 0, len(fileDomain))
	encoded = append(encoded, fileDomain...)
	frameSizes := make([]uint64, len(items))
	var previous billingvoucher.Digest
	for index, item := range items {
		frame, frameHash, err := encodeFrame(frameEnqueue, item.encoded, previous)
		if err != nil {
			return nil, nil, billingvoucher.Digest{}, err
		}
		encoded = append(encoded, frame...)
		frameSizes[index] = uint64(len(frame))
		previous = frameHash
	}
	return encoded, frameSizes, previous, nil
}

func appendFrame(path string, encoded []byte) (bool, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false, err
	}
	written := 0
	for written < len(encoded) {
		count, writeErr := file.Write(encoded[written:])
		written += count
		if writeErr != nil {
			file.Close()
			return false, writeErr
		}
		if count == 0 {
			file.Close()
			return false, io.ErrShortWrite
		}
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return true, err
	}
	if err := file.Close(); err != nil {
		return true, err
	}
	return true, nil
}

func truncateTail(path string, size int64) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err := file.Truncate(size); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func decodeLegacyFile(encoded []byte, limits Limits) ([]entry, uint64, error) {
	minimumSize := len(legacyFileDomain) + 8 + sha256.Size
	if len(encoded) < minimumSize {
		return nil, 0, fmt.Errorf("%w: legacy file is truncated", ErrCorrupt)
	}
	payloadEnd := len(encoded) - sha256.Size
	expectedChecksum := sha256.Sum256(encoded[:payloadEnd])
	if !bytes.Equal(expectedChecksum[:], encoded[payloadEnd:]) {
		return nil, 0, fmt.Errorf("%w: legacy checksum mismatch", ErrCorrupt)
	}
	if !bytes.Equal(encoded[:len(legacyFileDomain)], []byte(legacyFileDomain)) {
		return nil, 0, fmt.Errorf("%w: invalid legacy file domain", ErrCorrupt)
	}
	cursor := len(legacyFileDomain)
	count := binary.BigEndian.Uint64(encoded[cursor : cursor+8])
	cursor += 8
	if count > limits.MaxItems || count > uint64(^uint(0)>>1) {
		return nil, 0, fmt.Errorf("%w: legacy item count exceeds configured limit", ErrCorrupt)
	}
	items := make([]entry, 0, int(count))
	var payloadBytes uint64
	for index := uint64(0); index < count; index++ {
		if payloadEnd-cursor < 4 {
			return nil, 0, fmt.Errorf("%w: missing legacy item length at item %d", ErrCorrupt, index)
		}
		length := uint64(binary.BigEndian.Uint32(encoded[cursor : cursor+4]))
		cursor += 4
		if length == 0 || length > uint64(payloadEnd-cursor) || length > limits.MaxBytes-payloadBytes {
			return nil, 0, fmt.Errorf("%w: invalid legacy item length at item %d", ErrCorrupt, index)
		}
		envelopeBytes := encoded[cursor : cursor+int(length)]
		envelope, err := decodeEnvelope(envelopeBytes)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: invalid legacy envelope at item %d: %v", ErrCorrupt, index, err)
		}
		voucherID, err := envelope.Voucher.ID()
		if err != nil {
			return nil, 0, fmt.Errorf("%w: invalid legacy voucher ID at item %d: %v", ErrCorrupt, index, err)
		}
		items = append(items, entry{envelope: envelope, id: voucherID, encoded: bytes.Clone(envelopeBytes)})
		payloadBytes += length
		cursor += int(length)
	}
	if cursor != payloadEnd {
		return nil, 0, fmt.Errorf("%w: trailing legacy queue data", ErrCorrupt)
	}
	return items, payloadBytes, nil
}

func writeAtomic(path string, encoded []byte) (bool, error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	written, err := temporary.Write(encoded)
	if err != nil {
		temporary.Close()
		return false, err
	}
	if written != len(encoded) {
		temporary.Close()
		return false, io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return false, err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return true, err
	}
	if err := directoryHandle.Sync(); err != nil {
		directoryHandle.Close()
		return true, err
	}
	if err := directoryHandle.Close(); err != nil {
		return true, err
	}
	return true, nil
}

func voucherChannel(voucher billingvoucher.MutualVoucher) channelKey {
	return channelKey{
		session:   voucher.Body.SessionID,
		payer:     voucher.Body.PayerNatID,
		relay:     voucher.Body.PayeeRelayID,
		direction: voucher.Body.Direction,
	}
}

func cloneVoucher(voucher billingvoucher.MutualVoucher) billingvoucher.MutualVoucher {
	voucher.PayerSignature = bytes.Clone(voucher.PayerSignature)
	voucher.RelaySignature = bytes.Clone(voucher.RelaySignature)
	return voucher
}

func encodeEnvelope(envelope Envelope, requireSettlementIdentity bool) ([]byte, Envelope, error) {
	voucherBytes, err := envelope.Voucher.CanonicalBytes()
	if err != nil {
		return nil, Envelope{}, fmt.Errorf("billingqueue: invalid mutual voucher: %w", err)
	}
	voucher, err := billingvoucher.ParseCanonicalVoucher(voucherBytes)
	if err != nil {
		return nil, Envelope{}, fmt.Errorf("billingqueue: invalid canonical mutual voucher: %w", err)
	}
	canonicalEnvelope := Envelope{
		Voucher: voucher, PayerPublicKey: envelope.PayerPublicKey,
		PayerBillingPublicKey: envelope.PayerBillingPublicKey,
		PayerCert:             cloneCertificate(envelope.PayerCert),
	}
	if err := validateSettlementIdentity(canonicalEnvelope, requireSettlementIdentity); err != nil {
		return nil, Envelope{}, err
	}
	disk := diskEnvelope{
		CanonicalVoucher:      voucherBytes,
		PayerPublicKey:        canonicalEnvelope.PayerPublicKey,
		PayerBillingPublicKey: canonicalEnvelope.PayerBillingPublicKey,
		PayerCert:             cloneCertificate(canonicalEnvelope.PayerCert),
	}
	payload, err := json.Marshal(disk)
	if err != nil {
		return nil, Envelope{}, fmt.Errorf("billingqueue: encode settlement envelope: %w", err)
	}
	encoded := make([]byte, 0, len(envelopeDomain)+len(payload))
	encoded = append(encoded, envelopeDomain...)
	encoded = append(encoded, payload...)
	return encoded, canonicalEnvelope, nil
}

func decodeEnvelope(encoded []byte) (Envelope, error) {
	if len(encoded) <= len(envelopeDomain) || !bytes.Equal(encoded[:len(envelopeDomain)], []byte(envelopeDomain)) {
		return Envelope{}, errors.New("invalid envelope domain")
	}
	var disk diskEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded[len(envelopeDomain):]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&disk); err != nil {
		return Envelope{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Envelope{}, errors.New("trailing envelope data")
	}
	voucher, err := billingvoucher.ParseCanonicalVoucher(disk.CanonicalVoucher)
	if err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{
		Voucher: voucher, PayerPublicKey: disk.PayerPublicKey,
		PayerBillingPublicKey: disk.PayerBillingPublicKey,
		PayerCert:             cloneCertificate(disk.PayerCert),
	}
	if err := validateSettlementIdentity(envelope, false); err != nil {
		return Envelope{}, err
	}
	canonical, _, err := encodeEnvelope(envelope, false)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Envelope{}, errors.New("non-canonical settlement envelope")
	}
	return envelope, nil
}

func validateSettlementIdentity(envelope Envelope, required bool) error {
	if envelope.PayerPublicKey == "" && envelope.PayerBillingPublicKey == "" && envelope.PayerCert == nil && !required {
		return nil
	}
	if envelope.PayerPublicKey == "" || envelope.PayerCert == nil {
		return errors.New("billingqueue: payer public key and certificate are required")
	}
	publicKeyBytes, err := hex.DecodeString(envelope.PayerPublicKey)
	if err != nil || hex.EncodeToString(publicKeyBytes) != envelope.PayerPublicKey {
		return errors.New("billingqueue: payer public key is not canonical hex")
	}
	if _, err := ecdh.P256().NewPublicKey(publicKeyBytes); err != nil {
		return errors.New("billingqueue: payer public key is invalid")
	}
	payerID := envelope.Voucher.Body.PayerNatID.String()
	if admission.NodeIDFromPubKeyHex(envelope.PayerPublicKey) != payerID ||
		envelope.PayerCert.Cert.SubjectNodeID != payerID ||
		envelope.PayerCert.Cert.SubjectPubKey != envelope.PayerPublicKey ||
		envelope.PayerCert.Cert.Role != admission.RoleServer {
		return errors.New("billingqueue: payer settlement identity does not match voucher")
	}
	if err := admission.ValidateBillingBinding(envelope.PayerCert.Cert); err != nil {
		return fmt.Errorf("billingqueue: payer certificate billing binding is invalid: %w", err)
	}
	if envelope.PayerCert.Cert.AuthorizationID == "" {
		if envelope.PayerBillingPublicKey != "" {
			return errors.New("billingqueue: legacy payer certificate cannot use an independent billing key")
		}
		return nil
	}
	if envelope.PayerBillingPublicKey == "" ||
		envelope.PayerBillingPublicKey != envelope.PayerCert.Cert.BillingPubKey {
		return errors.New("billingqueue: payer billing public key does not match certificate")
	}
	billingPublicKeyBytes, err := hex.DecodeString(envelope.PayerBillingPublicKey)
	if err != nil || hex.EncodeToString(billingPublicKeyBytes) != envelope.PayerBillingPublicKey {
		return errors.New("billingqueue: payer billing public key is not canonical hex")
	}
	if _, err := ecdh.P256().NewPublicKey(billingPublicKeyBytes); err != nil {
		return errors.New("billingqueue: payer billing public key is invalid")
	}
	return nil
}

func cloneEnvelope(envelope Envelope) Envelope {
	return Envelope{
		Voucher: cloneVoucher(envelope.Voucher), PayerPublicKey: envelope.PayerPublicKey,
		PayerBillingPublicKey: envelope.PayerBillingPublicKey,
		PayerCert:             cloneCertificate(envelope.PayerCert),
	}
}

func cloneCertificate(certificate *admission.SignedCert) *admission.SignedCert {
	if certificate == nil {
		return nil
	}
	copyCertificate := *certificate
	return &copyCertificate
}
