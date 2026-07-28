package networkFrameWork

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/network"
)

var e2eTestRecordPrefix = []byte("bnfs-e2e-test-record")

type countingE2ESuite struct {
	mu        sync.Mutex
	nextID    uint64
	sealCalls int
	openCalls int
}

func (suite *countingE2ESuite) Encrypt(payload []byte) ([]byte, error) {
	record, _, err := suite.EncryptWithMessageID(payload, nil)
	return record, err
}

func (suite *countingE2ESuite) Decrypt(record []byte) ([]byte, error) {
	plaintext, _, _, err := suite.DecryptWithMessageID(record)
	return plaintext, err
}

func (suite *countingE2ESuite) NewMessageID() []byte {
	suite.mu.Lock()
	suite.nextID++
	sequence := suite.nextID
	suite.mu.Unlock()

	return e2eTestMessageID(sequence)
}

func (suite *countingE2ESuite) EncryptWithMessageID(payload, messageID []byte) ([]byte, []byte, error) {
	return suite.EncryptWithMessageIDAndAAD(payload, nil, messageID)
}

func (suite *countingE2ESuite) EncryptWithMessageIDAndAAD(payload, aad, messageID []byte) ([]byte, []byte, error) {
	if len(messageID) == 0 {
		messageID = suite.NewMessageID()
	} else {
		messageID = append([]byte(nil), messageID...)
	}
	suite.mu.Lock()
	suite.sealCalls++
	suite.mu.Unlock()
	return makeE2ETestRecord(payload, messageID, aad), messageID, nil
}

func (suite *countingE2ESuite) DecryptWithMessageID(record []byte) ([]byte, []byte, bool, error) {
	return suite.DecryptWithMessageIDAndAAD(record, nil)
}

func (suite *countingE2ESuite) DecryptWithMessageIDAndAAD(record, aad []byte) ([]byte, []byte, bool, error) {
	suite.mu.Lock()
	suite.openCalls++
	suite.mu.Unlock()
	plaintext, messageID, err := parseE2ETestRecord(record, aad)
	if err != nil {
		return nil, nil, false, err
	}
	return plaintext, messageID, true, nil
}

func (suite *countingE2ESuite) counts() (int, int) {
	suite.mu.Lock()
	defer suite.mu.Unlock()
	return suite.sealCalls, suite.openCalls
}

func makeE2ETestRecord(payload, messageID, aad []byte) []byte {
	aadDigest := sha256.Sum256(aad)
	record := make([]byte, 0, len(e2eTestRecordPrefix)+2+len(messageID)+len(aadDigest)+len(payload))
	record = append(record, e2eTestRecordPrefix...)
	messageIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(messageIDLength, uint16(len(messageID)))
	record = append(record, messageIDLength...)
	record = append(record, messageID...)
	record = append(record, aadDigest[:]...)
	record = append(record, payload...)
	return record
}

func e2eTestMessageID(sequence uint64) []byte {
	messageID := make([]byte, e2eMessageIDSize)
	copy(messageID[:32], []byte("bnfs-e2e-test-session-identifier"))
	binary.BigEndian.PutUint32(messageID[32:36], 1)
	binary.BigEndian.PutUint64(messageID[36:44], sequence)
	return messageID
}

func parseE2ETestRecord(record, aad []byte) ([]byte, []byte, error) {
	headerLength := len(e2eTestRecordPrefix) + 2
	if len(record) < headerLength || !bytes.Equal(record[:len(e2eTestRecordPrefix)], e2eTestRecordPrefix) {
		return nil, nil, errors.New("invalid E2E record")
	}
	messageIDLength := int(binary.BigEndian.Uint16(record[len(e2eTestRecordPrefix):headerLength]))
	if messageIDLength == 0 || len(record) < headerLength+messageIDLength+sha256.Size {
		return nil, nil, errors.New("invalid E2E message ID")
	}
	messageID := append([]byte(nil), record[headerLength:headerLength+messageIDLength]...)
	aadOffset := headerLength + messageIDLength
	aadDigest := sha256.Sum256(aad)
	if !bytes.Equal(record[aadOffset:aadOffset+sha256.Size], aadDigest[:]) {
		return nil, nil, errors.New("E2E AAD mismatch")
	}
	plaintext := append([]byte(nil), record[aadOffset+sha256.Size:]...)
	return plaintext, messageID, nil
}

type observingE2ELeg struct {
	nodeID       string
	connectionID string
	sendErr      error
	incoming     chan *network.Message
	closed       chan struct{}
	closeOnce    sync.Once

	mu             sync.Mutex
	sentPayloads   [][]byte
	cryptoInstalls int
}

type blockingE2ELeg struct {
	*observingE2ELeg
	started      chan struct{}
	canceled     chan struct{}
	startOnce    sync.Once
	canceledOnce sync.Once
}

func newBlockingE2ELeg() *blockingE2ELeg {
	return &blockingE2ELeg{
		observingE2ELeg: newObservingE2ELeg(nil),
		started:         make(chan struct{}),
		canceled:        make(chan struct{}),
	}
}

func (leg *blockingE2ELeg) SendMessage(ctx context.Context, message *network.Message) error {
	leg.mu.Lock()
	leg.sentPayloads = append(leg.sentPayloads, append([]byte(nil), message.Payload...))
	leg.mu.Unlock()
	leg.startOnce.Do(func() { close(leg.started) })
	<-ctx.Done()
	leg.canceledOnce.Do(func() { close(leg.canceled) })
	return ctx.Err()
}

type delayedE2ELeg struct {
	*observingE2ELeg
	delay time.Duration
}

func newDelayedE2ELeg(delay time.Duration) *delayedE2ELeg {
	return &delayedE2ELeg{observingE2ELeg: newObservingE2ELeg(nil), delay: delay}
}

func (leg *delayedE2ELeg) SendMessage(ctx context.Context, message *network.Message) error {
	leg.mu.Lock()
	leg.sentPayloads = append(leg.sentPayloads, append([]byte(nil), message.Payload...))
	leg.mu.Unlock()
	timer := time.NewTimer(leg.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return leg.sendErr
	}
}

func newObservingE2ELeg(sendErr error) *observingE2ELeg {
	return &observingE2ELeg{
		nodeID:       "e2e-test-peer",
		connectionID: "00000000-0000-0000-0000-000000000001",
		sendErr:      sendErr,
		incoming:     make(chan *network.Message, 4),
		closed:       make(chan struct{}),
	}
}

func (leg *observingE2ELeg) Close() error {
	leg.closeOnce.Do(func() { close(leg.closed) })
	return nil
}

func (leg *observingE2ELeg) NextMessage(ctx context.Context) (*network.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-leg.closed:
		return nil, errors.New("leg closed")
	case message := <-leg.incoming:
		return message, nil
	}
}

func (leg *observingE2ELeg) SendMessage(ctx context.Context, message *network.Message) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	leg.mu.Lock()
	leg.sentPayloads = append(leg.sentPayloads, append([]byte(nil), message.Payload...))
	leg.mu.Unlock()
	return leg.sendErr
}

func (leg *observingE2ELeg) SendMessageAsync(ctx context.Context, message *network.Message, callback network.MessageResultCallback) error {
	err := leg.SendMessage(ctx, message)
	if callback != nil {
		callback(network.MessageResult{Success: err == nil, Error: err})
	}
	return err
}

func (leg *observingE2ELeg) NodeId() string       { return leg.nodeID }
func (leg *observingE2ELeg) ConnectionId() string { return leg.connectionID }

func (leg *observingE2ELeg) SetCryptoSuite(network.EncrypSuite) {
	leg.mu.Lock()
	leg.cryptoInstalls++
	leg.mu.Unlock()
}

func (leg *observingE2ELeg) snapshot() ([][]byte, int) {
	leg.mu.Lock()
	defer leg.mu.Unlock()
	payloads := make([][]byte, len(leg.sentPayloads))
	for index := range leg.sentPayloads {
		payloads[index] = append([]byte(nil), leg.sentPayloads[index]...)
	}
	return payloads, leg.cryptoInstalls
}

func newE2ETestMessage(payload []byte) *network.Message {
	return &network.Message{
		Header: &network.Header{
			RouteName:     "/e2e-test",
			NodeId:        "e2e-test-peer",
			NodeIdVersion: 1,
			ConnectionId:  "00000000-0000-0000-0000-000000000001",
		},
		Payload: append([]byte(nil), payload...),
	}
}

func TestTcpStreamBillingObserverReceivesSealedRecord(t *testing.T) {
	sender, receiver := newPipeStreams(t)
	suite := &countingE2ESuite{}
	sender.SetCryptoSuite(suite)
	receiver.SetCryptoSuite(suite)

	observed := make(chan *network.Message, 1)
	if !SetOutboundRecordObserver(sender, func(message *network.Message, messageID []byte) error {
		if len(messageID) == 0 {
			t.Fatal("billing observer received an empty E2E message ID")
		}
		observed <- message
		return nil
	}) {
		t.Fatal("TcpStream rejected the billing record observer")
	}

	message := newE2ETestMessage([]byte("service response"))
	message.Header.BillingSessionID[0] = 1
	message.Header.BillingSequence = 1
	message.Header.BillingBytes = uint64(len(message.Payload))
	sendResult := make(chan error, 1)
	go func() { sendResult <- sender.SendMessage(context.Background(), message) }()

	received, err := receiver.NextMessage(context.Background())
	if err != nil {
		t.Fatalf("receive sealed service response: %v", err)
	}
	if !bytes.Equal(received.Payload, message.Payload) {
		t.Fatalf("received payload = %q, want %q", received.Payload, message.Payload)
	}
	if err := <-sendResult; err != nil {
		t.Fatalf("send sealed service response: %v", err)
	}
	select {
	case record := <-observed:
		if bytes.Equal(record.Payload, message.Payload) {
			t.Fatal("billing observer received plaintext instead of the sealed record")
		}
		if record.Header.BillingSequence != message.Header.BillingSequence {
			t.Fatalf("observed billing sequence = %d, want %d", record.Header.BillingSequence, message.Header.BillingSequence)
		}
	default:
		t.Fatal("billing observer was not called")
	}
}

func TestDualStreamKCPToTCPFailoverSealsOnce(t *testing.T) {
	suite := &countingE2ESuite{}
	kcpLeg := newObservingE2ELeg(errors.New("KCP unavailable"))
	tcpLeg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	t.Cleanup(func() { _ = dual.Close() })

	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatalf("attach KCP leg: %v", err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatalf("attach TCP leg: %v", err)
	}
	dual.SetCryptoSuite(suite)

	plaintext := []byte("seal exactly once before choosing a transport leg")
	message := newE2ETestMessage(plaintext)
	if err := dual.SendMessage(context.Background(), message); err != nil {
		t.Fatalf("KCP -> TCP failover send failed: %v", err)
	}

	sealCalls, _ := suite.counts()
	if sealCalls != 1 {
		t.Fatalf("one logical send must Seal once, got %d calls", sealCalls)
	}
	kcpPayloads, kcpCryptoInstalls := kcpLeg.snapshot()
	tcpPayloads, tcpCryptoInstalls := tcpLeg.snapshot()
	if kcpCryptoInstalls != 0 || tcpCryptoInstalls != 0 {
		t.Fatalf("E2E suite must stay on DualStream, leg installs: KCP=%d TCP=%d", kcpCryptoInstalls, tcpCryptoInstalls)
	}
	if len(kcpPayloads) != 1 || len(tcpPayloads) != 1 {
		t.Fatalf("expected one attempt per leg, got KCP=%d TCP=%d", len(kcpPayloads), len(tcpPayloads))
	}
	if !bytes.Equal(kcpPayloads[0], tcpPayloads[0]) {
		t.Fatal("KCP and TCP did not receive the same immutable E2E record")
	}
	if bytes.Equal(kcpPayloads[0], plaintext) {
		t.Fatal("transport legs received plaintext instead of an E2E record")
	}
	if !bytes.Equal(message.Payload, plaintext) {
		t.Fatal("SendMessage mutated the caller's plaintext message")
	}
	if dual.preferredTransport() != streamTransportTCP {
		t.Fatalf("TCP should become preferred after KCP failure, got %s", dual.preferredTransport())
	}
}

func TestDualStreamSlowKCPHedgesToTCPWithoutClosingKCP(t *testing.T) {
	suite := &countingE2ESuite{}
	kcpLeg := newBlockingE2ELeg()
	tcpLeg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	dual.kcpSendQuality = kcpSendQualityPolicy{
		minimumPayloadBytes:       64 * 1024,
		minimumGoodputBytesPerSec: 1024 * 1024 * 1024,
		startupBudget:             20 * time.Millisecond,
	}
	t.Cleanup(func() { _ = dual.Close() })

	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatalf("attach KCP leg: %v", err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatalf("attach TCP leg: %v", err)
	}
	dual.SetCryptoSuite(suite)
	observedRecords := 0
	dual.SetOutboundRecordObserver(func(_ *network.Message, messageID []byte) error {
		observedRecords++
		if len(messageID) == 0 {
			t.Fatal("billing observer received an empty E2E message ID")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("h"), 64*1024)
	message := newE2ETestMessage(payload)
	message.Header.BillingSequence = 1
	message.Header.BillingBytes = uint64(len(payload))
	message.Header.BillingSessionID[0] = 1
	if err := dual.SendMessage(ctx, message); err != nil {
		t.Fatalf("hedged send: %v", err)
	}
	select {
	case <-kcpLeg.canceled:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("losing KCP send did not observe the internal hedge cancellation")
	}
	if dual.preferredTransport() != streamTransportTCP {
		t.Fatalf("TCP should become preferred after quality hedge, got %s", dual.preferredTransport())
	}
	select {
	case <-kcpLeg.closed:
		t.Fatal("quality demotion closed a live KCP leg")
	default:
	}
	dual.mu.RLock()
	kcpStillAttached := dual.streamLocked(streamTransportKCP) == kcpLeg
	dual.mu.RUnlock()
	if !kcpStillAttached {
		t.Fatal("quality demotion detached the KCP leg")
	}

	if err := dual.SendMessage(ctx, newE2ETestMessage([]byte("stay on TCP"))); err != nil {
		t.Fatalf("preferred TCP send: %v", err)
	}
	kcpPayloads, _ := kcpLeg.snapshot()
	tcpPayloads, _ := tcpLeg.snapshot()
	if len(kcpPayloads) != 1 || len(tcpPayloads) != 2 {
		t.Fatalf("send attempts after demotion: KCP=%d TCP=%d, want 1/2", len(kcpPayloads), len(tcpPayloads))
	}
	if !bytes.Equal(kcpPayloads[0], tcpPayloads[0]) {
		t.Fatal("quality hedge did not reuse the same sealed E2E record")
	}
	if observedRecords != 1 {
		t.Fatalf("quality hedge observed %d billable records, want exactly 1", observedRecords)
	}
	sealCalls, _ := suite.counts()
	if sealCalls != 2 {
		t.Fatalf("logical sends sealed %d times, want 2", sealCalls)
	}
}

func TestKCPGoodputBudgetScalesWithPayload(t *testing.T) {
	policy := defaultKCPSendQualityPolicy()
	if _, enabled := policy.budget(64*1024 - 1); enabled {
		t.Fatal("sub-threshold control payload unexpectedly received a KCP quality budget")
	}
	first, enabled := policy.budget(64 * 1024)
	if !enabled {
		t.Fatal("64 KiB data payload did not receive a KCP quality budget")
	}
	second, enabled := policy.budget(128 * 1024)
	if !enabled {
		t.Fatal("128 KiB data payload did not receive a KCP quality budget")
	}
	if first != 2*time.Second+time.Second/16 {
		t.Fatalf("64 KiB quality budget=%v, want %v", first, 2*time.Second+time.Second/16)
	}
	if second-first != time.Second/16 {
		t.Fatalf("quality budget did not scale at 1 MiB/s: first=%v second=%v", first, second)
	}
}

func TestDualStreamKCPGoodputBudgetDoesNotHedgeSmallMessages(t *testing.T) {
	suite := &countingE2ESuite{}
	kcpLeg := newBlockingE2ELeg()
	tcpLeg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	dual.kcpSendQuality = kcpSendQualityPolicy{
		minimumPayloadBytes:       64 * 1024,
		minimumGoodputBytesPerSec: 1024 * 1024 * 1024,
		startupBudget:             time.Millisecond,
	}
	t.Cleanup(func() { _ = dual.Close() })
	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatal(err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatal(err)
	}
	dual.SetCryptoSuite(suite)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	message := newE2ETestMessage([]byte("small control message"))
	message.Header.RouteName = KeepAliveRoute
	err := dual.SendMessage(ctx, message)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("small message send error=%v, want caller deadline", err)
	}
	select {
	case <-kcpLeg.canceled:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("KCP send did not observe caller cancellation")
	}
	if payloads, _ := tcpLeg.snapshot(); len(payloads) != 0 {
		t.Fatalf("small control message was hedged to TCP %d times", len(payloads))
	}
	if dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("caller cancellation changed preferred leg to %s", dual.preferredTransport())
	}
	select {
	case <-kcpLeg.closed:
		t.Fatal("caller context cancellation closed the KCP leg")
	default:
	}
}

func TestDualStreamKCPGoodputBudgetRespectsEarlierCallerDeadline(t *testing.T) {
	suite := &countingE2ESuite{}
	kcpLeg := newBlockingE2ELeg()
	tcpLeg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	dual.kcpSendQuality = kcpSendQualityPolicy{
		minimumPayloadBytes:       64 * 1024,
		minimumGoodputBytesPerSec: 1024 * 1024 * 1024,
		startupBudget:             200 * time.Millisecond,
	}
	t.Cleanup(func() { _ = dual.Close() })
	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatal(err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatal(err)
	}
	dual.SetCryptoSuite(suite)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := dual.SendMessage(ctx, newE2ETestMessage(bytes.Repeat([]byte("d"), 64*1024)))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("large message send error=%v, want caller deadline", err)
	}
	if payloads, _ := tcpLeg.snapshot(); len(payloads) != 0 {
		t.Fatalf("caller deadline incorrectly started %d TCP hedges", len(payloads))
	}
	if dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("caller deadline changed preferred leg to %s", dual.preferredTransport())
	}
	select {
	case <-kcpLeg.closed:
		t.Fatal("caller deadline closed the healthy KCP leg")
	default:
	}
}

func TestDualStreamKCPGoodputBudgetAllowsShortJitter(t *testing.T) {
	suite := &countingE2ESuite{}
	kcpLeg := newDelayedE2ELeg(20 * time.Millisecond)
	tcpLeg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	dual.kcpSendQuality = kcpSendQualityPolicy{
		minimumPayloadBytes:       64 * 1024,
		minimumGoodputBytesPerSec: 1024 * 1024 * 1024,
		startupBudget:             75 * time.Millisecond,
	}
	t.Cleanup(func() { _ = dual.Close() })
	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatal(err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatal(err)
	}
	dual.SetCryptoSuite(suite)

	if err := dual.SendMessage(context.Background(), newE2ETestMessage(bytes.Repeat([]byte("j"), 64*1024))); err != nil {
		t.Fatal(err)
	}
	if payloads, _ := tcpLeg.snapshot(); len(payloads) != 0 {
		t.Fatalf("short KCP jitter started %d TCP hedges", len(payloads))
	}
	if dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("short KCP jitter changed preferred leg to %s", dual.preferredTransport())
	}
}

func TestDualStreamKCPGoodputBudgetRequiresDeduplicatedE2ERecord(t *testing.T) {
	kcpLeg := newBlockingE2ELeg()
	tcpLeg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	dual.kcpSendQuality = kcpSendQualityPolicy{
		minimumPayloadBytes:       64 * 1024,
		minimumGoodputBytesPerSec: 1024 * 1024 * 1024,
		startupBudget:             time.Millisecond,
	}
	t.Cleanup(func() { _ = dual.Close() })
	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatal(err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := dual.SendMessage(ctx, newE2ETestMessage(bytes.Repeat([]byte("u"), 64*1024)))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unsealed message send error=%v, want caller deadline", err)
	}
	if payloads, _ := tcpLeg.snapshot(); len(payloads) != 0 {
		t.Fatalf("unsealed message was unsafely duplicated over TCP %d times", len(payloads))
	}
	if dual.preferredTransport() != streamTransportKCP {
		t.Fatalf("unsealed message changed preferred leg to %s", dual.preferredTransport())
	}
}

func TestDualStreamKCPGoodputBudgetKeepsTCPPreferredWhenKCPFinishesFirst(t *testing.T) {
	suite := &countingE2ESuite{}
	kcpLeg := newDelayedE2ELeg(25 * time.Millisecond)
	tcpLeg := newBlockingE2ELeg()
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	dual.kcpSendQuality = kcpSendQualityPolicy{
		minimumPayloadBytes:       64 * 1024,
		minimumGoodputBytesPerSec: 1024 * 1024 * 1024,
		startupBudget:             10 * time.Millisecond,
	}
	t.Cleanup(func() { _ = dual.Close() })
	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatal(err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatal(err)
	}
	dual.SetCryptoSuite(suite)

	started := time.Now()
	if err := dual.SendMessage(context.Background(), newE2ETestMessage(bytes.Repeat([]byte("q"), 64*1024))); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("KCP completed after its budget but blocked behind the TCP hedge for %v", elapsed)
	}
	select {
	case <-tcpLeg.canceled:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("blocked TCP loser did not observe internal cancellation")
	}
	if dual.preferredTransport() != streamTransportTCP {
		t.Fatalf("late KCP completion restored preferred leg to %s", dual.preferredTransport())
	}
	kcpPayloads, _ := kcpLeg.snapshot()
	tcpPayloads, _ := tcpLeg.snapshot()
	if len(kcpPayloads) != 1 || len(tcpPayloads) != 1 || !bytes.Equal(kcpPayloads[0], tcpPayloads[0]) {
		t.Fatalf("late-KCP hedge attempts mismatch: KCP=%d TCP=%d", len(kcpPayloads), len(tcpPayloads))
	}
	select {
	case <-tcpLeg.closed:
		t.Fatal("internal hedge cancellation closed the healthy TCP leg")
	default:
	}
}

func TestDualStreamRelayReconnectReusesSealedRecord(t *testing.T) {
	suite := &countingE2ESuite{}
	failedRelayLeg := newObservingE2ELeg(errors.New("entry Relay disappeared"))
	replacementRelayLeg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	t.Cleanup(func() { _ = dual.Close() })

	if err := dual.attach(streamTransportTCP, failedRelayLeg); err != nil {
		t.Fatalf("attach initial Relay leg: %v", err)
	}
	dual.setPersistentReconnectDialer(streamTransportTCP, func(context.Context) (network.Stream, error) {
		return replacementRelayLeg, nil
	})
	dual.SetCryptoSuite(suite)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	plaintext := []byte("reuse this record after Relay migration")
	if err := dual.SendMessage(ctx, newE2ETestMessage(plaintext)); err != nil {
		t.Fatalf("send did not resume on replacement Relay leg: %v", err)
	}

	sealCalls, _ := suite.counts()
	if sealCalls != 1 {
		t.Fatalf("Relay migration must not reseal a logical message, got %d Seal calls", sealCalls)
	}
	failedPayloads, failedCryptoInstalls := failedRelayLeg.snapshot()
	replacementPayloads, replacementCryptoInstalls := replacementRelayLeg.snapshot()
	if failedCryptoInstalls != 0 || replacementCryptoInstalls != 0 {
		t.Fatalf("Relay legs must not own the E2E suite, installs: old=%d replacement=%d", failedCryptoInstalls, replacementCryptoInstalls)
	}
	if len(failedPayloads) != 1 || len(replacementPayloads) != 1 {
		t.Fatalf("expected one old/new Relay attempt, got old=%d replacement=%d", len(failedPayloads), len(replacementPayloads))
	}
	if !bytes.Equal(failedPayloads[0], replacementPayloads[0]) {
		t.Fatal("replacement Relay leg did not reuse the original immutable E2E record")
	}
	if bytes.Equal(replacementPayloads[0], plaintext) {
		t.Fatal("replacement Relay leg received plaintext")
	}
}

func TestDualStreamDeduplicatesE2ERecordAcrossLegs(t *testing.T) {
	suite := &countingE2ESuite{}
	kcpLeg := newObservingE2ELeg(nil)
	tcpLeg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	t.Cleanup(func() { _ = dual.Close() })

	if err := dual.attach(streamTransportKCP, kcpLeg); err != nil {
		t.Fatalf("attach KCP leg: %v", err)
	}
	if err := dual.attach(streamTransportTCP, tcpLeg); err != nil {
		t.Fatalf("attach TCP leg: %v", err)
	}
	dual.SetCryptoSuite(suite)

	plaintext := []byte("deliver this logical record once")
	firstCopy := newE2ETestMessage(nil)
	aad, err := network.CanonicalE2EAAD(firstCopy.Header)
	if err != nil {
		t.Fatal(err)
	}
	record := makeE2ETestRecord(plaintext, e2eTestMessageID(1), aad)
	firstCopy.Payload = append([]byte(nil), record...)
	secondCopy := newE2ETestMessage(record)
	kcpLeg.incoming <- firstCopy
	tcpLeg.incoming <- secondCopy

	firstCtx, firstCancel := context.WithTimeout(context.Background(), time.Second)
	defer firstCancel()
	received, err := dual.NextMessage(firstCtx)
	if err != nil {
		t.Fatalf("receive first E2E record: %v", err)
	}
	if !bytes.Equal(received.Payload, plaintext) {
		t.Fatalf("unexpected plaintext: got %q want %q", received.Payload, plaintext)
	}

	duplicateCtx, duplicateCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer duplicateCancel()
	if duplicate, duplicateErr := dual.NextMessage(duplicateCtx); !errors.Is(duplicateErr, context.DeadlineExceeded) {
		t.Fatalf("duplicate record crossed the session boundary: message=%v err=%v", duplicate, duplicateErr)
	}
}

func TestE2EReplayWindowRejectsRecordAfterWindowAdvance(t *testing.T) {
	var window e2eReplayWindow
	oldest := e2eTestMessageID(1)
	duplicate, err := window.observe(oldest)
	if err != nil || duplicate {
		t.Fatalf("record first observation: duplicate=%v err=%v", duplicate, err)
	}
	for sequence := uint64(2); sequence <= e2eReplayWindowSize+1; sequence++ {
		duplicate, err = window.observe(e2eTestMessageID(sequence))
		if err != nil || duplicate {
			t.Fatalf("advance replay window at sequence %d: duplicate=%v err=%v", sequence, duplicate, err)
		}
	}
	duplicate, err = window.observe(oldest)
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate {
		t.Fatal("historical record was accepted after leaving the replay window")
	}
}

func TestDualStreamRejectsInvalidE2ERecord(t *testing.T) {
	suite := &countingE2ESuite{}
	leg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	t.Cleanup(func() { _ = dual.Close() })

	if err := dual.attach(streamTransportTCP, leg); err != nil {
		t.Fatalf("attach TCP leg: %v", err)
	}
	dual.SetCryptoSuite(suite)
	leg.incoming <- newE2ETestMessage([]byte("not-an-e2e-record"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	message, err := dual.NextMessage(ctx)
	if err == nil {
		t.Fatalf("invalid E2E record was delivered instead of failing closed: %#v", message)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("invalid E2E record was silently dropped instead of returning its authentication error")
	}
}

func TestDualStreamRejectsTamperedAuthenticatedHeader(t *testing.T) {
	suite := &countingE2ESuite{}
	leg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	t.Cleanup(func() { _ = dual.Close() })

	if err := dual.attach(streamTransportTCP, leg); err != nil {
		t.Fatalf("attach TCP leg: %v", err)
	}
	dual.SetCryptoSuite(suite)
	message := newE2ETestMessage(nil)
	aad, err := network.CanonicalE2EAAD(message.Header)
	if err != nil {
		t.Fatal(err)
	}
	message.Payload = makeE2ETestRecord([]byte("protected"), e2eTestMessageID(1), aad)
	message.Header.RouteName = "/tampered-route"
	leg.incoming <- message

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if received, receiveErr := dual.NextMessage(ctx); receiveErr == nil {
		t.Fatalf("tampered authenticated header was delivered: %#v", received)
	}
}

func TestDualStreamRejectsEstablishedSessionDowngrade(t *testing.T) {
	suite := &countingE2ESuite{}
	leg := newObservingE2ELeg(nil)
	dual := newDualStream("e2e-test-peer", "00000000-0000-0000-0000-000000000001")
	t.Cleanup(func() { _ = dual.Close() })

	if err := dual.attach(streamTransportTCP, leg); err != nil {
		t.Fatalf("attach TCP leg: %v", err)
	}
	dual.SetCryptoSuite(suite)
	dual.SetCryptoSuite(nil)

	err := dual.SendMessage(context.Background(), newE2ETestMessage([]byte("must not become plaintext")))
	if err == nil {
		t.Fatal("established E2E session accepted a downgrade to plaintext")
	}
	if payloads, _ := leg.snapshot(); len(payloads) != 0 {
		t.Fatal("downgraded message reached a physical leg")
	}
}
