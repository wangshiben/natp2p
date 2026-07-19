package crypoto

import (
	"bnfs_p2p/network"
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type noiseMemoryStream struct {
	nodeID       string
	connectionID string
	inbox        <-chan *network.Message
	outbox       chan<- *network.Message
}

func (stream *noiseMemoryStream) Close() error { return nil }

func (stream *noiseMemoryStream) NextMessage(ctx context.Context) (*network.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case message := <-stream.inbox:
		return cloneNoiseTestMessage(message), nil
	}
}

func (stream *noiseMemoryStream) SendMessage(ctx context.Context, message *network.Message) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case stream.outbox <- cloneNoiseTestMessage(message):
		return nil
	}
}

func (stream *noiseMemoryStream) SendMessageAsync(ctx context.Context, message *network.Message, callback network.MessageResultCallback) error {
	err := stream.SendMessage(ctx, message)
	if callback != nil {
		callback(network.MessageResult{Success: err == nil, Error: err})
	}
	return err
}

func (stream *noiseMemoryStream) NodeId() string                     { return stream.nodeID }
func (stream *noiseMemoryStream) ConnectionId() string               { return stream.connectionID }
func (stream *noiseMemoryStream) SetCryptoSuite(network.EncrypSuite) {}

func cloneNoiseTestMessage(message *network.Message) *network.Message {
	if message == nil {
		return nil
	}
	cloned := &network.Message{Payload: append([]byte(nil), message.Payload...)}
	if message.Header != nil {
		header := *message.Header
		header.OriginData = append([]byte(nil), message.Header.OriginData...)
		cloned.Header = &header
	}
	return cloned
}

func noiseTestSessions(t *testing.T) (*TLSCrypto, *TLSCrypto) {
	t.Helper()
	initiatorKey, err := MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	responderKey, err := MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	initiatorInbox := make(chan *network.Message, 16)
	responderInbox := make(chan *network.Message, 16)
	connectionID := "00000000-0000-0000-0000-000000000101"
	initiatorStream := &noiseMemoryStream{
		nodeID:       nodeIDFromPublicBytes(responderKey.PublicKey().Bytes()),
		connectionID: connectionID,
		inbox:        initiatorInbox,
		outbox:       responderInbox,
	}
	responderStream := &noiseMemoryStream{
		nodeID:       nodeIDFromPublicBytes(initiatorKey.PublicKey().Bytes()),
		connectionID: connectionID,
		inbox:        responderInbox,
		outbox:       initiatorInbox,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var initiatorSession *TLSCrypto
	var responderSession *TLSCrypto
	var initiatorErr error
	var responderErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		initiatorSession, initiatorErr = NewNoiseCryptoContext(ctx, initiatorStream, initiatorKey, true)
	}()
	go func() {
		defer wait.Done()
		responderSession, responderErr = NewNoiseCryptoContext(ctx, responderStream, responderKey, false)
	}()
	wait.Wait()
	if initiatorErr != nil || responderErr != nil {
		t.Fatalf("Noise handshake failed: initiator=%v responder=%v", initiatorErr, responderErr)
	}
	return initiatorSession, responderSession
}

func TestNoiseXXRecordRoundTripAndStableRetry(t *testing.T) {
	initiator, responder := noiseTestSessions(t)
	payload := []byte("single-seal payload")
	aad := []byte("canonical billing header")
	messageID := initiator.NewMessageID()
	record1, returnedID, err := initiator.EncryptWithMessageIDAndAAD(payload, aad, messageID)
	if err != nil {
		t.Fatal(err)
	}
	record2, _, err := initiator.EncryptWithMessageIDAndAAD(payload, aad, messageID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(messageID, returnedID) || !bytes.Equal(record1, record2) {
		t.Fatal("same logical record did not produce identical serialized bytes")
	}
	plaintext, receivedID, authenticated, err := responder.DecryptWithMessageIDAndAAD(record1, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !authenticated || !bytes.Equal(plaintext, payload) || !bytes.Equal(receivedID, messageID) {
		t.Fatal("authenticated E2E record did not round-trip")
	}
}

func TestNoiseXXOutboundMessageIDBindsContentAndExpires(t *testing.T) {
	initiator, _ := noiseTestSessions(t)
	payload := []byte("immutable record payload")
	aad := []byte("immutable record AAD")
	messageID := initiator.NewMessageID()
	record, _, err := initiator.EncryptWithMessageIDAndAAD(payload, aad, messageID)
	if err != nil {
		t.Fatal(err)
	}
	retry, _, err := initiator.EncryptWithMessageIDAndAAD(payload, aad, messageID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record, retry) {
		t.Fatal("same message ID and content did not reproduce the immutable record")
	}
	if _, _, err := initiator.EncryptWithMessageIDAndAAD([]byte("different payload"), aad, messageID); err == nil {
		t.Fatal("message ID was reused with a different payload")
	}
	if _, _, err := initiator.EncryptWithMessageIDAndAAD(payload, []byte("different AAD"), messageID); err == nil {
		t.Fatal("message ID was reused with different AAD")
	}

	initiator.sendMu.Lock()
	accountedBytes := initiator.sendEpochBytes
	initiator.sendMu.Unlock()
	if accountedBytes != uint64(len(payload)) {
		t.Fatalf("stable retries must account plaintext once, got %d bytes", accountedBytes)
	}

	forgedID := append([]byte(nil), messageID...)
	forgedID[len(forgedID)-1] ^= 0x80
	if _, _, err := initiator.EncryptWithMessageIDAndAAD(payload, aad, forgedID); err == nil {
		t.Fatal("unissued message ID was accepted")
	}
	if _, _, err := initiator.EncryptWithMessageIDAndAAD(payload, aad, messageID[:len(messageID)-1]); err == nil {
		t.Fatal("malformed message ID silently allocated a new sequence")
	}

	for index := 0; index < e2eOutboundBindingCacheLimit; index++ {
		if issued := initiator.NewMessageID(); len(issued) != e2eMessageIDSize {
			t.Fatal("failed to issue message ID while exercising the bounded cache")
		}
	}
	if _, _, err := initiator.EncryptWithMessageIDAndAAD(payload, aad, messageID); err == nil {
		t.Fatal("expired message ID was accepted after binding cache eviction")
	}
}

func TestNoiseXXRecordRejectsTamperingAndWrongAAD(t *testing.T) {
	initiator, responder := noiseTestSessions(t)
	record, _, err := initiator.EncryptWithMessageIDAndAAD([]byte("protected"), []byte("aad-1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := responder.DecryptWithMessageIDAndAAD(record, []byte("aad-2")); err == nil {
		t.Fatal("wrong AAD was accepted")
	}
	tampered := append([]byte(nil), record...)
	tampered[len(tampered)-1] ^= 0x80
	if _, _, _, err := responder.DecryptWithMessageIDAndAAD(tampered, []byte("aad-1")); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	if _, _, _, err := initiator.DecryptWithMessageIDAndAAD(record, []byte("aad-1")); err == nil {
		t.Fatal("reflected record was accepted")
	}
}

func TestNoiseXXHandshakeRejectsUnexpectedIdentity(t *testing.T) {
	localKey, err := MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := MakeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	inbox := make(chan *network.Message, 1)
	outbox := make(chan *network.Message, 1)
	stream := &noiseMemoryStream{
		nodeID:       "unexpected-node-id",
		connectionID: "00000000-0000-0000-0000-000000000102",
		inbox:        inbox,
		outbox:       outbox,
	}
	hello := append([]byte(noiseHelloMagic), noiseProtocolVersion)
	hello = append(hello, peerKey.PublicKey().Bytes()...)
	inbox <- &network.Message{Header: &network.Header{}, Payload: hello}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = NewNoiseCryptoContext(ctx, stream, localKey, true)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected identity was not rejected immediately: %v", err)
	}
}
