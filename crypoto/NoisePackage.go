package crypoto

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

const (
	noiseProtocolVersion = byte(2)
	noiseSuiteID         = byte(1)

	noiseHelloMagic     = "BNFSN2H1"
	noiseMessageMagic   = "BNFSN2M1"
	noiseConfirmMagic   = "BNFSN2C1"
	noiseIdentityMagic  = "BNFSIDP2"
	e2eRecordMagic      = "BNFSE2E2"
	e2eRecordHeaderSize = 64
	e2eMessageIDSize    = 44

	noiseRoleInitiator = byte(0)
	noiseRoleResponder = byte(1)
	noiseDirectionI2R  = byte(0)
	noiseDirectionR2I  = byte(1)

	e2eRekeyBytes    = uint64(1 << 30)
	e2eRekeyInterval = time.Hour

	e2eOutboundBindingCacheLimit = 65536
)

var noiseCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

type outboundRecordBinding struct {
	digest [32]byte
	sealed bool
}

type NoiseCrypto struct {
	sendRoot      [32]byte
	recvRoot      [32]byte
	sessionID     [32]byte
	sendDirection byte
	recvDirection byte

	sendMu           sync.Mutex
	sendSequence     uint64
	sendEpoch        uint32
	sendEpochBytes   uint64
	sendEpochStarted time.Time

	outboundBindings     map[string]outboundRecordBinding
	outboundBindingOrder []string
	outboundBindingNext  int
}

type TLSCrypto = NoiseCrypto

func NewTLSCrypto(targetStream network.Stream, nodePrivateKey *ecdh.PrivateKey) (*NoiseCrypto, error) {
	return NewTLSCryptoContext(context.Background(), targetStream, nodePrivateKey)
}

func NewTLSCryptoContext(ctx context.Context, targetStream network.Stream, nodePrivateKey *ecdh.PrivateKey) (*NoiseCrypto, error) {
	return newNoiseCryptoContext(ctx, targetStream, nodePrivateKey, nil)
}

func NewNoiseCryptoContext(ctx context.Context, targetStream network.Stream, nodePrivateKey *ecdh.PrivateKey, initiator bool) (*NoiseCrypto, error) {
	return newNoiseCryptoContext(ctx, targetStream, nodePrivateKey, &initiator)
}

func newNoiseCryptoContext(ctx context.Context, targetStream network.Stream, nodePrivateKey *ecdh.PrivateKey, roleOverride *bool) (*NoiseCrypto, error) {
	if targetStream == nil {
		return nil, errors.New("noise E2E: stream is nil")
	}
	if nodePrivateKey == nil {
		return nil, errors.New("noise E2E: node private key is nil")
	}

	localPublic := nodePrivateKey.PublicKey().Bytes()
	peerPublic, localNodeID, peerNodeID, err := exchangeNoiseHello(ctx, targetStream, localPublic)
	if err != nil {
		return nil, err
	}
	initiator := bytes.Compare([]byte(localNodeID), []byte(peerNodeID)) < 0
	if roleOverride != nil {
		initiator = *roleOverride
	}
	initiatorNodeID, responderNodeID := localNodeID, peerNodeID
	if !initiator {
		initiatorNodeID, responderNodeID = peerNodeID, localNodeID
	}
	prologue := noisePrologue(initiatorNodeID, responderNodeID, targetStream.ConnectionId())
	staticKey, err := deriveNoiseStaticKey(nodePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("noise E2E: derive static key: %w", err)
	}
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseCipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     initiator,
		Prologue:      prologue,
		StaticKeypair: staticKey,
	})
	if err != nil {
		return nil, fmt.Errorf("noise E2E: initialize XX handshake: %w", err)
	}

	sendState, receiveState, err := runNoiseXX(ctx, targetStream, handshake, nodePrivateKey, peerPublic, staticKey.Public, prologue, initiator)
	if err != nil {
		return nil, err
	}
	channelBinding := append([]byte(nil), handshake.ChannelBinding()...)
	sessionID := sha256.Sum256(append([]byte("BNFS/E2E-SESSION/V2"), channelBinding...))
	if err := confirmNoiseKeys(ctx, targetStream, sendState, receiveState, channelBinding, sessionID, initiator); err != nil {
		return nil, err
	}
	sendRoot, err := deriveTrafficRoot(sendState.UnsafeKey(), channelBinding)
	if err != nil {
		return nil, err
	}
	receiveRoot, err := deriveTrafficRoot(receiveState.UnsafeKey(), channelBinding)
	if err != nil {
		return nil, err
	}
	sendDirection, receiveDirection := noiseDirectionI2R, noiseDirectionR2I
	if !initiator {
		sendDirection, receiveDirection = noiseDirectionR2I, noiseDirectionI2R
	}
	logx.Infof("[E2E] Noise_XX_25519_ChaChaPoly_SHA256 V2 established: local=%.16s peer=%.16s session=%x", localNodeID, peerNodeID, sessionID[:8])
	return &NoiseCrypto{
		sendRoot:         sendRoot,
		recvRoot:         receiveRoot,
		sessionID:        sessionID,
		sendDirection:    sendDirection,
		recvDirection:    receiveDirection,
		sendEpoch:        1,
		sendEpochStarted: time.Now(),
		outboundBindings: make(map[string]outboundRecordBinding),
	}, nil
}

func exchangeNoiseHello(ctx context.Context, stream network.Stream, localPublic []byte) (*ecdh.PublicKey, string, string, error) {
	if len(localPublic) != 65 {
		return nil, "", "", errors.New("noise E2E: invalid local P-256 public key")
	}
	payload := make([]byte, 0, len(noiseHelloMagic)+1+len(localPublic))
	payload = append(payload, noiseHelloMagic...)
	payload = append(payload, noiseProtocolVersion)
	payload = append(payload, localPublic...)
	if err := sendNoisePayload(ctx, stream, payload); err != nil {
		return nil, "", "", fmt.Errorf("noise E2E: send V2 hello: %w", err)
	}
	message, err := stream.NextMessage(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("noise E2E: receive V2 hello: %w", err)
	}
	expectedLength := len(noiseHelloMagic) + 1 + 65
	if len(message.Payload) != expectedLength || !bytes.Equal(message.Payload[:len(noiseHelloMagic)], []byte(noiseHelloMagic)) {
		return nil, "", "", errors.New("noise E2E: peer does not support the required V2 handshake")
	}
	if message.Payload[len(noiseHelloMagic)] != noiseProtocolVersion {
		return nil, "", "", fmt.Errorf("noise E2E: unsupported peer version %d", message.Payload[len(noiseHelloMagic)])
	}
	peerPublic, err := ecdh.P256().NewPublicKey(message.Payload[len(noiseHelloMagic)+1:])
	if err != nil {
		return nil, "", "", fmt.Errorf("noise E2E: parse peer identity key: %w", err)
	}
	localNodeID := nodeIDFromPublicBytes(localPublic)
	peerNodeID := nodeIDFromPublicBytes(peerPublic.Bytes())
	if expected := stream.NodeId(); expected != "" && expected != peerNodeID {
		return nil, "", "", fmt.Errorf("noise E2E: peer identity mismatch: expected %.16s received %.16s", expected, peerNodeID)
	}
	if localNodeID == peerNodeID {
		return nil, "", "", errors.New("noise E2E: refusing a session with the local node identity")
	}
	return peerPublic, localNodeID, peerNodeID, nil
}

func runNoiseXX(ctx context.Context, stream network.Stream, handshake *noise.HandshakeState, localIdentity *ecdh.PrivateKey, peerIdentity *ecdh.PublicKey, localStatic, prologue []byte, initiator bool) (*noise.CipherState, *noise.CipherState, error) {
	if initiator {
		message1, _, _, err := handshake.WriteMessage(nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("noise E2E: create XX message 1: %w", err)
		}
		if err := sendNoiseHandshakeMessage(ctx, stream, 1, message1); err != nil {
			return nil, nil, err
		}
		message2, err := receiveNoiseHandshakeMessage(ctx, stream, 2)
		if err != nil {
			return nil, nil, err
		}
		proof, _, _, err := handshake.ReadMessage(nil, message2)
		if err != nil {
			return nil, nil, fmt.Errorf("noise E2E: authenticate XX message 2: %w", err)
		}
		if err := verifyNoiseIdentityProof(peerIdentity, prologue, noiseRoleResponder, handshake.PeerStatic(), proof); err != nil {
			return nil, nil, err
		}
		localProof, err := makeNoiseIdentityProof(localIdentity, prologue, noiseRoleInitiator, localStatic)
		if err != nil {
			return nil, nil, err
		}
		message3, sendState, receiveState, err := handshake.WriteMessage(nil, localProof)
		if err != nil {
			return nil, nil, fmt.Errorf("noise E2E: create XX message 3: %w", err)
		}
		if sendState == nil || receiveState == nil {
			return nil, nil, errors.New("noise E2E: XX handshake did not produce transport keys")
		}
		if err := sendNoiseHandshakeMessage(ctx, stream, 3, message3); err != nil {
			return nil, nil, err
		}
		return sendState, receiveState, nil
	}

	message1, err := receiveNoiseHandshakeMessage(ctx, stream, 1)
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err := handshake.ReadMessage(nil, message1); err != nil {
		return nil, nil, fmt.Errorf("noise E2E: authenticate XX message 1: %w", err)
	}
	localProof, err := makeNoiseIdentityProof(localIdentity, prologue, noiseRoleResponder, localStatic)
	if err != nil {
		return nil, nil, err
	}
	message2, _, _, err := handshake.WriteMessage(nil, localProof)
	if err != nil {
		return nil, nil, fmt.Errorf("noise E2E: create XX message 2: %w", err)
	}
	if err := sendNoiseHandshakeMessage(ctx, stream, 2, message2); err != nil {
		return nil, nil, err
	}
	message3, err := receiveNoiseHandshakeMessage(ctx, stream, 3)
	if err != nil {
		return nil, nil, err
	}
	proof, initiatorToResponder, responderToInitiator, err := handshake.ReadMessage(nil, message3)
	if err != nil {
		return nil, nil, fmt.Errorf("noise E2E: authenticate XX message 3: %w", err)
	}
	if initiatorToResponder == nil || responderToInitiator == nil {
		return nil, nil, errors.New("noise E2E: XX handshake did not produce transport keys")
	}
	if err := verifyNoiseIdentityProof(peerIdentity, prologue, noiseRoleInitiator, handshake.PeerStatic(), proof); err != nil {
		return nil, nil, err
	}
	return responderToInitiator, initiatorToResponder, nil
}

func sendNoiseHandshakeMessage(ctx context.Context, stream network.Stream, sequence byte, body []byte) error {
	payload := make([]byte, 0, len(noiseMessageMagic)+1+len(body))
	payload = append(payload, noiseMessageMagic...)
	payload = append(payload, sequence)
	payload = append(payload, body...)
	if err := sendNoisePayload(ctx, stream, payload); err != nil {
		return fmt.Errorf("noise E2E: send XX message %d: %w", sequence, err)
	}
	return nil
}

func receiveNoiseHandshakeMessage(ctx context.Context, stream network.Stream, sequence byte) ([]byte, error) {
	message, err := stream.NextMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("noise E2E: receive XX message %d: %w", sequence, err)
	}
	headerLength := len(noiseMessageMagic) + 1
	if len(message.Payload) < headerLength || !bytes.Equal(message.Payload[:len(noiseMessageMagic)], []byte(noiseMessageMagic)) || message.Payload[len(noiseMessageMagic)] != sequence {
		return nil, fmt.Errorf("noise E2E: invalid XX message %d", sequence)
	}
	return message.Payload[headerLength:], nil
}

func confirmNoiseKeys(ctx context.Context, stream network.Stream, sendState, receiveState *noise.CipherState, channelBinding []byte, sessionID [32]byte, initiator bool) error {
	aad := append([]byte("BNFS/E2E-CONFIRM-AAD/V2"), channelBinding...)
	ready := append([]byte("BNFS/E2E-READY/V2"), sessionID[:]...)
	ack := append([]byte("BNFS/E2E-ACK/V2"), sessionID[:]...)
	if initiator {
		ciphertext, err := receiveNoiseConfirmation(ctx, stream, 1)
		if err != nil {
			return err
		}
		plaintext, err := receiveState.Decrypt(nil, aad, ciphertext)
		if err != nil || !bytes.Equal(plaintext, ready) {
			return errors.New("noise E2E: responder key confirmation failed")
		}
		ciphertext, err = sendState.Encrypt(nil, aad, ack)
		if err != nil {
			return fmt.Errorf("noise E2E: encrypt initiator confirmation: %w", err)
		}
		return sendNoiseConfirmation(ctx, stream, 2, ciphertext)
	}
	ciphertext, err := sendState.Encrypt(nil, aad, ready)
	if err != nil {
		return fmt.Errorf("noise E2E: encrypt responder confirmation: %w", err)
	}
	if err := sendNoiseConfirmation(ctx, stream, 1, ciphertext); err != nil {
		return err
	}
	ciphertext, err = receiveNoiseConfirmation(ctx, stream, 2)
	if err != nil {
		return err
	}
	plaintext, err := receiveState.Decrypt(nil, aad, ciphertext)
	if err != nil || !bytes.Equal(plaintext, ack) {
		return errors.New("noise E2E: initiator key confirmation failed")
	}
	return nil
}

func sendNoiseConfirmation(ctx context.Context, stream network.Stream, kind byte, ciphertext []byte) error {
	payload := make([]byte, 0, len(noiseConfirmMagic)+1+len(ciphertext))
	payload = append(payload, noiseConfirmMagic...)
	payload = append(payload, kind)
	payload = append(payload, ciphertext...)
	if err := sendNoisePayload(ctx, stream, payload); err != nil {
		return fmt.Errorf("noise E2E: send key confirmation %d: %w", kind, err)
	}
	return nil
}

func receiveNoiseConfirmation(ctx context.Context, stream network.Stream, kind byte) ([]byte, error) {
	message, err := stream.NextMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("noise E2E: receive key confirmation %d: %w", kind, err)
	}
	headerLength := len(noiseConfirmMagic) + 1
	if len(message.Payload) < headerLength || !bytes.Equal(message.Payload[:len(noiseConfirmMagic)], []byte(noiseConfirmMagic)) || message.Payload[len(noiseConfirmMagic)] != kind {
		return nil, fmt.Errorf("noise E2E: invalid key confirmation %d", kind)
	}
	return message.Payload[headerLength:], nil
}

func sendNoisePayload(ctx context.Context, stream network.Stream, payload []byte) error {
	return stream.SendMessage(ctx, &network.Message{
		Header: &network.Header{
			NodeId:        stream.NodeId(),
			NodeIdVersion: 1,
			ConnectionId:  stream.ConnectionId(),
		},
		Payload: payload,
	})
}

func deriveNoiseStaticKey(identity *ecdh.PrivateKey) (noise.DHKey, error) {
	private, err := hkdf.Key(sha256.New, identity.Bytes(), nil, "BNFS/E2E/X25519-STATIC/V2", 32)
	if err != nil {
		return noise.DHKey{}, err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{Private: private, Public: public}, nil
}

func makeNoiseIdentityProof(identity *ecdh.PrivateKey, prologue []byte, role byte, staticPublic []byte) ([]byte, error) {
	private, err := ecdsaPrivateKey(identity)
	if err != nil {
		return nil, err
	}
	digest := noiseIdentityDigest(prologue, role, staticPublic)
	signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
	if err != nil {
		return nil, fmt.Errorf("noise E2E: sign identity proof: %w", err)
	}
	proof := make([]byte, 0, len(noiseIdentityMagic)+2+len(signature))
	proof = append(proof, noiseIdentityMagic...)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(signature)))
	proof = append(proof, size[:]...)
	proof = append(proof, signature...)
	return proof, nil
}

func verifyNoiseIdentityProof(identity *ecdh.PublicKey, prologue []byte, role byte, staticPublic, proof []byte) error {
	headerLength := len(noiseIdentityMagic) + 2
	if len(proof) < headerLength || !bytes.Equal(proof[:len(noiseIdentityMagic)], []byte(noiseIdentityMagic)) {
		return errors.New("noise E2E: invalid identity proof")
	}
	signatureLength := int(binary.BigEndian.Uint16(proof[len(noiseIdentityMagic):headerLength]))
	if signatureLength == 0 || len(proof) != headerLength+signatureLength {
		return errors.New("noise E2E: invalid identity proof length")
	}
	public, err := ecdsaPublicKey(identity)
	if err != nil {
		return err
	}
	digest := noiseIdentityDigest(prologue, role, staticPublic)
	if !ecdsa.VerifyASN1(public, digest[:], proof[headerLength:]) {
		return errors.New("noise E2E: peer identity proof verification failed")
	}
	return nil
}

func noiseIdentityDigest(prologue []byte, role byte, staticPublic []byte) [32]byte {
	data := make([]byte, 0, len(prologue)+len(staticPublic)+32)
	data = append(data, "BNFS/E2E-IDENTITY-PROOF/V2"...)
	data = append(data, prologue...)
	data = append(data, role)
	data = append(data, staticPublic...)
	return sha256.Sum256(data)
}

func ecdsaPrivateKey(identity *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	public, err := ecdsaPublicKey(identity.PublicKey())
	if err != nil {
		return nil, err
	}
	private := &ecdsa.PrivateKey{PublicKey: *public, D: new(big.Int).SetBytes(identity.Bytes())}
	if private.D.Sign() <= 0 || private.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, errors.New("noise E2E: invalid P-256 identity scalar")
	}
	return private, nil
}

func ecdsaPublicKey(identity *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), identity.Bytes())
	if x == nil || y == nil {
		return nil, errors.New("noise E2E: invalid P-256 identity public key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func nodeIDFromPublicBytes(public []byte) string {
	encoded := hex.EncodeToString(public)
	digest := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(digest[:])
}

func noisePrologue(initiatorNodeID, responderNodeID, logicalConnectionID string) []byte {
	fields := []string{"BNFS", "2", initiatorNodeID, responderNodeID, logicalConnectionID}
	data := make([]byte, 0, 256)
	data = append(data, "BNFS/E2E-PROLOGUE/V2"...)
	var size [2]byte
	for _, field := range fields {
		binary.BigEndian.PutUint16(size[:], uint16(len(field)))
		data = append(data, size[:]...)
		data = append(data, field...)
	}
	return data
}

func deriveTrafficRoot(key [32]byte, channelBinding []byte) ([32]byte, error) {
	derived, err := hkdf.Key(sha256.New, key[:], channelBinding, "BNFS/E2E-TRAFFIC-ROOT/V2", 32)
	if err != nil {
		return [32]byte{}, fmt.Errorf("noise E2E: derive traffic root: %w", err)
	}
	var root [32]byte
	copy(root[:], derived)
	return root, nil
}

func (t *NoiseCrypto) Encrypt(payload []byte) ([]byte, error) {
	record, _, err := t.EncryptWithMessageIDAndAAD(payload, nil, nil)
	return record, err
}

func (t *NoiseCrypto) Decrypt(record []byte) ([]byte, error) {
	plaintext, _, _, err := t.DecryptWithMessageIDAndAAD(record, nil)
	return plaintext, err
}

func (t *NoiseCrypto) NewMessageID() []byte {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	return t.newMessageIDLocked(time.Now())
}

func (t *NoiseCrypto) EncryptWithMessageID(payload, messageID []byte) ([]byte, []byte, error) {
	return t.EncryptWithMessageIDAndAAD(payload, nil, messageID)
}

func (t *NoiseCrypto) DecryptWithMessageID(record []byte) ([]byte, []byte, bool, error) {
	return t.DecryptWithMessageIDAndAAD(record, nil)
}

func (t *NoiseCrypto) EncryptWithMessageIDAndAAD(payload, externalAAD, messageID []byte) ([]byte, []byte, error) {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if len(messageID) == 0 {
		messageID = t.newMessageIDLocked(time.Now())
		if len(messageID) == 0 {
			return nil, nil, errors.New("noise E2E: outbound message sequence exhausted")
		}
	} else if len(messageID) != e2eMessageIDSize {
		return nil, nil, errors.New("noise E2E: invalid outbound message ID length")
	} else {
		messageID = append([]byte(nil), messageID...)
	}
	if subtle.ConstantTimeCompare(messageID[:32], t.sessionID[:]) != 1 {
		return nil, nil, errors.New("noise E2E: outbound message belongs to another session")
	}
	epoch := binary.BigEndian.Uint32(messageID[32:36])
	sequence := binary.BigEndian.Uint64(messageID[36:44])
	if epoch == 0 || sequence == 0 || sequence > noise.MaxNonce {
		return nil, nil, errors.New("noise E2E: invalid outbound epoch or sequence")
	}
	bindingKey := string(messageID)
	binding, issued := t.outboundBindings[bindingKey]
	if !issued {
		return nil, nil, errors.New("noise E2E: outbound message ID is forged or expired")
	}
	bindingDigest := outboundRecordBindingDigest(payload, externalAAD)
	if binding.sealed && subtle.ConstantTimeCompare(binding.digest[:], bindingDigest[:]) != 1 {
		return nil, nil, errors.New("noise E2E: outbound message ID is already bound to different content")
	}
	header := t.recordHeader(t.sendDirection, epoch, sequence, len(payload))
	aad := appendRecordAAD(header, externalAAD)
	key, err := deriveEpochKey(t.sendRoot, t.sendDirection, epoch)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := noiseCipherSuite.Cipher(key).Encrypt(nil, sequence, aad, payload)
	record := make([]byte, 0, len(header)+len(ciphertext))
	record = append(record, header...)
	record = append(record, ciphertext...)
	if !binding.sealed {
		binding.digest = bindingDigest
		binding.sealed = true
		t.outboundBindings[bindingKey] = binding
		t.sendEpochBytes += uint64(len(payload))
	}
	return record, messageID, nil
}

func (t *NoiseCrypto) DecryptWithMessageIDAndAAD(record, externalAAD []byte) ([]byte, []byte, bool, error) {
	if len(record) < e2eRecordHeaderSize+16 {
		return nil, nil, false, errors.New("noise E2E: record is too short")
	}
	header := record[:e2eRecordHeaderSize]
	if !bytes.Equal(header[:8], []byte(e2eRecordMagic)) || header[8] != noiseProtocolVersion || header[9] != noiseSuiteID || header[11] != 0 {
		return nil, nil, false, errors.New("noise E2E: unsupported record header")
	}
	if header[10] != t.recvDirection {
		return nil, nil, false, errors.New("noise E2E: reflected or wrong-direction record")
	}
	epoch := binary.BigEndian.Uint32(header[12:16])
	sequence := binary.BigEndian.Uint64(header[16:24])
	if epoch == 0 || sequence == 0 || sequence > noise.MaxNonce {
		return nil, nil, false, errors.New("noise E2E: invalid record epoch or sequence")
	}
	if subtle.ConstantTimeCompare(header[24:56], t.sessionID[:]) != 1 {
		return nil, nil, false, errors.New("noise E2E: record belongs to another session")
	}
	plaintextLength := binary.BigEndian.Uint64(header[56:64])
	if plaintextLength > uint64(len(record)) || plaintextLength+e2eRecordHeaderSize+16 != uint64(len(record)) {
		return nil, nil, false, errors.New("noise E2E: record length mismatch")
	}
	key, err := deriveEpochKey(t.recvRoot, t.recvDirection, epoch)
	if err != nil {
		return nil, nil, false, err
	}
	aad := appendRecordAAD(header, externalAAD)
	plaintext, err := noiseCipherSuite.Cipher(key).Decrypt(nil, sequence, aad, record[e2eRecordHeaderSize:])
	if err != nil {
		return nil, nil, false, fmt.Errorf("noise E2E: record authentication failed: %w", err)
	}
	messageID := make([]byte, e2eMessageIDSize)
	copy(messageID[:32], t.sessionID[:])
	binary.BigEndian.PutUint32(messageID[32:36], epoch)
	binary.BigEndian.PutUint64(messageID[36:44], sequence)
	return plaintext, messageID, true, nil
}

// E2ERecordMetadata 是 Relay 无需解密即可读取的稳定记录元数据。它只解析公开头部；
// 记录的真实性仍由通信端的 AEAD 校验和随后形成的 NAT/Relay 双签凭证共同保证。
type E2ERecordMetadata struct {
	MessageID      []byte
	PlaintextBytes uint64
	Direction      byte
}

func InspectE2ERecord(record []byte) (E2ERecordMetadata, error) {
	if len(record) < e2eRecordHeaderSize+16 {
		return E2ERecordMetadata{}, errors.New("noise E2E: record is too short")
	}
	header := record[:e2eRecordHeaderSize]
	if !bytes.Equal(header[:8], []byte(e2eRecordMagic)) ||
		header[8] != noiseProtocolVersion || header[9] != noiseSuiteID || header[11] != 0 {
		return E2ERecordMetadata{}, errors.New("noise E2E: unsupported record header")
	}
	epoch := binary.BigEndian.Uint32(header[12:16])
	sequence := binary.BigEndian.Uint64(header[16:24])
	if epoch == 0 || sequence == 0 || sequence > noise.MaxNonce {
		return E2ERecordMetadata{}, errors.New("noise E2E: invalid record epoch or sequence")
	}
	plaintextLength := binary.BigEndian.Uint64(header[56:64])
	if plaintextLength > uint64(len(record)) || plaintextLength+e2eRecordHeaderSize+16 != uint64(len(record)) {
		return E2ERecordMetadata{}, errors.New("noise E2E: record length mismatch")
	}
	messageID := make([]byte, e2eMessageIDSize)
	copy(messageID[:32], header[24:56])
	binary.BigEndian.PutUint32(messageID[32:36], epoch)
	binary.BigEndian.PutUint64(messageID[36:44], sequence)
	return E2ERecordMetadata{
		MessageID:      messageID,
		PlaintextBytes: plaintextLength,
		Direction:      header[10],
	}, nil
}

func (t *NoiseCrypto) newMessageIDLocked(now time.Time) []byte {
	if t.sendEpoch == 0 {
		t.sendEpoch = 1
		t.sendEpochStarted = now
	}
	if t.sendEpochBytes >= e2eRekeyBytes || now.Sub(t.sendEpochStarted) >= e2eRekeyInterval {
		if t.sendEpoch == ^uint32(0) {
			return nil
		}
		t.sendEpoch++
		t.sendEpochBytes = 0
		t.sendEpochStarted = now
	}
	if t.sendSequence >= noise.MaxNonce {
		return nil
	}
	t.sendSequence++
	messageID := make([]byte, e2eMessageIDSize)
	copy(messageID[:32], t.sessionID[:])
	binary.BigEndian.PutUint32(messageID[32:36], t.sendEpoch)
	binary.BigEndian.PutUint64(messageID[36:44], t.sendSequence)
	t.rememberOutboundMessageIDLocked(messageID)
	return messageID
}

func (t *NoiseCrypto) rememberOutboundMessageIDLocked(messageID []byte) {
	if t.outboundBindings == nil {
		t.outboundBindings = make(map[string]outboundRecordBinding)
	}
	key := string(messageID)
	if _, exists := t.outboundBindings[key]; exists {
		return
	}
	if len(t.outboundBindingOrder) < e2eOutboundBindingCacheLimit {
		t.outboundBindingOrder = append(t.outboundBindingOrder, key)
	} else {
		expired := t.outboundBindingOrder[t.outboundBindingNext]
		delete(t.outboundBindings, expired)
		t.outboundBindingOrder[t.outboundBindingNext] = key
		t.outboundBindingNext = (t.outboundBindingNext + 1) % e2eOutboundBindingCacheLimit
	}
	t.outboundBindings[key] = outboundRecordBinding{}
}

func outboundRecordBindingDigest(payload, externalAAD []byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("BNFS/E2E-OUTBOUND-BINDING/V2"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(payload)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(payload)
	binary.BigEndian.PutUint64(size[:], uint64(len(externalAAD)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(externalAAD)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func (t *NoiseCrypto) recordHeader(direction byte, epoch uint32, sequence uint64, plaintextLength int) []byte {
	header := make([]byte, e2eRecordHeaderSize)
	copy(header[:8], e2eRecordMagic)
	header[8] = noiseProtocolVersion
	header[9] = noiseSuiteID
	header[10] = direction
	binary.BigEndian.PutUint32(header[12:16], epoch)
	binary.BigEndian.PutUint64(header[16:24], sequence)
	copy(header[24:56], t.sessionID[:])
	binary.BigEndian.PutUint64(header[56:64], uint64(plaintextLength))
	return header
}

func appendRecordAAD(header, externalAAD []byte) []byte {
	aad := make([]byte, 0, len(header)+4+len(externalAAD))
	aad = append(aad, header...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(externalAAD)))
	aad = append(aad, size[:]...)
	aad = append(aad, externalAAD...)
	return aad
}

func deriveEpochKey(root [32]byte, direction byte, epoch uint32) ([32]byte, error) {
	info := make([]byte, 0, 32)
	info = append(info, "BNFS/E2E-DATA-EPOCH/V2"...)
	info = append(info, direction)
	var epochBytes [4]byte
	binary.BigEndian.PutUint32(epochBytes[:], epoch)
	info = append(info, epochBytes[:]...)
	derived, err := hkdf.Expand(sha256.New, root[:], string(info), 32)
	if err != nil {
		return [32]byte{}, fmt.Errorf("noise E2E: derive epoch key: %w", err)
	}
	var key [32]byte
	copy(key[:], derived)
	return key, nil
}
