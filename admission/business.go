package admission

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	BusinessAdmissionVersion = 2
	BusinessAdmissionTTL     = 15 * time.Second
	BusinessAdmissionMaxTTL  = 30 * time.Second
	BusinessAdmissionMaxSize = 16 << 10
)

var (
	ErrBusinessAdmissionRequired = errors.New("business admission v2 is required")
	ErrBusinessAdmissionInvalid  = errors.New("business admission envelope is invalid")
	ErrBusinessAdmissionExpired  = errors.New("business admission proof is expired")
	ErrBusinessAdmissionReplay   = errors.New("business admission proof replay rejected")
)

// BusinessAdmissionEnvelopeV2 is the signed source proof carried in an
// ordinary business routing hello. It is deliberately independent of the
// transport framing so the same bytes survive TCP/KCP and relay bridging.
type BusinessAdmissionEnvelopeV2 struct {
	Version              int                        `json:"version"`
	SourceNodeID         string                     `json:"source_node_id"`
	SourcePublicKey      string                     `json:"source_public_key"`
	SourceCert           SignedCert                 `json:"source_cert"`
	SourceCertDigest     string                     `json:"source_cert_digest"`
	TargetNodeID         string                     `json:"target_node_id"`
	ConnectionID         string                     `json:"connection_id"`
	LegSessionID         string                     `json:"leg_session_id"`
	EntryRelayID         string                     `json:"entry_relay_id"`
	IssuedAt             int64                      `json:"issued_at"`
	ExpiresAt            int64                      `json:"expires_at"`
	Nonce                string                     `json:"nonce"`
	KnownRevocationEpoch uint64                     `json:"known_revocation_epoch,omitempty"`
	SourceSignature      string                     `json:"source_signature"`
	ForwardAttestation   *RelayForwardAttestationV1 `json:"forward_attestation,omitempty"`
}

type RelayForwardAttestationV1 struct {
	Version           int        `json:"version"`
	SourceProofDigest string     `json:"source_proof_digest"`
	EntryRelayID      string     `json:"entry_relay_id"`
	RelayNodeID       string     `json:"relay_node_id"`
	TargetNodeID      string     `json:"target_node_id"`
	ConnectionID      string     `json:"connection_id"`
	LegSessionID      string     `json:"leg_session_id"`
	VerifiedAt        int64      `json:"verified_at"`
	ExpiresAt         int64      `json:"expires_at"`
	RelayCert         SignedCert `json:"relay_cert"`
	RelayCertDigest   string     `json:"relay_cert_digest"`
	Signature         string     `json:"signature"`
}

type BusinessAdmissionDecision struct {
	SourceNodeID    string
	SourcePublicKey string
	ProofDigest     string
	Envelope        *BusinessAdmissionEnvelopeV2
}

func (envelope *BusinessAdmissionEnvelopeV2) signingBytes() ([]byte, error) {
	if envelope == nil {
		return nil, ErrBusinessAdmissionInvalid
	}
	var encoded []byte
	appendField := func(value string) error {
		if len(value) > 4096 {
			return fmt.Errorf("%w: field too long", ErrBusinessAdmissionInvalid)
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		encoded = append(encoded, length[:]...)
		encoded = append(encoded, value...)
		return nil
	}
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], uint32(envelope.Version))
	encoded = append(encoded, []byte("BNFS/BUSINESS-ADMISSION/V2\x00")...)
	encoded = append(encoded, version[:]...)
	for _, value := range []string{
		envelope.SourceNodeID, envelope.SourcePublicKey, envelope.SourceCertDigest,
		envelope.TargetNodeID, envelope.ConnectionID, envelope.LegSessionID,
		envelope.EntryRelayID, envelope.Nonce,
	} {
		if err := appendField(value); err != nil {
			return nil, err
		}
	}
	var number [8]byte
	for _, value := range []int64{envelope.IssuedAt, envelope.ExpiresAt} {
		binary.BigEndian.PutUint64(number[:], uint64(value))
		encoded = append(encoded, number[:]...)
	}
	binary.BigEndian.PutUint64(number[:], envelope.KnownRevocationEpoch)
	encoded = append(encoded, number[:]...)
	return encoded, nil
}

func (envelope *BusinessAdmissionEnvelopeV2) digest() ([]byte, error) {
	bytes, err := envelope.signingBytes()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(bytes)
	return digest[:], nil
}

func NewBusinessAdmissionEnvelope(identityPrivateKey *ecdh.PrivateKey, cert *SignedCert, targetNodeID, connectionID, legSessionID, entryRelayID string, knownEpoch uint64, now time.Time) (*BusinessAdmissionEnvelopeV2, error) {
	if identityPrivateKey == nil || cert == nil {
		return nil, ErrBusinessAdmissionInvalid
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nodePublicKey := hex.EncodeToString(identityPrivateKey.PublicKey().Bytes())
	if cert.Cert.SubjectPubKey != nodePublicKey || cert.Cert.Role != RoleClient {
		return nil, fmt.Errorf("%w: source certificate is not bound to a client identity", ErrBusinessAdmissionInvalid)
	}
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	certBytes, err := json.Marshal(cert.Cert)
	if err != nil {
		return nil, err
	}
	certDigest := sha256.Sum256(certBytes)
	envelope := &BusinessAdmissionEnvelopeV2{
		Version: BusinessAdmissionVersion, SourceNodeID: NodeIDFromPubKeyHex(nodePublicKey),
		SourcePublicKey: nodePublicKey, SourceCert: *cert,
		SourceCertDigest: hex.EncodeToString(certDigest[:]), TargetNodeID: targetNodeID,
		ConnectionID: connectionID, LegSessionID: legSessionID, EntryRelayID: entryRelayID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(BusinessAdmissionTTL).Unix(), Nonce: nonce,
		KnownRevocationEpoch: knownEpoch,
	}
	digest, err := envelope.digest()
	if err != nil {
		return nil, err
	}
	ecdsaKey, err := ecdhToECDSA(identityPrivateKey)
	if err != nil {
		return nil, err
	}
	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, digest)
	if err != nil {
		return nil, err
	}
	envelope.SourceSignature = base64.RawURLEncoding.EncodeToString(signature)
	return envelope, nil
}

func (envelope *BusinessAdmissionEnvelopeV2) Marshal() ([]byte, error) {
	if envelope == nil || envelope.Version != BusinessAdmissionVersion {
		return nil, ErrBusinessAdmissionInvalid
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if len(encoded) > BusinessAdmissionMaxSize {
		return nil, fmt.Errorf("%w: envelope exceeds %d bytes", ErrBusinessAdmissionInvalid, BusinessAdmissionMaxSize)
	}
	return encoded, nil
}

func AddRelayForwardAttestation(
	envelope *BusinessAdmissionEnvelopeV2,
	relayPrivateKey *ecdh.PrivateKey,
	relayCertificate *SignedCert,
	now time.Time,
) error {
	if envelope == nil || relayPrivateKey == nil || relayCertificate == nil || relayCertificate.Cert.Role != RoleRelay {
		return ErrBusinessAdmissionInvalid
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	relayPublicKey := hex.EncodeToString(relayPrivateKey.PublicKey().Bytes())
	if relayCertificate.Cert.SubjectPubKey != relayPublicKey {
		return fmt.Errorf("%w: relay certificate identity mismatch", ErrBusinessAdmissionInvalid)
	}
	proofDigest, err := envelope.proofDigest()
	if err != nil {
		return err
	}
	certificateBytes, err := json.Marshal(relayCertificate)
	if err != nil {
		return err
	}
	certificateDigest := sha256.Sum256(certificateBytes)
	attestation := &RelayForwardAttestationV1{
		Version: 1, SourceProofDigest: proofDigest, EntryRelayID: envelope.EntryRelayID,
		RelayNodeID: relayCertificate.Cert.SubjectNodeID, TargetNodeID: envelope.TargetNodeID,
		ConnectionID: envelope.ConnectionID, LegSessionID: envelope.LegSessionID,
		VerifiedAt: now.Unix(), ExpiresAt: minInt64(envelope.ExpiresAt, now.Add(BusinessAdmissionTTL).Unix()),
		RelayCert: *relayCertificate, RelayCertDigest: hex.EncodeToString(certificateDigest[:]),
	}
	canonical, err := attestation.signingBytes()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	privateKey, err := ecdhToECDSA(relayPrivateKey)
	if err != nil {
		return err
	}
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		return err
	}
	attestation.Signature = base64.RawURLEncoding.EncodeToString(signature)
	envelope.ForwardAttestation = attestation
	return nil
}

func VerifyRelayForwardAttestation(verifier CertVerifier, envelope *BusinessAdmissionEnvelopeV2, now time.Time) error {
	if verifier == nil || envelope == nil || envelope.ForwardAttestation == nil {
		return fmt.Errorf("%w: relay forward attestation required", ErrBusinessAdmissionInvalid)
	}
	attestation := envelope.ForwardAttestation
	if attestation.Version != 1 || attestation.EntryRelayID != envelope.EntryRelayID ||
		attestation.TargetNodeID != envelope.TargetNodeID || attestation.ConnectionID != envelope.ConnectionID ||
		attestation.LegSessionID != envelope.LegSessionID || attestation.RelayNodeID != attestation.RelayCert.Cert.SubjectNodeID {
		return fmt.Errorf("%w: relay forward attestation binding mismatch", ErrBusinessAdmissionInvalid)
	}
	proofDigest, err := envelope.proofDigest()
	if err != nil || attestation.SourceProofDigest != proofDigest {
		return fmt.Errorf("%w: relay forward source proof mismatch", ErrBusinessAdmissionInvalid)
	}
	certificateBytes, err := json.Marshal(&attestation.RelayCert)
	if err != nil {
		return err
	}
	certificateDigest := sha256.Sum256(certificateBytes)
	if !strings.EqualFold(attestation.RelayCertDigest, hex.EncodeToString(certificateDigest[:])) {
		return fmt.Errorf("%w: relay forward certificate digest mismatch", ErrBusinessAdmissionInvalid)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if attestation.ExpiresAt <= attestation.VerifiedAt || attestation.ExpiresAt-attestation.VerifiedAt > int64(BusinessAdmissionMaxTTL/time.Second) ||
		now.Unix() < attestation.VerifiedAt-60 || now.Unix() >= attestation.ExpiresAt {
		return ErrBusinessAdmissionExpired
	}
	if err := verifier.Verify(&attestation.RelayCert, VerifyOptions{
		Now: now, ExpectNodeID: attestation.RelayNodeID, ExpectRole: RoleRelay,
	}); err != nil {
		return fmt.Errorf("%w: relay certificate: %v", ErrBusinessAdmissionInvalid, err)
	}
	canonical, err := attestation.signingBytes()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	signature, err := base64.RawURLEncoding.DecodeString(attestation.Signature)
	if err != nil {
		return ErrBusinessAdmissionInvalid
	}
	publicKey, err := ParseIdentityPublicKey(attestation.RelayCert.Cert.SubjectPubKey)
	if err != nil {
		return err
	}
	publicECDSA, err := ecdhPublicToECDSA(publicKey)
	if err != nil || !ecdsa.VerifyASN1(publicECDSA, digest[:], signature) {
		return fmt.Errorf("%w: relay forward signature invalid", ErrBusinessAdmissionInvalid)
	}
	return nil
}

func (attestation *RelayForwardAttestationV1) signingBytes() ([]byte, error) {
	if attestation == nil {
		return nil, ErrBusinessAdmissionInvalid
	}
	copy := *attestation
	copy.Signature = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return nil, err
	}
	return append([]byte("BNFS/RELAY-FORWARD-ATTESTATION/V1\x00"), encoded...), nil
}

func (envelope *BusinessAdmissionEnvelopeV2) proofDigest() (string, error) {
	digest, err := envelope.digest()
	if err != nil {
		return "", err
	}
	proofDigest := sha256.Sum256(append(append([]byte(nil), digest...), []byte(envelope.Nonce)...))
	return hex.EncodeToString(proofDigest[:]), nil
}

func minInt64(first, second int64) int64 {
	if first < second {
		return first
	}
	return second
}

func ParseBusinessAdmissionEnvelope(payload []byte) (*BusinessAdmissionEnvelopeV2, error) {
	if len(payload) == 0 {
		return nil, ErrBusinessAdmissionRequired
	}
	if len(payload) > BusinessAdmissionMaxSize {
		return nil, fmt.Errorf("%w: envelope exceeds size limit", ErrBusinessAdmissionInvalid)
	}
	if payload[0] != '{' {
		return nil, ErrBusinessAdmissionRequired
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var envelope BusinessAdmissionEnvelopeV2
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBusinessAdmissionInvalid, err)
	}
	if envelope.Version != BusinessAdmissionVersion {
		return nil, ErrBusinessAdmissionRequired
	}
	return &envelope, nil
}

func VerifyBusinessAdmissionEnvelope(verifier CertVerifier, envelope *BusinessAdmissionEnvelopeV2, targetNodeID, connectionID string, now time.Time) (*BusinessAdmissionDecision, error) {
	if verifier == nil || envelope == nil || envelope.Version != BusinessAdmissionVersion {
		return nil, ErrBusinessAdmissionInvalid
	}
	if envelope.TargetNodeID != targetNodeID || envelope.ConnectionID != connectionID || envelope.LegSessionID == "" || envelope.EntryRelayID == "" {
		return nil, ErrBusinessAdmissionInvalid
	}
	if envelope.SourceNodeID != NodeIDFromPubKeyHex(envelope.SourcePublicKey) {
		return nil, ErrBusinessAdmissionInvalid
	}
	certBytes, err := json.Marshal(envelope.SourceCert.Cert)
	if err != nil {
		return nil, err
	}
	certDigest := sha256.Sum256(certBytes)
	if !strings.EqualFold(envelope.SourceCertDigest, hex.EncodeToString(certDigest[:])) || envelope.SourceCert.Cert.SubjectPubKey != envelope.SourcePublicKey {
		return nil, ErrBusinessAdmissionInvalid
	}
	if err := verifier.Verify(&envelope.SourceCert, VerifyOptions{Now: now, ExpectNodeID: envelope.SourceNodeID, ExpectRole: RoleClient}); err != nil {
		return nil, fmt.Errorf("%w: certificate: %v", ErrBusinessAdmissionInvalid, err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if envelope.ExpiresAt <= envelope.IssuedAt || envelope.ExpiresAt-envelope.IssuedAt > int64(BusinessAdmissionMaxTTL/time.Second) || now.Unix() < envelope.IssuedAt-60 || now.Unix() >= envelope.ExpiresAt {
		return nil, ErrBusinessAdmissionExpired
	}
	digest, err := envelope.digest()
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.SourceSignature)
	if err != nil {
		return nil, ErrBusinessAdmissionInvalid
	}
	publicKey, err := ParseIdentityPublicKey(envelope.SourcePublicKey)
	if err != nil {
		return nil, err
	}
	publicECDSA, err := ecdhPublicToECDSA(publicKey)
	if err != nil || !ecdsa.VerifyASN1(publicECDSA, digest, signature) {
		return nil, ErrBusinessAdmissionInvalid
	}
	proofDigest, err := envelope.proofDigest()
	if err != nil {
		return nil, err
	}
	return &BusinessAdmissionDecision{SourceNodeID: envelope.SourceNodeID, SourcePublicKey: envelope.SourcePublicKey, ProofDigest: proofDigest, Envelope: envelope}, nil
}

func ecdhToECDSA(privateKey *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	publicKey, err := ecdhPublicToECDSA(privateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	scalar := new(big.Int).SetBytes(privateKey.Bytes())
	if scalar.Sign() <= 0 || scalar.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, ErrBusinessAdmissionInvalid
	}
	return &ecdsa.PrivateKey{PublicKey: *publicKey, D: scalar}, nil
}

func ecdhPublicToECDSA(publicKey *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	if publicKey == nil {
		return nil, ErrBusinessAdmissionInvalid
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey.Bytes())
	if x == nil || y == nil {
		return nil, ErrBusinessAdmissionInvalid
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
