package billingcontrol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

const (
	ChallengeSize       = 32
	MaximumProofSize    = 72
	readyProofDomain    = "BNFS/BILLING-CONTROL/READY-PROOF/V1\x00"
	relayStateDomain    = "BNFS/BILLING-CONTROL/RELAY-STATE-PROOF/V1\x00"
	readyStateDomain    = "BNFS/BILLING-CONTROL/READY-STATE-PROOF/V1\x00"
	canonicalIdentifier = 32
)

type ProofBinding struct {
	Challenge []byte
	SessionID string
	PayerID   string
	RelayID   string
}

type RelayStateProofBinding struct {
	ProofBinding
	CumulativeBytes    uint64
	LastRecordID       string
	LastRecordSequence uint64
	RecordSetDigest    string
}

type ReadyStateProofBinding struct {
	RelayStateProofBinding
	SessionPreexisting   bool
	SessionResetRequired bool
	RecoveryVoucherID    string
}

type p256Signature struct {
	R *big.Int
	S *big.Int
}

func NewChallenge() ([]byte, error) {
	for {
		challenge := make([]byte, ChallengeSize)
		if _, err := rand.Read(challenge); err != nil {
			return nil, fmt.Errorf("billingcontrol: generate challenge: %w", err)
		}
		if !allZero(challenge) {
			return challenge, nil
		}
	}
}

func IdentityIDFromPublicKeyHex(publicKeyHex string) (string, error) {
	if _, err := parseIdentityPublicKey(publicKeyHex); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(publicKeyHex))
	return hex.EncodeToString(digest[:]), nil
}

func SignReadyProof(identity *ecdh.PrivateKey, binding ProofBinding) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("billingcontrol: payer identity private key is nil")
	}
	digest, err := readyProofDigest(binding)
	if err != nil {
		return nil, err
	}
	payerID, err := IdentityIDFromPublicKeyHex(hex.EncodeToString(identity.PublicKey().Bytes()))
	if err != nil {
		return nil, err
	}
	if payerID != binding.PayerID {
		return nil, errors.New("billingcontrol: payer private key does not match proof binding")
	}
	privateKey, err := ecdsaPrivateKey(identity)
	if err != nil {
		return nil, err
	}
	signatureR, signatureS, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("billingcontrol: sign ready proof: %w", err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if signatureS.Cmp(halfOrder) > 0 {
		signatureS.Sub(elliptic.P256().Params().N, signatureS)
	}
	encoded, err := asn1.Marshal(p256Signature{R: signatureR, S: signatureS})
	if err != nil {
		return nil, fmt.Errorf("billingcontrol: encode ready proof: %w", err)
	}
	if len(encoded) > MaximumProofSize {
		return nil, errors.New("billingcontrol: ready proof exceeds canonical size")
	}
	return encoded, nil
}

func VerifyReadyProof(publicKeyHex string, binding ProofBinding, proof []byte) error {
	digest, err := readyProofDigest(binding)
	if err != nil {
		return err
	}
	identity, err := parseIdentityPublicKey(publicKeyHex)
	if err != nil {
		return err
	}
	payerID, err := IdentityIDFromPublicKeyHex(publicKeyHex)
	if err != nil {
		return err
	}
	if payerID != binding.PayerID {
		return errors.New("billingcontrol: proof public key does not match payer binding")
	}
	parsed, err := parseCanonicalProof(proof, true)
	if err != nil {
		return err
	}
	publicKey, err := ecdsaPublicKey(identity)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(publicKey, digest[:], parsed.R, parsed.S) {
		return errors.New("billingcontrol: invalid payer ready proof")
	}
	return nil
}

func SignRelayStateProof(identity *ecdh.PrivateKey, binding RelayStateProofBinding) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("billingcontrol: Relay identity private key is nil")
	}
	digest, err := relayStateProofDigest(binding)
	if err != nil {
		return nil, err
	}
	relayID, err := IdentityIDFromPublicKeyHex(hex.EncodeToString(identity.PublicKey().Bytes()))
	if err != nil {
		return nil, err
	}
	if relayID != binding.RelayID {
		return nil, errors.New("billingcontrol: Relay private key does not match state proof binding")
	}
	privateKey, err := ecdsaPrivateKey(identity)
	if err != nil {
		return nil, err
	}
	signatureR, signatureS, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("billingcontrol: sign Relay state proof: %w", err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if signatureS.Cmp(halfOrder) > 0 {
		signatureS.Sub(elliptic.P256().Params().N, signatureS)
	}
	encoded, err := asn1.Marshal(p256Signature{R: signatureR, S: signatureS})
	if err != nil {
		return nil, fmt.Errorf("billingcontrol: encode Relay state proof: %w", err)
	}
	if len(encoded) > MaximumProofSize {
		return nil, errors.New("billingcontrol: Relay state proof exceeds canonical size")
	}
	return encoded, nil
}

func VerifyRelayStateProof(publicKeyHex string, binding RelayStateProofBinding, proof []byte) error {
	digest, err := relayStateProofDigest(binding)
	if err != nil {
		return err
	}
	identity, err := parseIdentityPublicKey(publicKeyHex)
	if err != nil {
		return err
	}
	relayID, err := IdentityIDFromPublicKeyHex(publicKeyHex)
	if err != nil {
		return err
	}
	if relayID != binding.RelayID {
		return errors.New("billingcontrol: state proof public key does not match Relay binding")
	}
	parsed, err := parseCanonicalProof(proof, true)
	if err != nil {
		return err
	}
	publicKey, err := ecdsaPublicKey(identity)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(publicKey, digest[:], parsed.R, parsed.S) {
		return errors.New("billingcontrol: invalid Relay state proof")
	}
	return nil
}

func SignReadyStateProof(identity *ecdh.PrivateKey, binding ReadyStateProofBinding) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("billingcontrol: payer identity private key is nil")
	}
	digest, err := readyStateProofDigest(binding)
	if err != nil {
		return nil, err
	}
	payerID, err := IdentityIDFromPublicKeyHex(hex.EncodeToString(identity.PublicKey().Bytes()))
	if err != nil {
		return nil, err
	}
	if payerID != binding.PayerID {
		return nil, errors.New("billingcontrol: payer private key does not match ready-state binding")
	}
	privateKey, err := ecdsaPrivateKey(identity)
	if err != nil {
		return nil, err
	}
	signatureR, signatureS, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("billingcontrol: sign ready-state proof: %w", err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if signatureS.Cmp(halfOrder) > 0 {
		signatureS.Sub(elliptic.P256().Params().N, signatureS)
	}
	encoded, err := asn1.Marshal(p256Signature{R: signatureR, S: signatureS})
	if err != nil {
		return nil, fmt.Errorf("billingcontrol: encode ready-state proof: %w", err)
	}
	if len(encoded) > MaximumProofSize {
		return nil, errors.New("billingcontrol: ready-state proof exceeds canonical size")
	}
	return encoded, nil
}

func VerifyReadyStateProof(publicKeyHex string, binding ReadyStateProofBinding, proof []byte) error {
	digest, err := readyStateProofDigest(binding)
	if err != nil {
		return err
	}
	identity, err := parseIdentityPublicKey(publicKeyHex)
	if err != nil {
		return err
	}
	payerID, err := IdentityIDFromPublicKeyHex(publicKeyHex)
	if err != nil {
		return err
	}
	if payerID != binding.PayerID {
		return errors.New("billingcontrol: ready-state proof public key does not match payer binding")
	}
	parsed, err := parseCanonicalProof(proof, true)
	if err != nil {
		return err
	}
	publicKey, err := ecdsaPublicKey(identity)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(publicKey, digest[:], parsed.R, parsed.S) {
		return errors.New("billingcontrol: invalid payer ready-state proof")
	}
	return nil
}

func readyProofDigest(binding ProofBinding) ([sha256.Size]byte, error) {
	if len(binding.Challenge) != ChallengeSize || allZero(binding.Challenge) {
		return [sha256.Size]byte{}, errors.New("billingcontrol: challenge must be a non-zero 32-byte value")
	}
	sessionID, err := decodeIdentifier("session", binding.SessionID)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	payerID, err := decodeIdentifier("payer", binding.PayerID)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	relayID, err := decodeIdentifier("Relay", binding.RelayID)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded := make([]byte, 0, len(readyProofDomain)+ChallengeSize+3*canonicalIdentifier)
	encoded = append(encoded, readyProofDomain...)
	encoded = append(encoded, binding.Challenge...)
	encoded = append(encoded, sessionID...)
	encoded = append(encoded, payerID...)
	encoded = append(encoded, relayID...)
	return sha256.Sum256(encoded), nil
}

func relayStateProofDigest(binding RelayStateProofBinding) ([sha256.Size]byte, error) {
	readyDigest, err := readyProofDigest(binding.ProofBinding)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	lastRecordID, err := decodeStateDigest("last Record", binding.LastRecordID)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	recordSetDigest, err := decodeStateDigest("record-set", binding.RecordSetDigest)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	emptyState := binding.CumulativeBytes == 0 && binding.LastRecordSequence == 0 &&
		allZero(lastRecordID) && allZero(recordSetDigest)
	nonEmptyState := binding.CumulativeBytes > 0 && binding.LastRecordSequence > 0 &&
		!allZero(lastRecordID) && !allZero(recordSetDigest)
	if !emptyState && !nonEmptyState {
		return [sha256.Size]byte{}, errors.New("billingcontrol: Relay state watermark is inconsistent")
	}
	encoded := make([]byte, 0, len(relayStateDomain)+sha256.Size+2*8+2*canonicalIdentifier)
	encoded = append(encoded, relayStateDomain...)
	encoded = append(encoded, readyDigest[:]...)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], binding.CumulativeBytes)
	encoded = append(encoded, number[:]...)
	encoded = append(encoded, lastRecordID...)
	binary.BigEndian.PutUint64(number[:], binding.LastRecordSequence)
	encoded = append(encoded, number[:]...)
	encoded = append(encoded, recordSetDigest...)
	return sha256.Sum256(encoded), nil
}

func readyStateProofDigest(binding ReadyStateProofBinding) ([sha256.Size]byte, error) {
	stateDigest, err := relayStateProofDigest(binding.RelayStateProofBinding)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if binding.SessionResetRequired && binding.SessionPreexisting {
		return [sha256.Size]byte{}, errors.New("billingcontrol: reset-required ready state is inconsistent")
	}
	recoveryVoucherID := make([]byte, canonicalIdentifier)
	if binding.RecoveryVoucherID != "" {
		recoveryVoucherID, err = decodeStateDigest("recovery voucher", binding.RecoveryVoucherID)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		if allZero(recoveryVoucherID) {
			return [sha256.Size]byte{}, errors.New("billingcontrol: recovery voucher ID must be non-zero")
		}
	}
	encoded := make([]byte, 0, len(readyStateDomain)+sha256.Size+2+canonicalIdentifier)
	encoded = append(encoded, readyStateDomain...)
	encoded = append(encoded, stateDigest[:]...)
	if binding.SessionPreexisting {
		encoded = append(encoded, 1)
	} else {
		encoded = append(encoded, 0)
	}
	if binding.SessionResetRequired {
		encoded = append(encoded, 1)
	} else {
		encoded = append(encoded, 0)
	}
	encoded = append(encoded, recoveryVoucherID...)
	return sha256.Sum256(encoded), nil
}

func decodeStateDigest(name, value string) ([]byte, error) {
	if len(value) != 2*canonicalIdentifier {
		return nil, fmt.Errorf("billingcontrol: %s digest must be 32 bytes", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("billingcontrol: %s digest is not canonical", name)
	}
	return decoded, nil
}

func decodeIdentifier(name, value string) ([]byte, error) {
	if len(value) != 2*canonicalIdentifier {
		return nil, fmt.Errorf("billingcontrol: %s ID must be 32 bytes", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value || allZero(decoded) {
		return nil, fmt.Errorf("billingcontrol: %s ID is not canonical", name)
	}
	return decoded, nil
}

func parseIdentityPublicKey(value string) (*ecdh.PublicKey, error) {
	if value == "" {
		return nil, errors.New("billingcontrol: identity public key is empty")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return nil, errors.New("billingcontrol: identity public key is not canonical hexadecimal")
	}
	identity, err := ecdh.P256().NewPublicKey(decoded)
	if err != nil {
		return nil, errors.New("billingcontrol: identity public key is not P-256")
	}
	return identity, nil
}

func ecdsaPrivateKey(identity *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	publicKey, err := ecdsaPublicKey(identity.PublicKey())
	if err != nil {
		return nil, err
	}
	scalar := new(big.Int).SetBytes(identity.Bytes())
	order := elliptic.P256().Params().N
	if scalar.Sign() <= 0 || scalar.Cmp(order) >= 0 {
		return nil, errors.New("billingcontrol: payer identity scalar is invalid")
	}
	expectedX, expectedY := elliptic.P256().ScalarBaseMult(scalar.Bytes())
	if expectedX.Cmp(publicKey.X) != 0 || expectedY.Cmp(publicKey.Y) != 0 {
		return nil, errors.New("billingcontrol: payer identity key pair does not match")
	}
	return &ecdsa.PrivateKey{PublicKey: *publicKey, D: scalar}, nil
}

func ecdsaPublicKey(identity *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	if identity == nil {
		return nil, errors.New("billingcontrol: P-256 identity public key is nil")
	}
	publicX, publicY := elliptic.Unmarshal(elliptic.P256(), identity.Bytes())
	if publicX == nil || publicY == nil {
		return nil, errors.New("billingcontrol: P-256 identity public key is invalid")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: publicX, Y: publicY}, nil
}

func parseCanonicalProof(proof []byte, requireLowS bool) (p256Signature, error) {
	if len(proof) == 0 || len(proof) > MaximumProofSize {
		return p256Signature{}, errors.New("billingcontrol: ready proof length is out of range")
	}
	var parsed p256Signature
	rest, err := asn1.Unmarshal(proof, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return p256Signature{}, errors.New("billingcontrol: ready proof is not valid ASN.1 P-256")
	}
	canonical, err := asn1.Marshal(parsed)
	if err != nil || !bytes.Equal(canonical, proof) {
		return p256Signature{}, errors.New("billingcontrol: ready proof is not canonical ASN.1")
	}
	order := elliptic.P256().Params().N
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || parsed.R.Cmp(order) >= 0 || parsed.S.Cmp(order) >= 0 {
		return p256Signature{}, errors.New("billingcontrol: ready proof scalar is out of range")
	}
	if requireLowS {
		halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
		if parsed.S.Cmp(halfOrder) > 0 {
			return p256Signature{}, errors.New("billingcontrol: ready proof is not canonical low-S")
		}
	}
	return parsed, nil
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
