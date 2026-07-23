package billingvoucher

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

const (
	CurrentVersion        uint16 = 1
	CumulativeWindowBytes        = uint64(1 << 20)
	IdentifierSize               = 32
	MaxSequence           uint64 = math.MaxInt64
	MaxBillableBytes      uint64 = math.MaxInt64
)

const (
	voucherBodyDomain    = "BNFS/USAGE-VOUCHER-BODY/V1"
	mutualVoucherDomain  = "BNFS/MUTUAL-VOUCHER/V1"
	mutualEncodingDomain = "BNFS/MUTUAL-VOUCHER-WIRE/V1"
	CanonicalBodySize    = len(voucherBodyDomain) + 2 + 7*IdentifierSize + 1 + 4*8
)

type Identifier [IdentifierSize]byte

type Digest [IdentifierSize]byte

func ParseIdentifierHex(value string) (Identifier, error) {
	var identifier Identifier
	decoded, err := decodeCanonicalHex(value)
	if err != nil {
		return identifier, fmt.Errorf("billingvoucher: invalid identifier: %w", err)
	}
	copy(identifier[:], decoded)
	return identifier, nil
}

func (identifier Identifier) String() string {
	return hex.EncodeToString(identifier[:])
}

func ParseDigestHex(value string) (Digest, error) {
	var digest Digest
	decoded, err := decodeCanonicalHex(value)
	if err != nil {
		return digest, fmt.Errorf("billingvoucher: invalid digest: %w", err)
	}
	copy(digest[:], decoded)
	return digest, nil
}

func (digest Digest) String() string {
	return hex.EncodeToString(digest[:])
}

func decodeCanonicalHex(value string) ([]byte, error) {
	if len(value) != 2*IdentifierSize {
		return nil, fmt.Errorf("expected %d hexadecimal characters", 2*IdentifierSize)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(decoded) != value {
		return nil, errors.New("hexadecimal text must use lowercase canonical form")
	}
	return decoded, nil
}

type Direction uint8

const (
	DirectionPayerOutbound Direction = 1
	DirectionPayerInbound  Direction = 2
)

func (direction Direction) Valid() bool {
	return direction == DirectionPayerOutbound || direction == DirectionPayerInbound
}

type VoucherBody struct {
	Version                 uint16
	SessionID               Identifier
	PayerNatID              Identifier
	PayeeRelayID            Identifier
	Direction               Direction
	Sequence                uint64
	PreviousMutualVoucherID Identifier
	CumulativeUniqueBytes   uint64
	LastRecordID            Identifier
	LastRecordSequence      uint64
	RecordSetDigest         Digest
	PolicyDigest            Digest
	AuthorizedThroughBytes  uint64
}

func (body VoucherBody) Validate() error {
	if body.Version != CurrentVersion {
		return fmt.Errorf("billingvoucher: unsupported version %d", body.Version)
	}
	if zeroIdentifier(body.SessionID) {
		return errors.New("billingvoucher: session ID is required")
	}
	if zeroIdentifier(body.PayerNatID) {
		return errors.New("billingvoucher: payer Nat ID is required")
	}
	if zeroIdentifier(body.PayeeRelayID) {
		return errors.New("billingvoucher: payee Relay ID is required")
	}
	if body.PayerNatID == body.PayeeRelayID {
		return errors.New("billingvoucher: payer Nat and payee Relay must differ")
	}
	if !body.Direction.Valid() {
		return fmt.Errorf("billingvoucher: invalid direction %d", body.Direction)
	}
	if body.Sequence == 0 || body.Sequence > MaxSequence {
		return fmt.Errorf("billingvoucher: sequence must be between 1 and %d", MaxSequence)
	}
	if body.Sequence == 1 && !zeroIdentifier(body.PreviousMutualVoucherID) {
		return errors.New("billingvoucher: first voucher must not reference a predecessor")
	}
	if body.Sequence > 1 && zeroIdentifier(body.PreviousMutualVoucherID) {
		return errors.New("billingvoucher: non-first voucher requires a predecessor ID")
	}
	if body.CumulativeUniqueBytes == 0 || body.CumulativeUniqueBytes > MaxBillableBytes {
		return fmt.Errorf("billingvoucher: cumulative unique bytes must be between 1 and %d", MaxBillableBytes)
	}
	if body.AuthorizedThroughBytes == 0 || body.AuthorizedThroughBytes > MaxBillableBytes {
		return fmt.Errorf("billingvoucher: authorized-through bytes must be between 1 and %d", MaxBillableBytes)
	}
	if body.CumulativeUniqueBytes > body.AuthorizedThroughBytes {
		return errors.New("billingvoucher: cumulative unique bytes exceed authorization")
	}
	if body.CumulativeUniqueBytes > sequenceWindowCeiling(body.Sequence) {
		return errors.New("billingvoucher: cumulative unique bytes exceed the 1 MiB sequence window ceiling")
	}
	if zeroIdentifier(body.LastRecordID) {
		return errors.New("billingvoucher: last RecordID is required")
	}
	if body.LastRecordSequence == 0 || body.LastRecordSequence > MaxSequence {
		return errors.New("billingvoucher: last RecordID sequence is invalid")
	}
	if zeroDigest(body.RecordSetDigest) {
		return errors.New("billingvoucher: record-set digest is required")
	}
	if zeroDigest(body.PolicyDigest) {
		return errors.New("billingvoucher: policy digest is required")
	}
	return nil
}

func sequenceWindowCeiling(sequence uint64) uint64 {
	if sequence > MaxBillableBytes/CumulativeWindowBytes {
		return MaxBillableBytes
	}
	return sequence * CumulativeWindowBytes
}

func (body VoucherBody) CanonicalBytes() ([]byte, error) {
	if err := body.Validate(); err != nil {
		return nil, err
	}
	encoded := make([]byte, CanonicalBodySize)
	offset := copy(encoded, voucherBodyDomain)
	binary.BigEndian.PutUint16(encoded[offset:offset+2], body.Version)
	offset += 2
	offset += copy(encoded[offset:], body.SessionID[:])
	offset += copy(encoded[offset:], body.PayerNatID[:])
	offset += copy(encoded[offset:], body.PayeeRelayID[:])
	encoded[offset] = byte(body.Direction)
	offset++
	binary.BigEndian.PutUint64(encoded[offset:offset+8], body.Sequence)
	offset += 8
	offset += copy(encoded[offset:], body.PreviousMutualVoucherID[:])
	binary.BigEndian.PutUint64(encoded[offset:offset+8], body.CumulativeUniqueBytes)
	offset += 8
	offset += copy(encoded[offset:], body.LastRecordID[:])
	binary.BigEndian.PutUint64(encoded[offset:offset+8], body.LastRecordSequence)
	offset += 8
	offset += copy(encoded[offset:], body.RecordSetDigest[:])
	offset += copy(encoded[offset:], body.PolicyDigest[:])
	binary.BigEndian.PutUint64(encoded[offset:offset+8], body.AuthorizedThroughBytes)
	return encoded, nil
}

func ParseCanonicalBody(encoded []byte) (VoucherBody, error) {
	var body VoucherBody
	if len(encoded) != CanonicalBodySize {
		return body, fmt.Errorf("billingvoucher: canonical body length %d, want %d", len(encoded), CanonicalBodySize)
	}
	if !bytes.Equal(encoded[:len(voucherBodyDomain)], []byte(voucherBodyDomain)) {
		return body, errors.New("billingvoucher: invalid canonical body domain")
	}
	offset := len(voucherBodyDomain)
	body.Version = binary.BigEndian.Uint16(encoded[offset : offset+2])
	offset += 2
	offset += copy(body.SessionID[:], encoded[offset:offset+IdentifierSize])
	offset += copy(body.PayerNatID[:], encoded[offset:offset+IdentifierSize])
	offset += copy(body.PayeeRelayID[:], encoded[offset:offset+IdentifierSize])
	body.Direction = Direction(encoded[offset])
	offset++
	body.Sequence = binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	offset += copy(body.PreviousMutualVoucherID[:], encoded[offset:offset+IdentifierSize])
	body.CumulativeUniqueBytes = binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	offset += copy(body.LastRecordID[:], encoded[offset:offset+IdentifierSize])
	body.LastRecordSequence = binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	offset += copy(body.RecordSetDigest[:], encoded[offset:offset+IdentifierSize])
	offset += copy(body.PolicyDigest[:], encoded[offset:offset+IdentifierSize])
	body.AuthorizedThroughBytes = binary.BigEndian.Uint64(encoded[offset : offset+8])
	if err := body.Validate(); err != nil {
		return VoucherBody{}, err
	}
	return body, nil
}

func (body VoucherBody) BodyID() (Identifier, error) {
	encoded, err := body.CanonicalBytes()
	if err != nil {
		return Identifier{}, err
	}
	return sha256.Sum256(encoded), nil
}

type MutualVoucher struct {
	Body           VoucherBody
	PayerSignature []byte
	RelaySignature []byte
}

func NewMutualVoucher(body VoucherBody, payerSignature, relaySignature []byte) (MutualVoucher, error) {
	voucher := MutualVoucher{
		Body:           body,
		PayerSignature: bytes.Clone(payerSignature),
		RelaySignature: bytes.Clone(relaySignature),
	}
	if _, err := voucher.ID(); err != nil {
		return MutualVoucher{}, err
	}
	return voucher, nil
}

func (voucher MutualVoucher) ID() (Identifier, error) {
	bodyID, err := voucher.Body.BodyID()
	if err != nil {
		return Identifier{}, err
	}
	if err := validateCanonicalSignature(voucher.PayerSignature); err != nil {
		return Identifier{}, fmt.Errorf("billingvoucher: invalid payer signature: %w", err)
	}
	if err := validateCanonicalSignature(voucher.RelaySignature); err != nil {
		return Identifier{}, fmt.Errorf("billingvoucher: invalid Relay signature: %w", err)
	}
	encoded := make([]byte, 0, len(mutualVoucherDomain)+IdentifierSize+4+len(voucher.PayerSignature)+len(voucher.RelaySignature))
	encoded = append(encoded, mutualVoucherDomain...)
	encoded = append(encoded, bodyID[:]...)
	encoded = appendLengthPrefixedSignature(encoded, voucher.PayerSignature)
	encoded = appendLengthPrefixedSignature(encoded, voucher.RelaySignature)
	return sha256.Sum256(encoded), nil
}

func (voucher MutualVoucher) CanonicalBytes() ([]byte, error) {
	body, err := voucher.Body.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if err := validateCanonicalSignature(voucher.PayerSignature); err != nil {
		return nil, fmt.Errorf("billingvoucher: invalid payer signature: %w", err)
	}
	if err := validateCanonicalSignature(voucher.RelaySignature); err != nil {
		return nil, fmt.Errorf("billingvoucher: invalid Relay signature: %w", err)
	}
	encoded := make([]byte, 0, len(mutualEncodingDomain)+len(body)+4+len(voucher.PayerSignature)+len(voucher.RelaySignature))
	encoded = append(encoded, mutualEncodingDomain...)
	encoded = append(encoded, body...)
	encoded = appendLengthPrefixedSignature(encoded, voucher.PayerSignature)
	encoded = appendLengthPrefixedSignature(encoded, voucher.RelaySignature)
	return encoded, nil
}

func ParseCanonicalVoucher(encoded []byte) (MutualVoucher, error) {
	minimum := len(mutualEncodingDomain) + CanonicalBodySize + 4
	if len(encoded) < minimum {
		return MutualVoucher{}, errors.New("billingvoucher: canonical mutual voucher is truncated")
	}
	if !bytes.Equal(encoded[:len(mutualEncodingDomain)], []byte(mutualEncodingDomain)) {
		return MutualVoucher{}, errors.New("billingvoucher: invalid mutual voucher domain")
	}
	offset := len(mutualEncodingDomain)
	body, err := ParseCanonicalBody(encoded[offset : offset+CanonicalBodySize])
	if err != nil {
		return MutualVoucher{}, err
	}
	offset += CanonicalBodySize
	payerSignature, next, err := readLengthPrefixedSignature(encoded, offset)
	if err != nil {
		return MutualVoucher{}, fmt.Errorf("billingvoucher: payer signature: %w", err)
	}
	relaySignature, next, err := readLengthPrefixedSignature(encoded, next)
	if err != nil {
		return MutualVoucher{}, fmt.Errorf("billingvoucher: Relay signature: %w", err)
	}
	if next != len(encoded) {
		return MutualVoucher{}, errors.New("billingvoucher: trailing canonical voucher data")
	}
	return NewMutualVoucher(body, payerSignature, relaySignature)
}

func appendLengthPrefixedSignature(encoded, signature []byte) []byte {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(signature)))
	encoded = append(encoded, length[:]...)
	return append(encoded, signature...)
}

func readLengthPrefixedSignature(encoded []byte, offset int) ([]byte, int, error) {
	if len(encoded)-offset < 2 {
		return nil, offset, errors.New("missing signature length")
	}
	length := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	if length == 0 || length > MaxSignatureSize || len(encoded)-offset < length {
		return nil, offset, errors.New("invalid signature length")
	}
	signature := bytes.Clone(encoded[offset : offset+length])
	if err := validateCanonicalSignature(signature); err != nil {
		return nil, offset, err
	}
	return signature, offset + length, nil
}

func ValidateSuccessor(previous, current MutualVoucher) error {
	previousID, err := previous.ID()
	if err != nil {
		return fmt.Errorf("billingvoucher: invalid predecessor: %w", err)
	}
	if _, err := current.ID(); err != nil {
		return fmt.Errorf("billingvoucher: invalid successor: %w", err)
	}
	previousBody := previous.Body
	currentBody := current.Body
	if previousBody.Sequence == MaxSequence || currentBody.Sequence != previousBody.Sequence+1 {
		return errors.New("billingvoucher: successor sequence must advance by exactly one")
	}
	if currentBody.PreviousMutualVoucherID != previousID {
		return errors.New("billingvoucher: successor does not reference the predecessor MutualVoucherID")
	}
	if currentBody.Version != previousBody.Version ||
		currentBody.SessionID != previousBody.SessionID ||
		currentBody.PayerNatID != previousBody.PayerNatID ||
		currentBody.PayeeRelayID != previousBody.PayeeRelayID ||
		currentBody.Direction != previousBody.Direction ||
		currentBody.PolicyDigest != previousBody.PolicyDigest ||
		currentBody.AuthorizedThroughBytes != previousBody.AuthorizedThroughBytes {
		return errors.New("billingvoucher: successor changes immutable channel bindings")
	}
	if currentBody.CumulativeUniqueBytes <= previousBody.CumulativeUniqueBytes {
		return errors.New("billingvoucher: successor cumulative unique bytes must increase")
	}
	if currentBody.LastRecordSequence <= previousBody.LastRecordSequence {
		return errors.New("billingvoucher: successor last RecordID sequence must increase")
	}
	if currentBody.CumulativeUniqueBytes-previousBody.CumulativeUniqueBytes > CumulativeWindowBytes {
		return errors.New("billingvoucher: successor exceeds the 1 MiB cumulative window")
	}
	if currentBody.RecordSetDigest == previousBody.RecordSetDigest {
		return errors.New("billingvoucher: successor record-set digest did not advance")
	}
	return nil
}

func zeroIdentifier(value Identifier) bool {
	return value == Identifier{}
}

func zeroDigest(value Digest) bool {
	return value == Digest{}
}
