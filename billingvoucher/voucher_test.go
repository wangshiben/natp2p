package billingvoucher

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestVoucherBodyCanonicalEncoding(t *testing.T) {
	body := deterministicBody()
	first, err := body.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	second, err := body.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes second call: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical body encoding changed between calls")
	}
	if len(first) != CanonicalBodySize {
		t.Fatalf("canonical body length=%d, want %d", len(first), CanonicalBodySize)
	}
	parsed, err := ParseCanonicalBody(first)
	if err != nil {
		t.Fatalf("ParseCanonicalBody: %v", err)
	}
	if parsed != body {
		t.Fatalf("canonical round trip changed body: got %#v want %#v", parsed, body)
	}
	bodyID, err := body.BodyID()
	if err != nil {
		t.Fatalf("BodyID: %v", err)
	}
	const expectedBodyID = "450a83a658e3383fcf659d8b383673ed18c9d3773fb7dea33a140e8641612040"
	if bodyID.String() != expectedBodyID {
		t.Fatalf("body ID=%s, want stable golden %s", bodyID, expectedBodyID)
	}
}

func TestMutualVoucherSignVerifyAndRoundTrip(t *testing.T) {
	payer := generateIdentity(t)
	relay := generateIdentity(t)
	body := bodyForIdentities(t, payer, relay, 1, 768*1024, Identifier{})

	payerSignature := mustSignPayer(t, body, payer)
	secondPayerSignature := mustSignPayer(t, body, payer)
	if !bytes.Equal(payerSignature, secondPayerSignature) {
		t.Fatal("RFC6979 payer signature is not deterministic")
	}
	relaySignature := mustSignRelay(t, body, relay)
	secondRelaySignature := mustSignRelay(t, body, relay)
	if !bytes.Equal(relaySignature, secondRelaySignature) {
		t.Fatal("RFC6979 Relay signature is not deterministic")
	}

	voucher, err := NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		t.Fatalf("NewMutualVoucher: %v", err)
	}
	if err := voucher.Verify(payer.PublicKey(), relay.PublicKey()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	firstID, err := voucher.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	secondID, err := voucher.ID()
	if err != nil {
		t.Fatalf("ID second call: %v", err)
	}
	if firstID != secondID {
		t.Fatal("MutualVoucherID changed between calls")
	}
	encoded, err := voucher.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	parsed, err := ParseCanonicalVoucher(encoded)
	if err != nil {
		t.Fatalf("ParseCanonicalVoucher: %v", err)
	}
	parsedID, err := parsed.ID()
	if err != nil {
		t.Fatalf("parsed ID: %v", err)
	}
	if parsedID != firstID || parsed.Body != voucher.Body ||
		!bytes.Equal(parsed.PayerSignature, voucher.PayerSignature) ||
		!bytes.Equal(parsed.RelaySignature, voucher.RelaySignature) {
		t.Fatal("canonical mutual voucher round trip changed the credential")
	}
}

func TestVoucherSignaturesBindEveryBodyField(t *testing.T) {
	payer := generateIdentity(t)
	relay := generateIdentity(t)
	body := bodyForIdentities(t, payer, relay, 1, 512*1024, Identifier{})
	voucher := mustMutualVoucher(t, body, payer, relay)

	tests := map[string]func(*VoucherBody){
		"version": func(candidate *VoucherBody) { candidate.Version++ },
		"session": func(candidate *VoucherBody) { candidate.SessionID[0] ^= 1 },
		"payer":   func(candidate *VoucherBody) { candidate.PayerNatID[0] ^= 1 },
		"relay":   func(candidate *VoucherBody) { candidate.PayeeRelayID[0] ^= 1 },
		"direction": func(candidate *VoucherBody) {
			candidate.Direction = DirectionPayerInbound
		},
		"sequence": func(candidate *VoucherBody) {
			candidate.Sequence = 2
			candidate.PreviousMutualVoucherID = testIdentifier(80)
		},
		"previous ID": func(candidate *VoucherBody) {
			candidate.Sequence = 2
			candidate.PreviousMutualVoucherID = testIdentifier(81)
		},
		"cumulative bytes":     func(candidate *VoucherBody) { candidate.CumulativeUniqueBytes++ },
		"last RecordID":        func(candidate *VoucherBody) { candidate.LastRecordID[0] ^= 1 },
		"last record sequence": func(candidate *VoucherBody) { candidate.LastRecordSequence++ },
		"record-set digest":    func(candidate *VoucherBody) { candidate.RecordSetDigest[0] ^= 1 },
		"policy digest":        func(candidate *VoucherBody) { candidate.PolicyDigest[0] ^= 1 },
		"authorization":        func(candidate *VoucherBody) { candidate.AuthorizedThroughBytes++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := voucher
			mutate(&candidate.Body)
			if err := candidate.Verify(payer.PublicKey(), relay.PublicKey()); err == nil {
				t.Fatal("tampered voucher verified")
			}
		})
	}
}

func TestVoucherBodyStrictRanges(t *testing.T) {
	valid := deterministicBody()
	tests := map[string]func(*VoucherBody){
		"unsupported version":  func(body *VoucherBody) { body.Version = CurrentVersion + 1 },
		"zero session":         func(body *VoucherBody) { body.SessionID = Identifier{} },
		"zero payer":           func(body *VoucherBody) { body.PayerNatID = Identifier{} },
		"zero Relay":           func(body *VoucherBody) { body.PayeeRelayID = Identifier{} },
		"same payer and Relay": func(body *VoucherBody) { body.PayeeRelayID = body.PayerNatID },
		"invalid direction":    func(body *VoucherBody) { body.Direction = 0 },
		"zero sequence":        func(body *VoucherBody) { body.Sequence = 0 },
		"sequence overflow":    func(body *VoucherBody) { body.Sequence = MaxSequence + 1 },
		"genesis predecessor":  func(body *VoucherBody) { body.PreviousMutualVoucherID = testIdentifier(90) },
		"missing predecessor": func(body *VoucherBody) {
			body.Sequence = 2
			body.PreviousMutualVoucherID = Identifier{}
		},
		"zero cumulative":           func(body *VoucherBody) { body.CumulativeUniqueBytes = 0 },
		"cumulative overflow":       func(body *VoucherBody) { body.CumulativeUniqueBytes = MaxBillableBytes + 1 },
		"zero authorization":        func(body *VoucherBody) { body.AuthorizedThroughBytes = 0 },
		"authorization overflow":    func(body *VoucherBody) { body.AuthorizedThroughBytes = MaxBillableBytes + 1 },
		"over authorization":        func(body *VoucherBody) { body.CumulativeUniqueBytes = body.AuthorizedThroughBytes + 1 },
		"over sequence window":      func(body *VoucherBody) { body.CumulativeUniqueBytes = CumulativeWindowBytes + 1 },
		"zero last RecordID":        func(body *VoucherBody) { body.LastRecordID = Identifier{} },
		"zero last record sequence": func(body *VoucherBody) { body.LastRecordSequence = 0 },
		"zero record set":           func(body *VoucherBody) { body.RecordSetDigest = Digest{} },
		"zero policy":               func(body *VoucherBody) { body.PolicyDigest = Digest{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid body passed validation")
			}
		})
	}

	maximum := valid
	maximum.Sequence = MaxSequence
	maximum.PreviousMutualVoucherID = testIdentifier(91)
	maximum.CumulativeUniqueBytes = MaxBillableBytes
	maximum.AuthorizedThroughBytes = MaxBillableBytes
	if err := maximum.Validate(); err != nil {
		t.Fatalf("maximum valid range rejected: %v", err)
	}
}

func TestValidateSuccessorOneMiBWindow(t *testing.T) {
	payer := generateIdentity(t)
	relay := generateIdentity(t)
	previousBody := bodyForIdentities(t, payer, relay, 1, 512*1024, Identifier{})
	previous := mustMutualVoucher(t, previousBody, payer, relay)
	previousID, err := previous.ID()
	if err != nil {
		t.Fatalf("previous ID: %v", err)
	}
	currentBody := bodyForIdentities(t, payer, relay, 2, 1280*1024, previousID)
	current := mustMutualVoucher(t, currentBody, payer, relay)
	if err := ValidateSuccessor(previous, current); err != nil {
		t.Fatalf("valid successor rejected: %v", err)
	}

	tests := map[string]func(*MutualVoucher){
		"sequence gap":      func(voucher *MutualVoucher) { voucher.Body.Sequence = 3 },
		"wrong predecessor": func(voucher *MutualVoucher) { voucher.Body.PreviousMutualVoucherID[0] ^= 1 },
		"non-increasing cumulative": func(voucher *MutualVoucher) {
			voucher.Body.CumulativeUniqueBytes = previous.Body.CumulativeUniqueBytes
		},
		"window exceeded": func(voucher *MutualVoucher) {
			voucher.Body.CumulativeUniqueBytes = previous.Body.CumulativeUniqueBytes + CumulativeWindowBytes + 1
		},
		"session changed": func(voucher *MutualVoucher) { voucher.Body.SessionID[0] ^= 1 },
		"payer changed":   func(voucher *MutualVoucher) { voucher.Body.PayerNatID[0] ^= 1 },
		"Relay changed":   func(voucher *MutualVoucher) { voucher.Body.PayeeRelayID[0] ^= 1 },
		"direction changed": func(voucher *MutualVoucher) {
			voucher.Body.Direction = DirectionPayerInbound
		},
		"policy changed":        func(voucher *MutualVoucher) { voucher.Body.PolicyDigest[0] ^= 1 },
		"authorization changed": func(voucher *MutualVoucher) { voucher.Body.AuthorizedThroughBytes++ },
		"record set unchanged": func(voucher *MutualVoucher) {
			voucher.Body.RecordSetDigest = previous.Body.RecordSetDigest
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := current
			mutate(&candidate)
			if err := ValidateSuccessor(previous, candidate); err == nil {
				t.Fatal("invalid successor accepted")
			}
		})
	}
}

func TestSignatureIdentityAndCanonicality(t *testing.T) {
	payer := generateIdentity(t)
	relay := generateIdentity(t)
	other := generateIdentity(t)
	body := bodyForIdentities(t, payer, relay, 1, 512*1024, Identifier{})
	payerSignature := mustSignPayer(t, body, payer)

	if _, err := SignPayer(body, other); err == nil {
		t.Fatal("wrong payer identity signed body")
	}
	if err := VerifyPayerSignature(body, payerSignature, other.PublicKey()); err == nil {
		t.Fatal("wrong payer public key verified signature")
	}
	if err := verifyBodySignature(body, payerSignature, payer.PublicKey(), body.PayerNatID, relaySignatureDomain); err == nil {
		t.Fatal("payer signature verified in Relay domain")
	}

	parsed, err := parseCanonicalSignature(payerSignature, true)
	if err != nil {
		t.Fatalf("parse payer signature: %v", err)
	}
	highS := new(big.Int).Sub(elliptic.P256().Params().N, parsed.S)
	malleable, err := asn1.Marshal(ecdsaSignature{R: parsed.R, S: highS})
	if err != nil {
		t.Fatalf("marshal high-S signature: %v", err)
	}
	if err := VerifyPayerSignature(body, malleable, payer.PublicKey()); err == nil {
		t.Fatal("high-S malleable signature verified")
	}
	withTrailingData := append(bytes.Clone(payerSignature), 0)
	if err := VerifyPayerSignature(body, withTrailingData, payer.PublicKey()); err == nil {
		t.Fatal("signature with trailing DER data verified")
	}

	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	if _, err := SignPayer(body, x25519); err == nil {
		t.Fatal("non-P-256 identity signed voucher")
	}
}

func TestCanonicalParsersRejectAmbiguity(t *testing.T) {
	payer := generateIdentity(t)
	relay := generateIdentity(t)
	body := bodyForIdentities(t, payer, relay, 1, 512*1024, Identifier{})
	bodyBytes, err := body.CanonicalBytes()
	if err != nil {
		t.Fatalf("body CanonicalBytes: %v", err)
	}
	for name, encoded := range map[string][]byte{
		"truncated": bodyBytes[:len(bodyBytes)-1],
		"trailing":  append(bytes.Clone(bodyBytes), 0),
		"domain":    append([]byte{'X'}, bodyBytes[1:]...),
	} {
		t.Run("body "+name, func(t *testing.T) {
			if _, err := ParseCanonicalBody(encoded); err == nil {
				t.Fatal("ambiguous body encoding accepted")
			}
		})
	}

	voucher := mustMutualVoucher(t, body, payer, relay)
	encoded, err := voucher.CanonicalBytes()
	if err != nil {
		t.Fatalf("voucher CanonicalBytes: %v", err)
	}
	for name, candidate := range map[string][]byte{
		"truncated": encoded[:len(encoded)-1],
		"trailing":  append(bytes.Clone(encoded), 0),
		"domain":    append([]byte{'X'}, encoded[1:]...),
	} {
		t.Run("mutual "+name, func(t *testing.T) {
			if _, err := ParseCanonicalVoucher(candidate); err == nil {
				t.Fatal("ambiguous mutual encoding accepted")
			}
		})
	}
}

func TestIdentifierTextAndCurrentNodeIDDerivation(t *testing.T) {
	identity := generateIdentity(t)
	nodeID, err := NodeIDFromPublicKey(identity.PublicKey())
	if err != nil {
		t.Fatalf("NodeIDFromPublicKey: %v", err)
	}
	publicHex := hex.EncodeToString(identity.PublicKey().Bytes())
	want := sha256.Sum256([]byte(publicHex))
	if nodeID != Identifier(want) {
		t.Fatalf("NodeID derivation mismatch: got %s want %x", nodeID, want)
	}
	parsed, err := ParseIdentifierHex(nodeID.String())
	if err != nil {
		t.Fatalf("ParseIdentifierHex: %v", err)
	}
	if parsed != nodeID {
		t.Fatal("identifier text round trip changed value")
	}
	if _, err := ParseIdentifierHex(strings.ToUpper(nodeID.String())); err == nil {
		t.Fatal("uppercase non-canonical identifier accepted")
	}
	if _, err := ParseDigestHex("00"); err == nil {
		t.Fatal("short digest accepted")
	}
}

func deterministicBody() VoucherBody {
	return VoucherBody{
		Version:                CurrentVersion,
		SessionID:              testIdentifier(1),
		PayerNatID:             testIdentifier(33),
		PayeeRelayID:           testIdentifier(65),
		Direction:              DirectionPayerOutbound,
		Sequence:               1,
		CumulativeUniqueBytes:  768 * 1024,
		LastRecordID:           testIdentifier(97),
		LastRecordSequence:     12,
		RecordSetDigest:        testDigest(129),
		PolicyDigest:           testDigest(161),
		AuthorizedThroughBytes: 4 * CumulativeWindowBytes,
	}
}

func bodyForIdentities(t *testing.T, payer, relay *ecdh.PrivateKey, sequence, cumulative uint64, previous Identifier) VoucherBody {
	t.Helper()
	payerID, err := NodeIDFromPublicKey(payer.PublicKey())
	if err != nil {
		t.Fatalf("payer NodeID: %v", err)
	}
	relayID, err := NodeIDFromPublicKey(relay.PublicKey())
	if err != nil {
		t.Fatalf("Relay NodeID: %v", err)
	}
	return VoucherBody{
		Version:                 CurrentVersion,
		SessionID:               testIdentifier(1),
		PayerNatID:              payerID,
		PayeeRelayID:            relayID,
		Direction:               DirectionPayerOutbound,
		Sequence:                sequence,
		PreviousMutualVoucherID: previous,
		CumulativeUniqueBytes:   cumulative,
		LastRecordID:            testIdentifier(byte(96 + sequence)),
		LastRecordSequence:      sequence * 10,
		RecordSetDigest:         testDigest(byte(128 + sequence)),
		PolicyDigest:            testDigest(160),
		AuthorizedThroughBytes:  4 * CumulativeWindowBytes,
	}
}

func generateIdentity(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	identity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 identity: %v", err)
	}
	return identity
}

func mustSignPayer(t *testing.T, body VoucherBody, identity *ecdh.PrivateKey) []byte {
	t.Helper()
	signature, err := SignPayer(body, identity)
	if err != nil {
		t.Fatalf("SignPayer: %v", err)
	}
	return signature
}

func mustSignRelay(t *testing.T, body VoucherBody, identity *ecdh.PrivateKey) []byte {
	t.Helper()
	signature, err := SignRelay(body, identity)
	if err != nil {
		t.Fatalf("SignRelay: %v", err)
	}
	return signature
}

func mustMutualVoucher(t *testing.T, body VoucherBody, payer, relay *ecdh.PrivateKey) MutualVoucher {
	t.Helper()
	voucher, err := NewMutualVoucher(body, mustSignPayer(t, body, payer), mustSignRelay(t, body, relay))
	if err != nil {
		t.Fatalf("NewMutualVoucher: %v", err)
	}
	return voucher
}

func testIdentifier(seed byte) Identifier {
	var identifier Identifier
	for index := range identifier {
		identifier[index] = seed + byte(index)
	}
	return identifier
}

func testDigest(seed byte) Digest {
	var digest Digest
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	return digest
}
