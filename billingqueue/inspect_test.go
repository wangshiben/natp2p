package billingqueue

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingvoucher"
)

func TestInspectActiveWALIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer queue.Close()
	for seed := byte(1); seed <= 2; seed++ {
		if err := queue.Enqueue(makeVoucher(t, seed)); err != nil {
			t.Fatalf("Enqueue %d: %v", seed, err)
		}
	}
	before := captureInspectionFile(t, path)

	inspection, err := Inspect(path, testLimits)
	if err != nil {
		t.Fatalf("Inspect active WAL: %v", err)
	}
	if inspection.Schema != WALInspectionSchema || inspection.Depth != 2 ||
		inspection.PayloadBytes != queue.Bytes() || inspection.IncompleteTail {
		t.Fatalf("inspection = %#v, want complete WAL with depth 2 and %d payload bytes", inspection, queue.Bytes())
	}
	assertInspectionFileUnchanged(t, path, before)

	if err := queue.Enqueue(makeVoucher(t, 3)); err != nil {
		t.Fatalf("Enqueue after Inspect: %v", err)
	}
	afterGrowth, err := Inspect(path, testLimits)
	if err != nil {
		t.Fatalf("Inspect after active growth: %v", err)
	}
	if afterGrowth.Depth != 3 || afterGrowth.PayloadBytes != queue.Bytes() {
		t.Fatalf("inspection after growth = %#v, want depth 3 and %d payload bytes", afterGrowth, queue.Bytes())
	}
}

func TestInspectIncompleteTailDoesNotTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first := makeVoucher(t, 11)
	if err := queue.Enqueue(first); err != nil {
		t.Fatalf("Enqueue first: %v", err)
	}
	firstPayloadBytes := queue.Bytes()
	if err := queue.Enqueue(makeVoucher(t, 12)); err != nil {
		t.Fatalf("Enqueue second: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	complete, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile complete WAL: %v", err)
	}
	if err := os.Truncate(path, int64(len(complete)-8)); err != nil {
		t.Fatalf("Truncate test tail: %v", err)
	}
	before := captureInspectionFile(t, path)

	inspection, err := Inspect(path, testLimits)
	if err != nil {
		t.Fatalf("Inspect incomplete tail: %v", err)
	}
	if inspection.Schema != WALInspectionSchema || inspection.Depth != 1 ||
		inspection.PayloadBytes != firstPayloadBytes || !inspection.IncompleteTail {
		t.Fatalf("inspection = %#v, want one live item and an incomplete tail", inspection)
	}
	assertInspectionFileUnchanged(t, path, before)
}

func TestInspectCompleteFrameCorruptionFailsClosedWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := queue.Enqueue(makeVoucher(t, 21)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	corrupt, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	corrupt[len(corrupt)-1] ^= 0xff
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile corrupt WAL: %v", err)
	}
	before := captureInspectionFile(t, path)

	if _, err := Inspect(path, testLimits); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Inspect corrupt WAL error = %v, want ErrCorrupt", err)
	}
	assertInspectionFileUnchanged(t, path, before)
}

func TestInspectLegacyQueueDoesNotMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	voucher := makeVoucher(t, 31)
	payload, _, err := encodeEnvelope(Envelope{Voucher: voucher}, false)
	if err != nil {
		t.Fatalf("encodeEnvelope: %v", err)
	}
	encoded := make([]byte, 0, len(legacyFileDomain)+8+4+len(payload)+sha256.Size)
	encoded = append(encoded, legacyFileDomain...)
	count := make([]byte, 8)
	binary.BigEndian.PutUint64(count, 1)
	encoded = append(encoded, count...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)))
	encoded = append(encoded, length...)
	encoded = append(encoded, payload...)
	checksum := sha256.Sum256(encoded)
	encoded = append(encoded, checksum[:]...)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile legacy queue: %v", err)
	}
	before := captureInspectionFile(t, path)

	inspection, err := Inspect(path, testLimits)
	if err != nil {
		t.Fatalf("Inspect legacy queue: %v", err)
	}
	if inspection.Schema != LegacyInspectionSchema || inspection.Depth != 1 ||
		inspection.PayloadBytes != uint64(len(payload)) || inspection.IncompleteTail {
		t.Fatalf("legacy inspection = %#v", inspection)
	}
	assertInspectionFileUnchanged(t, path, before)
}

func TestInspectTargetAuthorizesCompleteVerifiedLiveChains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	payer := generateInspectionIdentity(t)
	relay := generateInspectionIdentity(t)
	cumulative := []uint64{962632, 1924868, 2887104, 3849340, 4811576}
	chain := makeInspectionVoucherChain(t, payer, relay, identifier(41, "target-session"), cumulative)
	for index, voucher := range chain {
		if err := queue.EnqueueEnvelope(inspectionEnvelope(voucher, payer)); err != nil {
			t.Fatalf("EnqueueEnvelope %d: %v", index, err)
		}
	}
	if err := queue.Enqueue(makeVoucher(t, 42)); err != nil {
		t.Fatalf("Enqueue unrelated voucher: %v", err)
	}
	before := captureInspectionFile(t, path)
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relay.PublicKey())

	inspection, err := InspectWithOptions(path, testLimits, InspectionOptions{
		PayerID: payerID, RelayID: relayID, RelayPublicKey: relay.PublicKey(),
	})
	if err != nil {
		t.Fatalf("InspectWithOptions: %v", err)
	}
	if inspection.Depth != 6 || inspection.ChannelDepth != 5 ||
		inspection.AuthorizedBytes != cumulative[len(cumulative)-1] || inspection.SessionCount != 1 {
		t.Fatalf("target inspection = %#v", inspection)
	}
	assertInspectionFileUnchanged(t, path, before)
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestInspectTargetSumsIndependentCompleteChannels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer queue.Close()
	payer := generateInspectionIdentity(t)
	relay := generateInspectionIdentity(t)
	first := makeInspectionVoucherChain(t, payer, relay, identifier(51, "session-a"), []uint64{700000, 1500000})
	second := makeInspectionVoucherChain(t, payer, relay, identifier(52, "session-b"), []uint64{500000})
	for _, voucher := range []billingvoucher.MutualVoucher{first[0], second[0], first[1]} {
		if err := queue.EnqueueEnvelope(inspectionEnvelope(voucher, payer)); err != nil {
			t.Fatalf("EnqueueEnvelope: %v", err)
		}
	}
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	inspection, err := InspectWithOptions(path, testLimits, InspectionOptions{
		PayerID: payerID, RelayPublicKey: relay.PublicKey(),
	})
	if err != nil {
		t.Fatalf("InspectWithOptions: %v", err)
	}
	if inspection.ChannelDepth != 3 || inspection.AuthorizedBytes != 2000000 || inspection.SessionCount != 2 {
		t.Fatalf("multi-channel inspection = %#v", inspection)
	}
}

func TestInspectTargetCanUseExplicitPayerIdentityForLegacyEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer queue.Close()
	payer := generateInspectionIdentity(t)
	relay := generateInspectionIdentity(t)
	chain := makeInspectionVoucherChain(t, payer, relay, identifier(61, "legacy-envelope"), []uint64{800000})
	if err := queue.Enqueue(chain[0]); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	inspection, err := InspectWithOptions(path, testLimits, InspectionOptions{
		PayerPublicKey: payer.PublicKey(), RelayPublicKey: relay.PublicKey(),
	})
	if err != nil {
		t.Fatalf("InspectWithOptions: %v", err)
	}
	if inspection.ChannelDepth != 1 || inspection.AuthorizedBytes != 800000 || inspection.SessionCount != 1 {
		t.Fatalf("explicit identity inspection = %#v", inspection)
	}
}

func TestInspectTargetFailsClosedOnInvalidProof(t *testing.T) {
	tests := map[string]func(*testing.T, *ecdh.PrivateKey, *ecdh.PrivateKey) []billingvoucher.MutualVoucher{
		"invalid payer signature": func(t *testing.T, payer, relay *ecdh.PrivateKey) []billingvoucher.MutualVoucher {
			chain := makeInspectionVoucherChain(t, payer, relay, identifier(70, "payer-signature"), []uint64{600000})
			other := makeInspectionVoucherChain(t, payer, relay, identifier(69, "other-payer-signature"), []uint64{600000})
			chain[0].PayerSignature = bytes.Clone(other[0].PayerSignature)
			return chain
		},
		"invalid Relay signature": func(t *testing.T, payer, relay *ecdh.PrivateKey) []billingvoucher.MutualVoucher {
			chain := makeInspectionVoucherChain(t, payer, relay, identifier(71, "signature"), []uint64{600000})
			other := makeInspectionVoucherChain(t, payer, relay, identifier(72, "other-signature"), []uint64{600000})
			chain[0].RelaySignature = bytes.Clone(other[0].RelaySignature)
			return chain
		},
		"missing genesis": func(t *testing.T, payer, relay *ecdh.PrivateKey) []billingvoucher.MutualVoucher {
			chain := makeInspectionVoucherChain(t, payer, relay, identifier(73, "missing-genesis"), []uint64{500000, 1200000})
			return chain[1:]
		},
		"sequence gap": func(t *testing.T, payer, relay *ecdh.PrivateKey) []billingvoucher.MutualVoucher {
			first := makeInspectionVoucherChain(t, payer, relay, identifier(74, "sequence-gap"), []uint64{500000})[0]
			firstID, _ := first.ID()
			third := makeInspectionVoucher(t, payer, relay, first.Body.SessionID, 3, 1300000, firstID)
			return []billingvoucher.MutualVoucher{first, third}
		},
		"window exceeded": func(t *testing.T, payer, relay *ecdh.PrivateKey) []billingvoucher.MutualVoucher {
			first := makeInspectionVoucherChain(t, payer, relay, identifier(75, "window"), []uint64{500000})[0]
			firstID, _ := first.ID()
			second := makeInspectionVoucher(t, payer, relay, first.Body.SessionID, 2, 1600000, firstID)
			return []billingvoucher.MutualVoucher{first, second}
		},
		"unsupported direction": func(t *testing.T, payer, relay *ecdh.PrivateKey) []billingvoucher.MutualVoucher {
			voucher := makeInspectionVoucherChain(t, payer, relay, identifier(76, "direction"), []uint64{500000})[0]
			voucher.Body.Direction = billingvoucher.DirectionPayerInbound
			return []billingvoucher.MutualVoucher{resignInspectionVoucher(t, voucher.Body, payer, relay)}
		},
		"unsupported policy": func(t *testing.T, payer, relay *ecdh.PrivateKey) []billingvoucher.MutualVoucher {
			voucher := makeInspectionVoucherChain(t, payer, relay, identifier(77, "policy"), []uint64{500000})[0]
			voucher.Body.PolicyDigest = digest(77, "unsupported-policy")
			return []billingvoucher.MutualVoucher{resignInspectionVoucher(t, voucher.Body, payer, relay)}
		},
		"unsupported authorization": func(t *testing.T, payer, relay *ecdh.PrivateKey) []billingvoucher.MutualVoucher {
			voucher := makeInspectionVoucherChain(t, payer, relay, identifier(78, "authorization"), []uint64{500000})[0]
			voucher.Body.AuthorizedThroughBytes = 2 * billingvoucher.CumulativeWindowBytes
			return []billingvoucher.MutualVoucher{resignInspectionVoucher(t, voucher.Body, payer, relay)}
		},
	}
	for name, makeChain := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wait-submit.queue")
			queue, err := Open(path, testLimits)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			payer := generateInspectionIdentity(t)
			relay := generateInspectionIdentity(t)
			for index, voucher := range makeChain(t, payer, relay) {
				if err := queue.EnqueueEnvelope(inspectionEnvelope(voucher, payer)); err != nil {
					t.Fatalf("EnqueueEnvelope %d: %v", index, err)
				}
			}
			if err := queue.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			payerID, _ := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
			if _, err := InspectWithOptions(path, testLimits, InspectionOptions{
				PayerID: payerID, RelayPublicKey: relay.PublicKey(),
			}); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("InspectWithOptions error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestInspectTargetRequiresBoundVerificationIdentities(t *testing.T) {
	payer := generateInspectionIdentity(t)
	otherPayer := generateInspectionIdentity(t)
	relay := generateInspectionIdentity(t)
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	otherRelay := generateInspectionIdentity(t)
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relay.PublicKey())

	if _, _, err := normalizeInspectionOptions(InspectionOptions{PayerID: payerID}); err == nil {
		t.Fatal("targeted options without Relay verification identity were accepted")
	}
	if _, _, err := normalizeInspectionOptions(InspectionOptions{
		PayerID: payerID, PayerPublicKey: otherPayer.PublicKey(), RelayPublicKey: relay.PublicKey(),
	}); err == nil {
		t.Fatal("mismatched payer identity was accepted")
	}
	if _, _, err := normalizeInspectionOptions(InspectionOptions{
		PayerID: payerID, RelayID: relayID, RelayPublicKey: otherRelay.PublicKey(),
	}); err == nil {
		t.Fatal("mismatched Relay identity was accepted")
	}
}

func generateInspectionIdentity(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	identity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return identity
}

func makeInspectionVoucherChain(t *testing.T, payer, relay *ecdh.PrivateKey, session billingvoucher.Identifier, cumulative []uint64) []billingvoucher.MutualVoucher {
	t.Helper()
	chain := make([]billingvoucher.MutualVoucher, 0, len(cumulative))
	var previous billingvoucher.Identifier
	for index, bytes := range cumulative {
		voucher := makeInspectionVoucher(t, payer, relay, session, uint64(index+1), bytes, previous)
		previous, _ = voucher.ID()
		chain = append(chain, voucher)
	}
	return chain
}

func makeInspectionVoucher(t *testing.T, payer, relay *ecdh.PrivateKey, session billingvoucher.Identifier, sequence, cumulative uint64, previous billingvoucher.Identifier) billingvoucher.MutualVoucher {
	t.Helper()
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relay.PublicKey())
	body := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: session,
		PayerNatID: payerID, PayeeRelayID: relayID,
		Direction: billingvoucher.DirectionPayerOutbound, Sequence: sequence,
		PreviousMutualVoucherID: previous, CumulativeUniqueBytes: cumulative,
		LastRecordID: identifier(byte(80+sequence), "inspection-record"), LastRecordSequence: sequence,
		RecordSetDigest: digest(byte(100+sequence), "inspection-record-set"),
		PolicyDigest:    billingvoucher.CurrentPolicyDigest(), AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	return resignInspectionVoucher(t, body, payer, relay)
}

func resignInspectionVoucher(t *testing.T, body billingvoucher.VoucherBody, payer, relay *ecdh.PrivateKey) billingvoucher.MutualVoucher {
	t.Helper()
	payerSignature, err := billingvoucher.SignPayer(body, payer)
	if err != nil {
		t.Fatalf("SignPayer: %v", err)
	}
	relaySignature, err := billingvoucher.SignRelay(body, relay)
	if err != nil {
		t.Fatalf("SignRelay: %v", err)
	}
	voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		t.Fatalf("NewMutualVoucher: %v", err)
	}
	return voucher
}

func inspectionEnvelope(voucher billingvoucher.MutualVoucher, payer *ecdh.PrivateKey) Envelope {
	publicKey := hex.EncodeToString(payer.PublicKey().Bytes())
	return Envelope{Voucher: voucher, PayerPublicKey: publicKey, PayerCert: &admission.SignedCert{
		Cert: admission.Cert{
			SubjectNodeID: admission.NodeIDFromPubKeyHex(publicKey), SubjectPubKey: publicKey,
			Role: admission.RoleServer, NotBefore: time.Now().Add(-time.Minute).Unix(),
			NotAfter: time.Now().Add(time.Hour).Unix(), Nonce: "01", Issuer: "inspect-test",
		},
		Sig: "00",
	}}
}

type inspectionFileSnapshot struct {
	contents []byte
	mode     os.FileMode
	size     int64
	modTime  int64
}

func captureInspectionFile(t *testing.T, path string) inspectionFileSnapshot {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile snapshot: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat snapshot: %v", err)
	}
	return inspectionFileSnapshot{
		contents: contents,
		mode:     info.Mode(),
		size:     info.Size(),
		modTime:  info.ModTime().UnixNano(),
	}
}

func assertInspectionFileUnchanged(t *testing.T, path string, before inspectionFileSnapshot) {
	t.Helper()
	after := captureInspectionFile(t, path)
	if !bytes.Equal(after.contents, before.contents) || after.mode != before.mode ||
		after.size != before.size || after.modTime != before.modTime {
		t.Fatal("Inspect modified, replaced, truncated, or migrated the persistent queue")
	}
}
