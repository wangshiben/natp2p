package billingqueue

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingvoucher"
)

var testLimits = Limits{MaxItems: 64, MaxBytes: 1 << 20}

func TestQueuePersistsIndependentPayerBillingIdentity(t *testing.T) {
	payerIdentity, _ := ecdh.P256().GenerateKey(rand.Reader)
	payerBillingKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	relayIdentity, _ := ecdh.P256().GenerateKey(rand.Reader)
	relayBillingKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payerIdentity.PublicKey())
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relayIdentity.PublicKey())
	body := billingvoucher.VoucherBody{
		Version: billingvoucher.CurrentVersion, SessionID: identifier(90, "billing-session"),
		PayerNatID: payerID, PayeeRelayID: relayID, Direction: billingvoucher.DirectionPayerOutbound,
		Sequence: 1, CumulativeUniqueBytes: 1024,
		LastRecordID: identifier(90, "billing-record"), LastRecordSequence: 1,
		RecordSetDigest: digest(90, "billing-records"), PolicyDigest: billingvoucher.CurrentPolicyDigest(),
		AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
	}
	payerSignature, _ := billingvoucher.SignPayerBilling(body, payerBillingKey)
	relaySignature, _ := billingvoucher.SignRelayBilling(body, relayBillingKey)
	voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		t.Fatal(err)
	}
	payerPublicKey := hex.EncodeToString(payerIdentity.PublicKey().Bytes())
	payerBillingPublicKey := hex.EncodeToString(payerBillingKey.PublicKey().Bytes())
	billingKeyID, _ := admission.BillingKeyIDFromPublicKeyHex(payerBillingPublicKey)
	certificate := &admission.SignedCert{Cert: admission.Cert{
		SubjectNodeID: payerID.String(), SubjectPubKey: payerPublicKey, Role: admission.RoleServer,
		NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix(), Nonce: "01",
		AuthorizationID: admission.NodeAuthorizationID(payerID.String(), billingKeyID),
		BillingKeyID:    billingKeyID, BillingPubKey: payerBillingPublicKey,
	}, Sig: "00"}
	envelope := Envelope{
		Voucher: voucher, PayerPublicKey: payerPublicKey,
		PayerBillingPublicKey: payerBillingPublicKey, PayerCert: certificate,
	}
	path := filepath.Join(t.TempDir(), "billing-envelope.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.EnqueueEnvelope(envelope); err != nil {
		t.Fatalf("enqueue independent billing identity: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	items, err := recovered.SnapshotEnvelopes()
	if err != nil || len(items) != 1 || items[0].PayerBillingPublicKey != payerBillingPublicKey {
		t.Fatalf("recovered billing identity = %+v, err=%v", items, err)
	}
	if err := items[0].Voucher.VerifyBillingSignatures(
		payerBillingKey.PublicKey(), relayBillingKey.PublicKey(),
	); err != nil {
		t.Fatalf("recovered billing voucher signatures: %v", err)
	}
}

func TestQueuePersistsEveryGrowthAndRecoversFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	vouchers := []billingvoucher.MutualVoucher{
		makeVoucher(t, 1),
		makeVoucher(t, 2),
		makeVoucher(t, 3),
	}

	for index, voucher := range vouchers {
		if err := queue.Enqueue(voucher); err != nil {
			t.Fatalf("Enqueue %d: %v", index, err)
		}
		snapshot, err := Open(path, testLimits)
		if err != nil {
			t.Fatalf("Open snapshot %d: %v", index, err)
		}
		if snapshot.Len() != index+1 {
			t.Fatalf("persisted length after enqueue %d = %d, want %d", index, snapshot.Len(), index+1)
		}
		if err := snapshot.Close(); err != nil {
			t.Fatalf("Close snapshot %d: %v", index, err)
		}
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recovered, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open recovered queue: %v", err)
	}
	defer recovered.Close()
	for index, expected := range vouchers {
		actual, err := recovered.Peek()
		if err != nil {
			t.Fatalf("Peek %d: %v", index, err)
		}
		assertSameVoucher(t, actual, expected)
		expectedID := voucherID(t, expected)
		if err := recovered.Remove(expectedID); err != nil {
			t.Fatalf("Remove %d: %v", index, err)
		}
	}
	if _, err := recovered.Peek(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Peek empty error = %v, want ErrEmpty", err)
	}
}

func TestQueueRemoveChecksHeadAndPersistsDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	first := makeVoucher(t, 11)
	second := makeVoucher(t, 12)
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := queue.Enqueue(first); err != nil {
		t.Fatalf("Enqueue first: %v", err)
	}
	if err := queue.Enqueue(second); err != nil {
		t.Fatalf("Enqueue second: %v", err)
	}
	if err := queue.Remove(voucherID(t, second)); !errors.Is(err, ErrHeadMismatch) {
		t.Fatalf("out-of-order Remove error = %v, want ErrHeadMismatch", err)
	}
	if err := queue.Remove(voucherID(t, first)); err != nil {
		t.Fatalf("Remove first: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recovered, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open after first deletion: %v", err)
	}
	if recovered.Len() != 1 {
		t.Fatalf("length after persisted deletion = %d, want 1", recovered.Len())
	}
	remaining, err := recovered.Peek()
	if err != nil {
		t.Fatalf("Peek remaining: %v", err)
	}
	assertSameVoucher(t, remaining, second)
	if err := recovered.Remove(voucherID(t, second)); err != nil {
		t.Fatalf("Remove second: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatalf("Close recovered: %v", err)
	}

	empty, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open after final deletion: %v", err)
	}
	defer empty.Close()
	if empty.Len() != 0 {
		t.Fatalf("persisted empty queue length = %d, want 0", empty.Len())
	}
}

func TestQueueCapacityLimitsLeavePersistentStateUnchanged(t *testing.T) {
	first := makeVoucher(t, 21)
	second := makeVoucher(t, 22)
	third := makeVoucher(t, 23)

	t.Run("items", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wait-submit.queue")
		limits := Limits{MaxItems: 2, MaxBytes: testLimits.MaxBytes}
		queue, err := Open(path, limits)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := queue.Enqueue(first); err != nil {
			t.Fatalf("Enqueue first: %v", err)
		}
		if err := queue.Enqueue(second); err != nil {
			t.Fatalf("Enqueue second: %v", err)
		}
		if err := queue.Enqueue(third); !errors.Is(err, ErrFull) {
			t.Fatalf("third Enqueue error = %v, want ErrFull", err)
		}
		queue.Close()
		recovered, err := Open(path, limits)
		if err != nil {
			t.Fatalf("Open recovered: %v", err)
		}
		defer recovered.Close()
		if recovered.Len() != 2 {
			t.Fatalf("persisted length = %d, want 2", recovered.Len())
		}
	})

	t.Run("bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wait-submit.queue")
		firstBytes, _, err := encodeEnvelope(Envelope{Voucher: first}, false)
		if err != nil {
			t.Fatalf("encodeEnvelope: %v", err)
		}
		limits := Limits{MaxItems: 2, MaxBytes: uint64(len(firstBytes))}
		queue, err := Open(path, limits)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := queue.Enqueue(first); err != nil {
			t.Fatalf("Enqueue first: %v", err)
		}
		if queue.Bytes() != uint64(len(firstBytes)) {
			t.Fatalf("Bytes = %d, want %d", queue.Bytes(), len(firstBytes))
		}
		if err := queue.Enqueue(second); !errors.Is(err, ErrFull) {
			t.Fatalf("second Enqueue error = %v, want ErrFull", err)
		}
		queue.Close()
		recovered, err := Open(path, limits)
		if err != nil {
			t.Fatalf("Open recovered: %v", err)
		}
		defer recovered.Close()
		if recovered.Len() != 1 || recovered.Bytes() != uint64(len(firstBytes)) {
			t.Fatalf("recovered state = (%d items, %d bytes), want (1, %d)", recovered.Len(), recovered.Bytes(), len(firstBytes))
		}
	})
}

func TestQueuePayerQuotaIsolatesIndependentPayersAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	limits := Limits{
		MaxItems: 4, MaxBytes: 1 << 20,
		MaxItemsPerPayer: 2, MaxBytesPerPayer: 1 << 20,
	}
	queue, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	chain := makeVoucherChain(t, 24, 3)
	for index := 0; index < 2; index++ {
		if err := queue.Enqueue(chain[index]); err != nil {
			t.Fatalf("enqueue payer item %d: %v", index, err)
		}
	}
	if err := queue.Enqueue(chain[2]); !errors.Is(err, ErrPayerFull) {
		t.Fatalf("payer quota error = %v, want ErrPayerFull", err)
	}
	independent := makeVoucher(t, 25)
	if err := queue.Enqueue(independent); err != nil {
		t.Fatalf("independent payer was blocked by another payer quota: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if err := recovered.Enqueue(chain[2]); !errors.Is(err, ErrPayerFull) {
		t.Fatalf("reopened payer quota error = %v, want ErrPayerFull", err)
	}
	if recovered.Len() != 3 {
		t.Fatalf("reopened queue length = %d, want 3", recovered.Len())
	}
}

func TestQueueCorruptionFailsClosedWithoutClearingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := queue.Enqueue(makeVoucher(t, 31)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	queue.Close()

	corrupt, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	corrupt[len(corrupt)-1] ^= 0xff
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile corrupt queue: %v", err)
	}
	if _, err := Open(path, testLimits); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open corrupt queue error = %v, want ErrCorrupt", err)
	}
	stillCorrupt, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after failed Open: %v", err)
	}
	if !bytes.Equal(stillCorrupt, corrupt) {
		t.Fatal("failed Open modified or cleared the corrupt queue")
	}
}

func TestQueueIncompleteTailRecoversLastCompleteFrame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first := makeVoucher(t, 32)
	second := makeVoucher(t, 33)
	if err := queue.Enqueue(first); err != nil {
		t.Fatalf("Enqueue first: %v", err)
	}
	firstState, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat first frame: %v", err)
	}
	if err := queue.Enqueue(second); err != nil {
		t.Fatalf("Enqueue second: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	complete, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if int64(len(complete)) <= firstState.Size()+8 {
		t.Fatal("second frame is unexpectedly short")
	}
	if err := os.Truncate(path, int64(len(complete)-8)); err != nil {
		t.Fatalf("Truncate incomplete tail: %v", err)
	}

	recovered, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open with incomplete tail: %v", err)
	}
	defer recovered.Close()
	if recovered.Len() != 1 {
		t.Fatalf("recovered length = %d, want 1", recovered.Len())
	}
	actual, err := recovered.Peek()
	if err != nil {
		t.Fatalf("Peek recovered: %v", err)
	}
	assertSameVoucher(t, actual, first)
	truncatedState, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat recovered WAL: %v", err)
	}
	if truncatedState.Size() != firstState.Size() {
		t.Fatalf("recovered WAL size = %d, want %d", truncatedState.Size(), firstState.Size())
	}
}

func TestQueueMiddleFrameCorruptionFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for seed := byte(34); seed < 37; seed++ {
		if err := queue.Enqueue(makeVoucher(t, seed)); err != nil {
			t.Fatalf("Enqueue %d: %v", seed, err)
		}
	}
	queue.Close()
	corrupt, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	offset := len(fileDomain) + framePrefixSize + 1 + sha256.Size + 8
	if offset >= len(corrupt)-sha256.Size {
		t.Fatal("first WAL frame is unexpectedly short")
	}
	corrupt[offset] ^= 0xff
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile corrupt WAL: %v", err)
	}
	if _, err := Open(path, testLimits); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open corrupt middle frame error = %v, want ErrCorrupt", err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after failed Open: %v", err)
	}
	if !bytes.Equal(unchanged, corrupt) {
		t.Fatal("failed Open modified a checksum-invalid complete frame")
	}
}

func TestQueueRejectsTruncatedExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	if err := os.WriteFile(path, []byte("truncated"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Open(path, testLimits); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open truncated queue error = %v, want ErrCorrupt", err)
	}
}

func TestQueueConcurrentEnqueueIsRaceFreeAndDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	const count = 12
	vouchers := make([]billingvoucher.MutualVoucher, count)
	for index := range vouchers {
		vouchers[index] = makeVoucher(t, byte(50+index))
	}

	var waitGroup sync.WaitGroup
	errorsByIndex := make([]error, count)
	for index := range vouchers {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			errorsByIndex[index] = queue.Enqueue(vouchers[index])
		}(index)
	}
	waitGroup.Wait()
	for index, err := range errorsByIndex {
		if err != nil {
			t.Fatalf("Enqueue %d: %v", index, err)
		}
	}
	if queue.Len() != count {
		t.Fatalf("length = %d, want %d", queue.Len(), count)
	}
	queue.Close()
	recovered, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open recovered: %v", err)
	}
	defer recovered.Close()
	if recovered.Len() != count {
		t.Fatalf("recovered length = %d, want %d", recovered.Len(), count)
	}
}

func TestQueuePeekReturnsSignatureCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer queue.Close()
	voucher := makeVoucher(t, 71)
	if err := queue.Enqueue(voucher); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	first, err := queue.Peek()
	if err != nil {
		t.Fatalf("Peek first: %v", err)
	}
	first.PayerSignature[0] ^= 0xff
	first.RelaySignature[0] ^= 0xff
	second, err := queue.Peek()
	if err != nil {
		t.Fatalf("Peek second: %v", err)
	}
	assertSameVoucher(t, second, voucher)
}

func TestQueueSnapshotIsReadOnlyFIFODeepCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer queue.Close()
	vouchers := []billingvoucher.MutualVoucher{
		makeVoucher(t, 81),
		makeVoucher(t, 82),
		makeVoucher(t, 83),
	}
	for index, voucher := range vouchers {
		if err := queue.Enqueue(voucher); err != nil {
			t.Fatalf("Enqueue %d: %v", index, err)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile before Snapshot: %v", err)
	}

	snapshot, err := queue.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot) != len(vouchers) {
		t.Fatalf("Snapshot length = %d, want %d", len(snapshot), len(vouchers))
	}
	for index := range vouchers {
		assertSameVoucher(t, snapshot[index], vouchers[index])
	}
	snapshot[0].PayerSignature[0] ^= 0xff
	snapshot[1].RelaySignature[0] ^= 0xff

	secondSnapshot, err := queue.Snapshot()
	if err != nil {
		t.Fatalf("second Snapshot: %v", err)
	}
	for index := range vouchers {
		assertSameVoucher(t, secondSnapshot[index], vouchers[index])
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after Snapshot: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("Snapshot modified the persistent queue file")
	}
}

func TestQueueSnapshotEmptyAndClosed(t *testing.T) {
	queue, err := Open(filepath.Join(t.TempDir(), "wait-submit.queue"), testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	snapshot, err := queue.Snapshot()
	if err != nil {
		t.Fatalf("empty Snapshot: %v", err)
	}
	if snapshot == nil || len(snapshot) != 0 {
		t.Fatalf("empty Snapshot = %#v, want non-nil empty slice", snapshot)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := queue.Snapshot(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Snapshot after Close error = %v, want ErrClosed", err)
	}
}

func TestQueueChannelHeadsAllowCrossPayerProgressWithoutReorderingChannel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wait-submit.queue")
	queue, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	firstChannel := makeVoucherChain(t, 91, 2)
	secondChannel := makeVoucherChain(t, 92, 1)
	for _, voucher := range []billingvoucher.MutualVoucher{firstChannel[0], firstChannel[1], secondChannel[0]} {
		if err := queue.Enqueue(voucher); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	heads, err := queue.ChannelHeads()
	if err != nil {
		t.Fatalf("ChannelHeads: %v", err)
	}
	if len(heads) != 2 {
		t.Fatalf("channel heads = %d, want 2", len(heads))
	}
	assertSameVoucher(t, heads[0].Voucher, firstChannel[0])
	assertSameVoucher(t, heads[1].Voucher, secondChannel[0])
	if err := queue.RemoveChannelHead(voucherID(t, firstChannel[1])); !errors.Is(err, ErrHeadMismatch) {
		t.Fatalf("RemoveChannelHead successor error = %v, want ErrHeadMismatch", err)
	}
	if err := queue.RemoveChannelHead(voucherID(t, secondChannel[0])); err != nil {
		t.Fatalf("RemoveChannelHead independent payer: %v", err)
	}
	queue.Close()

	recovered, err := Open(path, testLimits)
	if err != nil {
		t.Fatalf("Open recovered: %v", err)
	}
	defer recovered.Close()
	remaining, err := recovered.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("remaining length = %d, want 2", len(remaining))
	}
	assertSameVoucher(t, remaining[0], firstChannel[0])
	assertSameVoucher(t, remaining[1], firstChannel[1])
	if err := recovered.RemoveChannelHead(voucherID(t, firstChannel[0])); err != nil {
		t.Fatalf("RemoveChannelHead predecessor: %v", err)
	}
	if err := recovered.RemoveChannelHead(voucherID(t, firstChannel[1])); err != nil {
		t.Fatalf("RemoveChannelHead successor: %v", err)
	}
}

func makeVoucher(t *testing.T, seed byte) billingvoucher.MutualVoucher {
	t.Helper()
	payer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Generate payer identity: %v", err)
	}
	relay, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Generate Relay identity: %v", err)
	}
	payerID, err := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	if err != nil {
		t.Fatalf("payer NodeID: %v", err)
	}
	relayID, err := billingvoucher.NodeIDFromPublicKey(relay.PublicKey())
	if err != nil {
		t.Fatalf("Relay NodeID: %v", err)
	}
	body := billingvoucher.VoucherBody{
		Version:                billingvoucher.CurrentVersion,
		SessionID:              identifier(seed, "session"),
		PayerNatID:             payerID,
		PayeeRelayID:           relayID,
		Direction:              billingvoucher.DirectionPayerOutbound,
		Sequence:               1,
		CumulativeUniqueBytes:  uint64(seed) + 1,
		LastRecordID:           identifier(seed, "record"),
		LastRecordSequence:     uint64(seed) + 1,
		RecordSetDigest:        digest(seed, "records"),
		PolicyDigest:           digest(seed, "policy"),
		AuthorizedThroughBytes: billingvoucher.CumulativeWindowBytes,
	}
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

func makeVoucherChain(t *testing.T, seed byte, count int) []billingvoucher.MutualVoucher {
	t.Helper()
	payer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Generate payer identity: %v", err)
	}
	relay, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Generate Relay identity: %v", err)
	}
	payerID, _ := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	relayID, _ := billingvoucher.NodeIDFromPublicKey(relay.PublicKey())
	sessionID := identifier(seed, "chain-session")
	result := make([]billingvoucher.MutualVoucher, 0, count)
	var previous billingvoucher.Identifier
	var cumulative uint64
	for index := 0; index < count; index++ {
		cumulative += uint64(index + 1)
		body := billingvoucher.VoucherBody{
			Version: billingvoucher.CurrentVersion, SessionID: sessionID,
			PayerNatID: payerID, PayeeRelayID: relayID,
			Direction: billingvoucher.DirectionPayerOutbound,
			Sequence:  uint64(index + 1), PreviousMutualVoucherID: previous,
			CumulativeUniqueBytes:  cumulative,
			LastRecordID:           identifier(seed+byte(index), "chain-record"),
			LastRecordSequence:     uint64(index + 1),
			RecordSetDigest:        digest(seed+byte(index), "chain-records"),
			PolicyDigest:           billingvoucher.CurrentPolicyDigest(),
			AuthorizedThroughBytes: billingvoucher.MaxBillableBytes,
		}
		payerSignature, err := billingvoucher.SignPayer(body, payer)
		if err != nil {
			t.Fatalf("SignPayer %d: %v", index, err)
		}
		relaySignature, err := billingvoucher.SignRelay(body, relay)
		if err != nil {
			t.Fatalf("SignRelay %d: %v", index, err)
		}
		voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
		if err != nil {
			t.Fatalf("NewMutualVoucher %d: %v", index, err)
		}
		previous, err = voucher.ID()
		if err != nil {
			t.Fatalf("voucher ID %d: %v", index, err)
		}
		result = append(result, voucher)
	}
	return result
}

func identifier(seed byte, label string) billingvoucher.Identifier {
	return sha256.Sum256(append([]byte(label), seed))
}

func digest(seed byte, label string) billingvoucher.Digest {
	return sha256.Sum256(append([]byte(label), seed))
}

func voucherID(t *testing.T, voucher billingvoucher.MutualVoucher) billingvoucher.Identifier {
	t.Helper()
	id, err := voucher.ID()
	if err != nil {
		t.Fatalf("voucher ID: %v", err)
	}
	return id
}

func assertSameVoucher(t *testing.T, actual, expected billingvoucher.MutualVoucher) {
	t.Helper()
	actualBytes, err := actual.CanonicalBytes()
	if err != nil {
		t.Fatalf("actual CanonicalBytes: %v", err)
	}
	expectedBytes, err := expected.CanonicalBytes()
	if err != nil {
		t.Fatalf("expected CanonicalBytes: %v", err)
	}
	if !bytes.Equal(actualBytes, expectedBytes) {
		t.Fatal("voucher changed across queue operation")
	}
}
