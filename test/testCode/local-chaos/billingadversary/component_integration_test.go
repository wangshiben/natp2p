package billingadversary

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"bnfs_p2p/billingvoucher"
)

type referenceLedger struct {
	payer          *ecdh.PublicKey
	relay          *ecdh.PublicKey
	last           *billingvoucher.MutualVoucher
	seen           map[billingvoucher.Identifier]struct{}
	settledBytes   uint64
	securityFrozen bool
}

func newReferenceLedger(payer, relay *ecdh.PublicKey) *referenceLedger {
	return &referenceLedger{
		payer: payer,
		relay: relay,
		seen:  make(map[billingvoucher.Identifier]struct{}),
	}
}

func (ledger *referenceLedger) apply(voucher billingvoucher.MutualVoucher) (uint64, error) {
	if err := voucher.Verify(ledger.payer, ledger.relay); err != nil {
		return 0, err
	}
	voucherID, err := voucher.ID()
	if err != nil {
		return 0, err
	}
	if _, exists := ledger.seen[voucherID]; exists {
		return 0, nil
	}
	if ledger.last == nil {
		if voucher.Body.Sequence != 1 {
			return 0, errors.New("first accepted voucher must have sequence one")
		}
	} else {
		if voucher.Body.Sequence == ledger.last.Body.Sequence {
			ledger.securityFrozen = true
			return 0, errors.New("same sequence has a different voucher ID")
		}
		if err := billingvoucher.ValidateSuccessor(*ledger.last, voucher); err != nil {
			return 0, err
		}
	}
	previousBytes := ledger.settledBytes
	delta := voucher.Body.CumulativeUniqueBytes - previousBytes
	ledger.settledBytes = voucher.Body.CumulativeUniqueBytes
	ledger.seen[voucherID] = struct{}{}
	copy := voucher
	ledger.last = &copy
	return delta, nil
}

func TestProtocolComponentRejectsMaliciousMutations(t *testing.T) {
	payer := generateIdentity(t)
	relay := generateIdentity(t)
	genesis := signedVoucher(t, voucherBody(t, payer, relay, 1, 256*1024, billingvoucher.Identifier{}), payer, relay)
	genesisID, err := genesis.ID()
	if err != nil {
		t.Fatalf("genesis ID: %v", err)
	}
	successorBody := voucherBody(t, payer, relay, 2, 512*1024, genesisID)
	successor := signedVoucher(t, successorBody, payer, relay)

	t.Run("relay usage inflation", func(t *testing.T) {
		candidate := successor
		candidate.Body.CumulativeUniqueBytes += 64 * 1024
		if err := candidate.Verify(payer.PublicKey(), relay.PublicKey()); err == nil {
			t.Fatal("inflated cumulative bytes retained valid signatures")
		}
	})

	t.Run("relay request replay", func(t *testing.T) {
		ledger := newReferenceLedger(payer.PublicKey(), relay.PublicKey())
		if delta, err := ledger.apply(genesis); err != nil || delta != genesis.Body.CumulativeUniqueBytes {
			t.Fatalf("first apply delta=%d err=%v", delta, err)
		}
		if delta, err := ledger.apply(genesis); err != nil || delta != 0 {
			t.Fatalf("replay delta=%d err=%v", delta, err)
		}
	})

	t.Run("relay fee policy override", func(t *testing.T) {
		candidate := successor
		candidate.Body.PolicyDigest[0] ^= 1
		if err := candidate.Verify(payer.PublicKey(), relay.PublicKey()); err == nil {
			t.Fatal("altered policy retained valid signatures")
		}
	})

	t.Run("Nat stale watermark", func(t *testing.T) {
		staleBody := successorBody
		staleBody.CumulativeUniqueBytes = genesis.Body.CumulativeUniqueBytes
		staleBody.RecordSetDigest[0] ^= 1
		stale := signedVoucher(t, staleBody, payer, relay)
		if err := billingvoucher.ValidateSuccessor(genesis, stale); err == nil {
			t.Fatal("non-increasing cumulative watermark was accepted")
		}
	})

	t.Run("Nat same-sequence fork", func(t *testing.T) {
		forkBody := successorBody
		forkBody.CumulativeUniqueBytes += 64 * 1024
		forkBody.LastRecordID[0] ^= 1
		forkBody.RecordSetDigest[0] ^= 1
		fork := signedVoucher(t, forkBody, payer, relay)
		ledger := newReferenceLedger(payer.PublicKey(), relay.PublicKey())
		if _, err := ledger.apply(genesis); err != nil {
			t.Fatalf("apply genesis: %v", err)
		}
		if _, err := ledger.apply(successor); err != nil {
			t.Fatalf("apply successor: %v", err)
		}
		if delta, err := ledger.apply(fork); err == nil || delta != 0 || !ledger.securityFrozen {
			t.Fatalf("fork delta=%d frozen=%v err=%v", delta, ledger.securityFrozen, err)
		}
	})

	t.Run("Nat signature refusal", func(t *testing.T) {
		relaySignature, err := billingvoucher.SignRelay(successorBody, relay)
		if err != nil {
			t.Fatalf("relay signature: %v", err)
		}
		if _, err := billingvoucher.NewMutualVoucher(successorBody, nil, relaySignature); err == nil {
			t.Fatal("voucher without payer signature was accepted")
		}
	})

	t.Run("relay voucher tamper", func(t *testing.T) {
		candidate := successor
		candidate.Body.RecordSetDigest[0] ^= 1
		if err := candidate.Verify(payer.PublicKey(), relay.PublicKey()); err == nil {
			t.Fatal("tampered record-set digest retained valid signatures")
		}
	})
}

func TestProtocolComponentBacklogRecoveryIsExactlyOnce(t *testing.T) {
	payer := generateIdentity(t)
	relay := generateIdentity(t)
	bodies := make([]billingvoucher.VoucherBody, 3)
	vouchers := make([]billingvoucher.MutualVoucher, 3)
	bodies[0] = voucherBody(t, payer, relay, 1, 256*1024, billingvoucher.Identifier{})
	vouchers[0] = signedVoucher(t, bodies[0], payer, relay)
	for index := 1; index < len(vouchers); index++ {
		previousID, err := vouchers[index-1].ID()
		if err != nil {
			t.Fatalf("previous ID: %v", err)
		}
		bodies[index] = voucherBody(t, payer, relay, uint64(index+1), uint64(index+1)*256*1024, previousID)
		vouchers[index] = signedVoucher(t, bodies[index], payer, relay)
	}

	ledger := newReferenceLedger(payer.PublicKey(), relay.PublicKey())
	if ledger.settledBytes != 0 {
		t.Fatal("disconnected outbox changed the ledger before recovery")
	}
	for _, voucher := range vouchers {
		if _, err := ledger.apply(voucher); err != nil {
			t.Fatalf("recovery apply: %v", err)
		}
	}
	if delta, err := ledger.apply(vouchers[len(vouchers)-1]); err != nil || delta != 0 {
		t.Fatalf("recovered tail replay delta=%d err=%v", delta, err)
	}
	if ledger.settledBytes != vouchers[len(vouchers)-1].Body.CumulativeUniqueBytes {
		t.Fatalf("settled bytes=%d want=%d", ledger.settledBytes, vouchers[len(vouchers)-1].Body.CumulativeUniqueBytes)
	}
}

func generateIdentity(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	identity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return identity
}

func voucherBody(t *testing.T, payer, relay *ecdh.PrivateKey, sequence, cumulative uint64, previous billingvoucher.Identifier) billingvoucher.VoucherBody {
	t.Helper()
	payerID, err := billingvoucher.NodeIDFromPublicKey(payer.PublicKey())
	if err != nil {
		t.Fatalf("payer ID: %v", err)
	}
	relayID, err := billingvoucher.NodeIDFromPublicKey(relay.PublicKey())
	if err != nil {
		t.Fatalf("relay ID: %v", err)
	}
	return billingvoucher.VoucherBody{
		Version:                 billingvoucher.CurrentVersion,
		SessionID:               identifier("session"),
		PayerNatID:              payerID,
		PayeeRelayID:            relayID,
		Direction:               billingvoucher.DirectionPayerOutbound,
		Sequence:                sequence,
		PreviousMutualVoucherID: previous,
		CumulativeUniqueBytes:   cumulative,
		LastRecordID:            identifier(string(rune(sequence)) + "record"),
		LastRecordSequence:      sequence,
		RecordSetDigest:         digest(string(rune(sequence)) + "record-set"),
		PolicyDigest:            digest("fixed-policy"),
		AuthorizedThroughBytes:  8 * 1024 * 1024,
	}
}

func signedVoucher(t *testing.T, body billingvoucher.VoucherBody, payer, relay *ecdh.PrivateKey) billingvoucher.MutualVoucher {
	t.Helper()
	payerSignature, err := billingvoucher.SignPayer(body, payer)
	if err != nil {
		t.Fatalf("sign payer: %v", err)
	}
	relaySignature, err := billingvoucher.SignRelay(body, relay)
	if err != nil {
		t.Fatalf("sign relay: %v", err)
	}
	voucher, err := billingvoucher.NewMutualVoucher(body, payerSignature, relaySignature)
	if err != nil {
		t.Fatalf("new mutual voucher: %v", err)
	}
	return voucher
}

func identifier(label string) billingvoucher.Identifier {
	return sha256.Sum256([]byte(label))
}

func digest(label string) billingvoucher.Digest {
	return sha256.Sum256([]byte(label))
}
