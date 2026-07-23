package billingrecord

import (
	"bytes"
	"testing"

	"bnfs_p2p/billingvoucher"
)

func TestRecordIDAndSetDigestBindEvidence(t *testing.T) {
	var session billingvoucher.Identifier
	session[0] = 1
	record := Record{
		SessionID: session, Sequence: 1, Bytes: 42, Connection: "connection",
		E2ERecordID: bytes.Repeat([]byte{2}, 44), Ciphertext: []byte("ciphertext"),
	}
	identifier, err := record.ID()
	if err != nil {
		t.Fatalf("record ID: %v", err)
	}
	digest, err := Advance(billingvoucher.Digest{}, identifier, record.Sequence, record.Bytes)
	if err != nil {
		t.Fatalf("advance: %v", err)
	}
	changed := record
	changed.Ciphertext = []byte("different")
	changedID, err := changed.ID()
	if err != nil {
		t.Fatalf("changed ID: %v", err)
	}
	if identifier == changedID || digest == (billingvoucher.Digest{}) {
		t.Fatal("record evidence was not bound into its identifiers")
	}
}

func TestRecordRejectsIncompleteEvidence(t *testing.T) {
	if _, err := (Record{}).ID(); err == nil {
		t.Fatal("empty record evidence was accepted")
	}
	if _, err := Advance(billingvoucher.Digest{}, billingvoucher.Identifier{}, 1, 1); err == nil {
		t.Fatal("empty record ID was accepted")
	}
}
