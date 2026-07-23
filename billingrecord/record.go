package billingrecord

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"bnfs_p2p/billingvoucher"
)

const recordDomain = "BNFS/BILLABLE-E2E-RECORD/V1"
const setDomain = "BNFS/BILLABLE-RECORD-SET/V1"

type Record struct {
	SessionID   billingvoucher.Identifier
	Sequence    uint64
	Bytes       uint64
	Connection  string
	E2ERecordID []byte
	Ciphertext  []byte
}

func (record Record) ID() (billingvoucher.Identifier, error) {
	if record.SessionID == (billingvoucher.Identifier{}) {
		return billingvoucher.Identifier{}, errors.New("billingrecord: session ID is required")
	}
	if record.Sequence == 0 {
		return billingvoucher.Identifier{}, errors.New("billingrecord: sequence is required")
	}
	if record.Bytes == 0 || record.Bytes > billingvoucher.MaxBillableBytes {
		return billingvoucher.Identifier{}, errors.New("billingrecord: invalid billable byte count")
	}
	if len(record.Connection) == 0 || len(record.Connection) > 65535 {
		return billingvoucher.Identifier{}, errors.New("billingrecord: invalid connection ID")
	}
	if len(record.E2ERecordID) == 0 || len(record.E2ERecordID) > 255 {
		return billingvoucher.Identifier{}, errors.New("billingrecord: invalid E2E record ID")
	}
	if len(record.Ciphertext) == 0 {
		return billingvoucher.Identifier{}, errors.New("billingrecord: ciphertext is required")
	}

	hash := sha256.New()
	_, _ = hash.Write([]byte(recordDomain))
	_, _ = hash.Write(record.SessionID[:])
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], record.Sequence)
	_, _ = hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], record.Bytes)
	_, _ = hash.Write(number[:])
	var short [2]byte
	binary.BigEndian.PutUint16(short[:], uint16(len(record.Connection)))
	_, _ = hash.Write(short[:])
	_, _ = hash.Write([]byte(record.Connection))
	_, _ = hash.Write([]byte{byte(len(record.E2ERecordID))})
	_, _ = hash.Write(record.E2ERecordID)
	ciphertextDigest := sha256.Sum256(record.Ciphertext)
	_, _ = hash.Write(ciphertextDigest[:])
	var identifier billingvoucher.Identifier
	copy(identifier[:], hash.Sum(nil))
	return identifier, nil
}

func Advance(previous billingvoucher.Digest, recordID billingvoucher.Identifier, sequence, bytes uint64) (billingvoucher.Digest, error) {
	if recordID == (billingvoucher.Identifier{}) || sequence == 0 || bytes == 0 {
		return billingvoucher.Digest{}, errors.New("billingrecord: invalid record-set input")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(setDomain))
	_, _ = hash.Write(previous[:])
	_, _ = hash.Write(recordID[:])
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], sequence)
	_, _ = hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], bytes)
	_, _ = hash.Write(number[:])
	var digest billingvoucher.Digest
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
