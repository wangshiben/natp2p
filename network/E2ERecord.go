package network

import (
	"encoding/binary"
	"errors"
)

var ErrE2ERecordRequired = errors.New("network: established E2E session requires an authenticated record")

func SealMessagePayload(suite EncrypSuite, message *Message, messageID []byte) ([]byte, error) {
	if suite == nil || message == nil {
		return nil, nil
	}
	aad, err := CanonicalE2EAAD(message.Header)
	if err != nil {
		return nil, err
	}
	if identitySuite, ok := suite.(MessageIdentityAADSuite); ok {
		ciphertext, id, err := identitySuite.EncryptWithMessageIDAndAAD(message.Payload, aad, messageID)
		if err != nil {
			return nil, err
		}
		message.Payload = ciphertext
		return id, nil
	}
	if identitySuite, ok := suite.(MessageIdentitySuite); ok {
		ciphertext, id, err := identitySuite.EncryptWithMessageID(message.Payload, messageID)
		if err != nil {
			return nil, err
		}
		message.Payload = ciphertext
		return id, nil
	}
	ciphertext, err := suite.Encrypt(message.Payload)
	if err != nil {
		return nil, err
	}
	message.Payload = ciphertext
	return nil, nil
}

func OpenMessagePayload(suite EncrypSuite, message *Message) ([]byte, bool, error) {
	if suite == nil || message == nil {
		return nil, false, nil
	}
	aad, err := CanonicalE2EAAD(message.Header)
	if err != nil {
		return nil, false, err
	}
	if identitySuite, ok := suite.(MessageIdentityAADSuite); ok {
		plaintext, id, authenticated, err := identitySuite.DecryptWithMessageIDAndAAD(message.Payload, aad)
		if err != nil {
			return nil, false, err
		}
		if !authenticated {
			return nil, false, ErrE2ERecordRequired
		}
		message.Payload = plaintext
		return id, true, nil
	}
	if identitySuite, ok := suite.(MessageIdentitySuite); ok {
		plaintext, id, authenticated, err := identitySuite.DecryptWithMessageID(message.Payload)
		if err != nil {
			return nil, false, err
		}
		if !authenticated {
			return nil, false, ErrE2ERecordRequired
		}
		message.Payload = plaintext
		return id, true, nil
	}
	plaintext, err := suite.Decrypt(message.Payload)
	if err != nil {
		return nil, false, err
	}
	message.Payload = plaintext
	return nil, false, nil
}

func CanonicalE2EAAD(header *Header) ([]byte, error) {
	if header == nil {
		return nil, errors.New("network: E2E message header is nil")
	}
	const domain = "BNFS/E2E-MESSAGE-AAD/V3"
	fields := []string{header.RouteName, header.NodeId, header.ConnectionId}
	total := len(domain) + 1 + len(header.BillingSessionID) + 16
	for _, field := range fields {
		if len(field) > int(^uint16(0)) {
			return nil, errors.New("network: E2E AAD field is too long")
		}
		total += 2 + len(field)
	}
	aad := make([]byte, 0, total)
	aad = append(aad, domain...)
	aad = append(aad, version1)
	var length [2]byte
	for _, field := range fields {
		binary.BigEndian.PutUint16(length[:], uint16(len(field)))
		aad = append(aad, length[:]...)
		aad = append(aad, field...)
	}
	aad = append(aad, header.BillingSessionID[:]...)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], header.BillingSequence)
	aad = append(aad, number[:]...)
	binary.BigEndian.PutUint64(number[:], header.BillingBytes)
	aad = append(aad, number[:]...)
	return aad, nil
}
