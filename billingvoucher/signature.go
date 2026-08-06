package billingvoucher

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

const MaxSignatureSize = 72

const (
	payerSignatureDomain = "BNFS/NAT-VOUCHER/V1"
	relaySignatureDomain = "BNFS/RELAY-VOUCHER/V1"
)

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

func NodeIDFromPublicKey(identity *ecdh.PublicKey) (Identifier, error) {
	if _, err := ecdsaPublicKey(identity); err != nil {
		return Identifier{}, err
	}
	publicKeyHex := hex.EncodeToString(identity.Bytes())
	return sha256.Sum256([]byte(publicKeyHex)), nil
}

func SignPayer(body VoucherBody, identity *ecdh.PrivateKey) ([]byte, error) {
	return signBody(body, identity, body.PayerNatID, payerSignatureDomain)
}

func SignRelay(body VoucherBody, identity *ecdh.PrivateKey) ([]byte, error) {
	return signBody(body, identity, body.PayeeRelayID, relaySignatureDomain)
}

// SignPayerBilling 使用已由 CA 证书绑定的独立扣费密钥签署 payer 凭证。
// 调用方必须先校验证书中的节点身份与扣费公钥绑定。
func SignPayerBilling(body VoucherBody, billingKey *ecdh.PrivateKey) ([]byte, error) {
	return signBodyWithBillingKey(body, billingKey, payerSignatureDomain)
}

// SignRelayBilling 使用已由 CA 证书绑定的独立扣费密钥签署 Relay 凭证。
func SignRelayBilling(body VoucherBody, billingKey *ecdh.PrivateKey) ([]byte, error) {
	return signBodyWithBillingKey(body, billingKey, relaySignatureDomain)
}

func VerifyPayerSignature(body VoucherBody, signature []byte, identity *ecdh.PublicKey) error {
	return verifyBodySignature(body, signature, identity, body.PayerNatID, payerSignatureDomain)
}

func VerifyRelaySignature(body VoucherBody, signature []byte, identity *ecdh.PublicKey) error {
	return verifyBodySignature(body, signature, identity, body.PayeeRelayID, relaySignatureDomain)
}

// VerifyPayerBillingSignature 校验 CA 已绑定扣费公钥的 payer 签名，不把扣费公钥误作 Node ID。
func VerifyPayerBillingSignature(body VoucherBody, signature []byte, billingKey *ecdh.PublicKey) error {
	return verifyBodyBillingSignature(body, signature, billingKey, payerSignatureDomain)
}

// VerifyRelayBillingSignature 校验 CA 已绑定扣费公钥的 Relay 签名。
func VerifyRelayBillingSignature(body VoucherBody, signature []byte, billingKey *ecdh.PublicKey) error {
	return verifyBodyBillingSignature(body, signature, billingKey, relaySignatureDomain)
}

func (voucher MutualVoucher) Verify(payerIdentity, relayIdentity *ecdh.PublicKey) error {
	if err := VerifyPayerSignature(voucher.Body, voucher.PayerSignature, payerIdentity); err != nil {
		return fmt.Errorf("billingvoucher: payer verification failed: %w", err)
	}
	if err := VerifyRelaySignature(voucher.Body, voucher.RelaySignature, relayIdentity); err != nil {
		return fmt.Errorf("billingvoucher: Relay verification failed: %w", err)
	}
	return nil
}

// VerifyBillingSignatures 校验已通过 CA 证书绑定的两组扣费公钥。
// 节点 ID 与身份公钥的校验由调用方在调用本方法前完成。
func (voucher MutualVoucher) VerifyBillingSignatures(payerBillingKey, relayBillingKey *ecdh.PublicKey) error {
	if err := VerifyPayerBillingSignature(voucher.Body, voucher.PayerSignature, payerBillingKey); err != nil {
		return fmt.Errorf("billingvoucher: payer billing verification failed: %w", err)
	}
	if err := VerifyRelayBillingSignature(voucher.Body, voucher.RelaySignature, relayBillingKey); err != nil {
		return fmt.Errorf("billingvoucher: Relay billing verification failed: %w", err)
	}
	return nil
}

func signBody(body VoucherBody, identity *ecdh.PrivateKey, expectedID Identifier, domain string) ([]byte, error) {
	if err := body.Validate(); err != nil {
		return nil, err
	}
	privateKey, err := ecdsaPrivateKey(identity)
	if err != nil {
		return nil, err
	}
	actualID, err := NodeIDFromPublicKey(identity.PublicKey())
	if err != nil {
		return nil, err
	}
	if actualID != expectedID {
		return nil, errors.New("billingvoucher: signer identity does not match voucher binding")
	}
	return signValidatedBody(body, privateKey, domain)
}

func signBodyWithBillingKey(body VoucherBody, billingKey *ecdh.PrivateKey, domain string) ([]byte, error) {
	if err := body.Validate(); err != nil {
		return nil, err
	}
	privateKey, err := ecdsaPrivateKey(billingKey)
	if err != nil {
		return nil, err
	}
	return signValidatedBody(body, privateKey, domain)
}

func signValidatedBody(body VoucherBody, privateKey *ecdsa.PrivateKey, domain string) ([]byte, error) {
	bodyID, err := body.BodyID()
	if err != nil {
		return nil, err
	}
	digest := signatureDigest(domain, bodyID)
	rawSignature, err := privateKey.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("billingvoucher: P-256 ECDSA signing failed: %w", err)
	}
	return canonicalizeSignature(rawSignature)
}

func verifyBodySignature(body VoucherBody, signature []byte, identity *ecdh.PublicKey, expectedID Identifier, domain string) error {
	if err := body.Validate(); err != nil {
		return err
	}
	publicKey, err := ecdsaPublicKey(identity)
	if err != nil {
		return err
	}
	actualID, err := NodeIDFromPublicKey(identity)
	if err != nil {
		return err
	}
	if actualID != expectedID {
		return errors.New("billingvoucher: verifier identity does not match voucher binding")
	}
	return verifyValidatedBodySignature(body, signature, publicKey, domain)
}

func verifyBodyBillingSignature(
	body VoucherBody,
	signature []byte,
	billingKey *ecdh.PublicKey,
	domain string,
) error {
	if err := body.Validate(); err != nil {
		return err
	}
	publicKey, err := ecdsaPublicKey(billingKey)
	if err != nil {
		return err
	}
	return verifyValidatedBodySignature(body, signature, publicKey, domain)
}

func verifyValidatedBodySignature(
	body VoucherBody,
	signature []byte,
	publicKey *ecdsa.PublicKey,
	domain string,
) error {
	parsed, err := parseCanonicalSignature(signature, true)
	if err != nil {
		return err
	}
	bodyID, err := body.BodyID()
	if err != nil {
		return err
	}
	digest := signatureDigest(domain, bodyID)
	if !ecdsa.Verify(publicKey, digest[:], parsed.R, parsed.S) {
		return errors.New("billingvoucher: invalid P-256 ECDSA signature")
	}
	return nil
}

func signatureDigest(domain string, bodyID Identifier) [sha256.Size]byte {
	encoded := make([]byte, 0, len(domain)+len(bodyID))
	encoded = append(encoded, domain...)
	encoded = append(encoded, bodyID[:]...)
	return sha256.Sum256(encoded)
}

func canonicalizeSignature(signature []byte) ([]byte, error) {
	parsed, err := parseCanonicalSignature(signature, false)
	if err != nil {
		return nil, err
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if parsed.S.Cmp(halfOrder) > 0 {
		parsed.S.Sub(elliptic.P256().Params().N, parsed.S)
	}
	canonical, err := asn1.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("billingvoucher: encode ECDSA signature: %w", err)
	}
	if len(canonical) > MaxSignatureSize {
		return nil, errors.New("billingvoucher: P-256 signature exceeds canonical size")
	}
	return canonical, nil
}

func validateCanonicalSignature(signature []byte) error {
	_, err := parseCanonicalSignature(signature, true)
	return err
}

func parseCanonicalSignature(signature []byte, requireLowS bool) (ecdsaSignature, error) {
	if len(signature) == 0 || len(signature) > MaxSignatureSize {
		return ecdsaSignature{}, errors.New("P-256 signature length is out of range")
	}
	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return ecdsaSignature{}, errors.New("invalid ASN.1 P-256 signature")
	}
	canonical, err := asn1.Marshal(parsed)
	if err != nil || !bytes.Equal(canonical, signature) {
		return ecdsaSignature{}, errors.New("non-canonical ASN.1 P-256 signature")
	}
	order := elliptic.P256().Params().N
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || parsed.R.Cmp(order) >= 0 || parsed.S.Cmp(order) >= 0 {
		return ecdsaSignature{}, errors.New("P-256 signature scalar is out of range")
	}
	if requireLowS {
		halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
		if parsed.S.Cmp(halfOrder) > 0 {
			return ecdsaSignature{}, errors.New("P-256 signature is not low-S canonical")
		}
	}
	return parsed, nil
}

func ecdsaPrivateKey(identity *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	if identity == nil {
		return nil, errors.New("billingvoucher: P-256 identity private key is nil")
	}
	publicKey, err := ecdsaPublicKey(identity.PublicKey())
	if err != nil {
		return nil, err
	}
	scalar := new(big.Int).SetBytes(identity.Bytes())
	order := elliptic.P256().Params().N
	if scalar.Sign() <= 0 || scalar.Cmp(order) >= 0 {
		return nil, errors.New("billingvoucher: invalid P-256 identity scalar")
	}
	expectedX, expectedY := elliptic.P256().ScalarBaseMult(scalar.Bytes())
	if expectedX.Cmp(publicKey.X) != 0 || expectedY.Cmp(publicKey.Y) != 0 {
		return nil, errors.New("billingvoucher: identity private and public keys do not match")
	}
	return &ecdsa.PrivateKey{PublicKey: *publicKey, D: scalar}, nil
}

func ecdsaPublicKey(identity *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	if identity == nil {
		return nil, errors.New("billingvoucher: P-256 identity public key is nil")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), identity.Bytes())
	if x == nil || y == nil {
		return nil, errors.New("billingvoucher: identity key is not a valid P-256 key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
