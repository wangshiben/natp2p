package admission

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const denyDecisionDomain = "BNFS/CA-DENY-DECISION/V1\x00"

type DenyDecision struct {
	DecisionID  string `json:"decision_id"`
	ErrorCode   string `json:"error_code"`
	ScopeType   string `json:"scope_type"`
	ScopeID     string `json:"scope_id"`
	EffectiveAt int64  `json:"effective_at"`
	Epoch       uint64 `json:"epoch"`
	RelayID     string `json:"relay_id"`
	RequestID   string `json:"request_id"`
	IssuedAt    int64  `json:"issued_at"`
	Signature   string `json:"signature"`
}

func (decision DenyDecision) canonicalBytes() ([]byte, error) {
	decision.Signature = ""
	payload, err := json.Marshal(decision)
	if err != nil {
		return nil, err
	}
	return append([]byte(denyDecisionDomain), payload...), nil
}

func SignDenyDecision(privateKey *ecdsa.PrivateKey, decision DenyDecision) (*DenyDecision, error) {
	if privateKey == nil || decision.ErrorCode == "" || decision.ScopeType == "" || decision.ScopeID == "" || decision.RequestID == "" {
		return nil, errors.New("admission: incomplete deny decision")
	}
	if decision.IssuedAt == 0 {
		decision.IssuedAt = time.Now().UTC().Unix()
	}
	if decision.EffectiveAt == 0 {
		decision.EffectiveAt = decision.IssuedAt
	}
	if decision.DecisionID == "" {
		seed := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", decision.ErrorCode, decision.ScopeType, decision.ScopeID, decision.RequestID, decision.IssuedAt)))
		decision.DecisionID = hex.EncodeToString(seed[:])
	}
	canonical, err := decision.canonicalBytes()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		return nil, err
	}
	decision.Signature = hex.EncodeToString(signature)
	return &decision, nil
}

func VerifyDenyDecision(publicKey *ecdsa.PublicKey, decision *DenyDecision, relayID, requestID string, now time.Time) error {
	if publicKey == nil || decision == nil || decision.DecisionID == "" || decision.ErrorCode == "" || decision.ScopeType == "" || decision.ScopeID == "" {
		return errors.New("admission: incomplete deny decision")
	}
	if relayID != "" && decision.RelayID != relayID {
		return errors.New("admission: deny decision relay mismatch")
	}
	if requestID != "" && decision.RequestID != requestID {
		return errors.New("admission: deny decision request mismatch")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if decision.IssuedAt > now.Add(time.Minute).Unix() || decision.IssuedAt < now.Add(-10*time.Minute).Unix() || decision.EffectiveAt > now.Add(time.Minute).Unix() {
		return errors.New("admission: deny decision timestamp invalid")
	}
	canonical, err := decision.canonicalBytes()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	signature, err := hex.DecodeString(decision.Signature)
	if err != nil || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return errors.New("admission: deny decision signature invalid")
	}
	return nil
}
