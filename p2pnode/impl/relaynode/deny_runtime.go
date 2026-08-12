package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/logx"
	"fmt"
	"time"
)

var permanentDenyCodes = map[string]struct{}{
	"node_revoked": {}, "certificate_revoked": {}, "node_authorization_revoked": {},
	"billing_key_revoked": {}, "billing_key_expired": {}, "billing_user_disabled": {},
}

func (n *RelayNode) applyDenyDecision(decision *admission.DenyDecision) error {
	if decision == nil {
		return fmt.Errorf("relaynode: missing deny decision")
	}
	if _, ok := permanentDenyCodes[decision.ErrorCode]; !ok {
		return fmt.Errorf("relaynode: deny decision is not permanent: %s", decision.ErrorCode)
	}
	if decision.RelayID != n.idStr() || decision.ScopeID == "" || decision.ScopeType == "" {
		return fmt.Errorf("relaynode: deny decision identity or scope mismatch")
	}
	cfg := n.admissionConfig()
	if cfg == nil {
		return fmt.Errorf("relaynode: deny decision requires admission configuration")
	}
	verifier, ok := cfg.Verifier.(*admission.CAClient)
	if !ok || verifier == nil {
		return fmt.Errorf("relaynode: deny decision requires a CA verifier")
	}
	if err := verifier.VerifyDenyDecision(decision, n.idStr(), ""); err != nil {
		return err
	}
	n.mu.RLock()
	revocationControl := n.revocationControl
	n.mu.RUnlock()
	if revocationControl != nil {
		if err := revocationControl.persistDecision(*decision); err != nil {
			return fmt.Errorf("relaynode: persist deny decision before apply: %w", err)
		}
	}
	return n.applyVerifiedDeny(
		decision.DecisionID, decision.ScopeType, decision.ScopeID, decision.ErrorCode,
		decision.EffectiveAt, decision,
	)
}

func (n *RelayNode) applyRevocationEvent(event admission.RevocationEvent) error {
	if _, ok := permanentDenyCodes[event.ErrorCode]; !ok {
		return fmt.Errorf("relaynode: revocation event is not permanent: %s", event.ErrorCode)
	}
	if event.EventID == "" || event.ScopeType == "" || event.ScopeID == "" {
		return fmt.Errorf("relaynode: incomplete revocation event")
	}
	return n.applyVerifiedDeny(event.EventID, event.ScopeType, event.ScopeID, event.ErrorCode, event.EffectiveAt, nil)
}

func (n *RelayNode) applyVerifiedDeny(
	identifier string,
	scopeType string,
	scopeID string,
	errorCode string,
	effectiveAt int64,
	decision *admission.DenyDecision,
) error {
	key := scopeType + ":" + scopeID
	n.businessAdmissionMu.Lock()
	if _, exists := n.businessDeniedScopes[key]; exists {
		n.businessAdmissionMu.Unlock()
		return nil
	}
	n.businessDeniedScopes[key] = struct{}{}
	if decision != nil {
		n.businessDenyDecisions[decision.DecisionID] = *decision
	}
	n.businessAdmissionMu.Unlock()

	deny := admission.DenyDecision{ScopeType: scopeType, ScopeID: scopeID, ErrorCode: errorCode}
	payers := n.accounts.nodesForDeny(deny)
	for _, payerID := range payers {
		if err := n.starter.Cover().CloseHostedRegistration(payerID); err != nil {
			logx.Warnf("[relaynode] 撤销处置关闭注册流失败: node=%.16s err=%v", payerID, err)
		}
	}
	closedPeers := n.closePeerLinksForDeny(deny)
	n.mu.RLock()
	pipeline := n.billingPipeline
	n.mu.RUnlock()
	if pipeline != nil {
		pipeline.blockPayers(payers, fmt.Errorf("relaynode: CA permanent deny %s", errorCode))
	}
	logx.Warnf("[relaynode] 已应用 CA 签名永久拒绝: id=%.16s scope=%s:%s code=%s effective=%s affected_nat=%d affected_relay=%d",
		identifier, scopeType, scopeID, errorCode,
		time.Unix(effectiveAt, 0).UTC().Format(time.RFC3339), len(payers), closedPeers)

	cfg := n.admissionConfig()
	if cfg != nil && cfg.SelfCert != nil &&
		(n.businessScopeDenied(cfg.SelfCert.Cert) || n.businessCertificateDenied(cfg.SelfCert)) {
		logx.Errorf("[relaynode] 本 Relay 身份已被 CA 撤销，执行 fail-closed 关闭: scope=%s:%s", scopeType, scopeID)
		go func() { _ = n.Close() }()
	}
	return nil
}

func (s *accountStore) nodesForDeny(decision admission.DenyDecision) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0)
	for nodeID, account := range s.accounts {
		if certificateMatchesDeny(account.Cert, account.UserID, decision) {
			result = append(result, nodeID)
		}
	}
	return result
}

func certificateMatchesDeny(certificate *admission.SignedCert, userID string, decision admission.DenyDecision) bool {
	if certificate == nil {
		return false
	}
	switch decision.ScopeType {
	case "node":
		return certificate.Cert.SubjectNodeID == decision.ScopeID
	case "authorization":
		return certificate.Cert.AuthorizationID == decision.ScopeID
	case "billing_key":
		return certificate.Cert.BillingKeyID == decision.ScopeID
	case "user":
		return userID == decision.ScopeID || certificate.Cert.BillingUserID == decision.ScopeID
	case "certificate":
		certificateID, err := admission.CertificateID(certificate)
		return err == nil && certificateID == decision.ScopeID
	}
	return false
}
