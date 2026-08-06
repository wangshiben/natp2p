package billingcontrol

import "bnfs_p2p/admission"

const Route = "/billing/control/v1"

const (
	TypeSession  = "session"
	TypeReady    = "ready"
	TypeClaim    = "claim"
	TypeCosigned = "cosigned"
	TypeReject   = "reject"
)

type Message struct {
	Type                  string                `json:"type"`
	SessionID             string                `json:"session_id,omitempty"`
	Challenge             []byte                `json:"challenge,omitempty"`
	PayerProof            []byte                `json:"payer_proof,omitempty"`
	RelayStateProof       []byte                `json:"relay_state_proof,omitempty"`
	SessionPreexisting    bool                  `json:"session_preexisting,omitempty"`
	SessionResetRequired  bool                  `json:"session_reset_required,omitempty"`
	CumulativeBytes       uint64                `json:"cumulative_bytes,omitempty"`
	LastRecordID          string                `json:"last_record_id,omitempty"`
	LastRecordSequence    uint64                `json:"last_record_sequence,omitempty"`
	RecordSetDigest       string                `json:"record_set_digest,omitempty"`
	Body                  []byte                `json:"body,omitempty"`
	RelaySignature        []byte                `json:"relay_signature,omitempty"`
	RelayPublicKey        string                `json:"relay_public_key,omitempty"`
	RelayBillingPublicKey string                `json:"relay_billing_public_key,omitempty"`
	RelayCert             *admission.SignedCert `json:"relay_cert,omitempty"`
	Voucher               []byte                `json:"voucher,omitempty"`
	PayerPublicKey        string                `json:"payer_public_key,omitempty"`
	PayerBillingPublicKey string                `json:"payer_billing_public_key,omitempty"`
	PayerCert             *admission.SignedCert `json:"payer_cert,omitempty"`
	Error                 string                `json:"error,omitempty"`
}
