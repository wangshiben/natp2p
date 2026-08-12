package admission

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	RevocationSyncVersion    = 1
	revocationEventDomain    = "BNFS/CA-REVOCATION-EVENT/V1\x00"
	revocationRequestDomain  = "BNFS/RELAY-REVOCATION-SYNC/V1\x00"
	revocationResponseDomain = "BNFS/CA-REVOCATION-SYNC/V1\x00"
)

type RevocationEvent struct {
	Version     int    `json:"version"`
	Epoch       uint64 `json:"epoch"`
	EventID     string `json:"event_id"`
	ScopeType   string `json:"scope_type"`
	ScopeID     string `json:"scope_id"`
	ErrorCode   string `json:"error_code"`
	EffectiveAt int64  `json:"effective_at"`
	ReasonCode  string `json:"reason_code,omitempty"`
	CreatedAt   int64  `json:"created_at"`
	Signature   string `json:"signature"`
}

type RevocationSyncRequest struct {
	Version        int        `json:"version"`
	RelayID        string     `json:"relay_id"`
	RelayPublicKey string     `json:"relay_public_key"`
	RelayCert      SignedCert `json:"relay_cert"`
	AfterEpoch     uint64     `json:"after_epoch"`
	AckEpoch       uint64     `json:"ack_epoch"`
	Timestamp      int64      `json:"timestamp"`
	Nonce          string     `json:"nonce"`
	WaitSeconds    int        `json:"wait_seconds,omitempty"`
	Signature      string     `json:"signature"`
}

type RevocationSyncResponse struct {
	Version      int               `json:"version"`
	RelayID      string            `json:"relay_id"`
	RequestNonce string            `json:"request_nonce"`
	FromEpoch    uint64            `json:"from_epoch"`
	CurrentEpoch uint64            `json:"current_epoch"`
	ServerTime   int64             `json:"server_time"`
	Events       []RevocationEvent `json:"events"`
	Signature    string            `json:"signature"`
}

func (event RevocationEvent) canonicalBytes() ([]byte, error) {
	// 生成撤销事件的签名载荷，签名字段本身不参与摘要。
	event.Signature = ""
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return append([]byte(revocationEventDomain), encoded...), nil
}

func SignRevocationEvent(privateKey *ecdsa.PrivateKey, event RevocationEvent) (RevocationEvent, error) {
	// 为撤销事件补齐版本并使用 CA 私钥签名。
	if privateKey == nil || event.Epoch == 0 || event.EventID == "" || event.ScopeType == "" || event.ScopeID == "" || event.ErrorCode == "" {
		return RevocationEvent{}, errors.New("admission: incomplete revocation event")
	}
	if event.Version == 0 {
		event.Version = RevocationSyncVersion
	}
	canonical, err := event.canonicalBytes()
	if err != nil {
		return RevocationEvent{}, err
	}
	digest := sha256.Sum256(canonical)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		return RevocationEvent{}, err
	}
	event.Signature = hex.EncodeToString(signature)
	return event, nil
}

func VerifyRevocationEvent(publicKey *ecdsa.PublicKey, event RevocationEvent) error {
	// 校验单条撤销事件的格式、版本和 CA 签名。
	if publicKey == nil || event.Version != RevocationSyncVersion || event.Epoch == 0 || event.EventID == "" || event.ScopeType == "" || event.ScopeID == "" || event.ErrorCode == "" {
		return errors.New("admission: incomplete revocation event")
	}
	canonical, err := event.canonicalBytes()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	signature, err := hex.DecodeString(event.Signature)
	if err != nil || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return errors.New("admission: revocation event signature invalid")
	}
	return nil
}

func NewRevocationSyncRequest(identity *ecdh.PrivateKey, certificate *SignedCert, afterEpoch, ackEpoch uint64, waitSeconds int, now time.Time) (RevocationSyncRequest, error) {
	// 创建 Relay 到 CA 的撤销增量同步请求，并绑定 Relay 身份。
	if identity == nil || certificate == nil || certificate.Cert.Role != RoleRelay {
		return RevocationSyncRequest{}, errors.New("admission: relay identity and certificate are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	publicKey := hex.EncodeToString(identity.PublicKey().Bytes())
	if certificate.Cert.SubjectPubKey != publicKey {
		return RevocationSyncRequest{}, errors.New("admission: relay sync certificate identity mismatch")
	}
	nonce, err := NewNonce()
	if err != nil {
		return RevocationSyncRequest{}, err
	}
	request := RevocationSyncRequest{
		Version: RevocationSyncVersion, RelayID: certificate.Cert.SubjectNodeID,
		RelayPublicKey: publicKey, RelayCert: *certificate, AfterEpoch: afterEpoch,
		AckEpoch: ackEpoch, Timestamp: now.Unix(), Nonce: nonce, WaitSeconds: waitSeconds,
	}
	canonical, err := request.canonicalBytes()
	if err != nil {
		return RevocationSyncRequest{}, err
	}
	digest := sha256.Sum256(canonical)
	privateKey, err := ecdhToECDSA(identity)
	if err != nil {
		return RevocationSyncRequest{}, err
	}
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		return RevocationSyncRequest{}, err
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return request, nil
}

func VerifyRevocationSyncRequest(request RevocationSyncRequest, now time.Time) error {
	// 校验 Relay 同步请求的时间、epoch 范围和自签名身份。
	if request.Version != RevocationSyncVersion || request.RelayID == "" || request.RelayPublicKey == "" || request.Nonce == "" || request.Signature == "" {
		return errors.New("admission: incomplete relay revocation sync request")
	}
	if request.RelayCert.Cert.Role != RoleRelay || request.RelayCert.Cert.SubjectNodeID != request.RelayID || request.RelayCert.Cert.SubjectPubKey != request.RelayPublicKey {
		return errors.New("admission: relay revocation sync identity mismatch")
	}
	if request.AckEpoch > request.AfterEpoch || request.WaitSeconds < 0 || request.WaitSeconds > 25 {
		return errors.New("admission: relay revocation sync bounds invalid")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if request.Timestamp < now.Add(-time.Minute).Unix() || request.Timestamp > now.Add(time.Minute).Unix() {
		return errors.New("admission: relay revocation sync timestamp invalid")
	}
	canonical, err := request.canonicalBytes()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
	if err != nil {
		return errors.New("admission: relay revocation sync signature invalid")
	}
	identity, err := ParseIdentityPublicKey(request.RelayPublicKey)
	if err != nil {
		return err
	}
	publicKey, err := ecdhPublicToECDSA(identity)
	if err != nil || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return errors.New("admission: relay revocation sync signature invalid")
	}
	return nil
}

func (request RevocationSyncRequest) canonicalBytes() ([]byte, error) {
	// 生成不含签名字段的撤销同步请求规范载荷。
	request.Signature = ""
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return append([]byte(revocationRequestDomain), encoded...), nil
}

func SignRevocationSyncResponse(privateKey *ecdsa.PrivateKey, response RevocationSyncResponse) (RevocationSyncResponse, error) {
	// 使用 CA 私钥签发撤销同步响应，供 Relay 验证来源。
	if privateKey == nil || response.Version != RevocationSyncVersion || response.RelayID == "" || response.RequestNonce == "" {
		return RevocationSyncResponse{}, errors.New("admission: incomplete revocation sync response")
	}
	canonical, err := response.canonicalBytes()
	if err != nil {
		return RevocationSyncResponse{}, err
	}
	digest := sha256.Sum256(canonical)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		return RevocationSyncResponse{}, err
	}
	response.Signature = hex.EncodeToString(signature)
	return response, nil
}

func VerifyRevocationSyncResponse(publicKey *ecdsa.PublicKey, response RevocationSyncResponse, relayID, requestNonce string) error {
	// 校验同步响应是否对应当前 Relay 请求并验证 CA 签名。
	if publicKey == nil || response.Version != RevocationSyncVersion || response.RelayID != relayID || response.RequestNonce != requestNonce || response.Signature == "" {
		return errors.New("admission: revocation sync response binding invalid")
	}
	if response.FromEpoch > response.CurrentEpoch {
		return errors.New("admission: revocation sync response epoch invalid")
	}
	canonical, err := response.canonicalBytes()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	signature, err := hex.DecodeString(response.Signature)
	if err != nil || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return errors.New("admission: revocation sync response signature invalid")
	}
	return nil
}

func (response RevocationSyncResponse) canonicalBytes() ([]byte, error) {
	// 生成不包含签名字段的同步响应规范载荷。
	response.Signature = ""
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("admission: encode revocation sync response: %w", err)
	}
	return append([]byte(revocationResponseDomain), encoded...), nil
}
