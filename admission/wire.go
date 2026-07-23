package admission

// CA/indexServer Web 服务的 HTTP 线格式。
//
// 端点约定（见 DESIGN §5 决策 A）：
//   - GET  /pubkey  → PubKeyResp（CA 当前公钥 PEM）。relay 启动/注册时拉一次并缓存。
//   - POST /issue    ← IssueRequest；→ IssueResponse（签发好的 SignedCert）。
//
// 这些类型故意只用基础 JSON 标量，方便日后 CA 换成任意语言的正式 Web 应用时保持契约兼容。

// PubKeyResp 是 GET /pubkey 的应答。
type PubKeyResp struct {
	// PubKeyPEM 是 CA 公钥的 PKIX/SPKI PEM 文本。
	PubKeyPEM string `json:"pubkey_pem"`
	// Issuer 是 CA 标识（人读/审计用）。
	Issuer string `json:"issuer,omitempty"`
}

// IssueRequest 是 POST /issue 的请求：申请方声明自己的公钥与期望角色。
//
// 本地测试 CA 可在 HTTP 层为该请求配置角色隔离的 enrollment Bearer；线格式不携带凭据，
// 避免证书申请被记录或转发时泄露认证材料。生产 CA 仍应接入正式身份核验、角色审批与吊销流程。
type IssueRequest struct {
	// SubjectPubKey 是申请方的 P-256 ECDH 公钥 hex。CA 据它推导 NodeID。
	SubjectPubKey string `json:"subject_pubkey"`
	// Role 是申请的角色。
	Role Role `json:"role"`
	// TTLSeconds 是期望有效期（秒）；CA 可裁剪到自身策略上限。<=0 用 CA 默认。
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// IssueResponse 是 POST /issue 的应答。
type IssueResponse struct {
	// SignedCert 是签发好的完整证书（成功时非空）。
	SignedCert *SignedCert `json:"signed_cert,omitempty"`
	// Error 非空表示签发失败原因。
	Error string `json:"error,omitempty"`
}

// SettleRequest 是 relay 周期性上报某 serverNode 上行用量、并请求余额裁决的请求。
//
// 计费模型（见 DESIGN §4）：relay 本地按节点累计上行净荷，每隔 N 个时间片把【自上次上报以来的
// 增量 UsedDelta】上报给 CA；CA 从该节点余额扣减，返回扣减后余额与是否仍可继续（Allow）。
// relay 据 Allow=false 熔断该节点转发。上报量由 relay 的准入身份背书（relay 是受信组件）。
type SettleRequest struct {
	// NodeID 是被计费的 serverNode。
	NodeID string `json:"node_id"`
	// RelayNodeID 是上报方 relay 的 NodeId（审计/防重放用）。
	RelayNodeID string `json:"relay_node_id,omitempty"`
	// UsedDelta 是自上次上报以来新增的上行净荷字节（增量，非累计）。
	UsedDelta int64 `json:"used_delta"`
}

// SettleResponse 是 CA 对结算请求的裁决。
type SettleResponse struct {
	// Balance 是扣减后该节点剩余余额（字节）。可为负（欠费）。
	Balance int64 `json:"balance"`
	// Allow 报告该节点是否仍可继续获得转发服务（余额 > 0）。false → relay 应熔断。
	Allow bool `json:"allow"`
	// Error 非空表示结算失败原因（如未知节点）。
	Error string `json:"error,omitempty"`
}

// VoucherSettleRequest submits one canonical, mutually signed cumulative usage
// voucher. []byte is represented as standard base64 by encoding/json.
type VoucherSettleRequest struct {
	CanonicalVoucher []byte      `json:"canonical_voucher"`
	PayerPublicKey   string      `json:"payer_public_key"`
	RelayPublicKey   string      `json:"relay_public_key"`
	PayerCert        *SignedCert `json:"payer_cert"`
	RelayCert        *SignedCert `json:"relay_cert"`
}

// VoucherSettleResponse reports the authoritative accounting decision. Delta
// and RelayCredit are zero when no new mutation occurred. A retryable response
// leaves the voucher and every accounting watermark untouched, so the exact
// same voucher can be submitted again after the reported condition is fixed.
type VoucherSettleResponse struct {
	VoucherID   string `json:"voucher_id,omitempty"`
	Delta       int64  `json:"delta"`
	Balance     int64  `json:"balance"`
	RelayCredit int64  `json:"relay_credit"`
	Allow       bool   `json:"allow"`
	Replayed    bool   `json:"replayed,omitempty"`
	Stale       bool   `json:"stale,omitempty"`
	Frozen      bool   `json:"frozen,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
	Retryable   bool   `json:"retryable,omitempty"`
	Error       string `json:"error,omitempty"`
}

// ReserveRequest 是 relay 在【建立一条业务连接时】向 CA 请求「连接保证金」双扣的请求。
//
// 连接保证金模型（见 DESIGN / BILLING_修复方案_机制层）：每建立一条连接，对 client 与 server
// 各扣一笔一次性入场费（平费、不退、无量上限），任一方余额不足即拒绝建连。这抬高「白嫖」门槛：
// 免费领的 0 余额证书连不上；连接churn 迅速耗尽余额。client 后续字节不再计量，server 上行照旧计费。
type ReserveRequest struct {
	// ConnID 是本次业务连接标识（审计/幂等参考）。
	ConnID string `json:"conn_id"`
	// ClientNodeID / ServerNodeID 是连接两端的 NodeId。
	ClientNodeID string `json:"client_node_id"`
	ServerNodeID string `json:"server_node_id"`
	// RelayNodeID 是发起预扣的 relay（审计）。
	RelayNodeID string `json:"relay_node_id,omitempty"`
	// ClientFee / ServerFee 是本次要扣的入场费（字节）。由 relay 按策略传入，CA 校验并扣减。
	ClientFee int64 `json:"client_fee"`
	ServerFee int64 `json:"server_fee"`
}

// ReserveResponse 是 CA 对连接保证金双扣的裁决。
type ReserveResponse struct {
	// Allow=true 表示双方余额均足够、已各自扣费，可建连；false 表示被拒（至少一方不足）。
	Allow bool `json:"allow"`
	// ClientBalance / ServerBalance 是扣费后余额（Allow=false 时为未扣的当前余额）。
	ClientBalance int64 `json:"client_balance"`
	ServerBalance int64 `json:"server_balance"`
	// Error 非空表示失败原因（如缺少字段 / 余额不足的说明）。
	Error string `json:"error,omitempty"`
}

// CreditRequest 是给某节点充值（增加余额）的请求。MVP/测试用；生产中由支付系统驱动。
type CreditRequest struct {
	NodeID   string `json:"node_id"`
	AddBytes int64  `json:"add_bytes"`
}

// CreditResponse 是充值后的余额。
type CreditResponse struct {
	Balance int64  `json:"balance"`
	Error   string `json:"error,omitempty"`
}

// 默认端点路径常量，CA 服务与 caclient 共用，避免拼写漂移。
const (
	PathPubKey        = "/pubkey"
	PathIssue         = "/issue"
	PathSettle        = "/settle"
	PathCredit        = "/credit"
	PathBalance       = "/balance"
	PathReserve       = "/reserve"
	PathVoucherSettle = "/v1/channel/voucher"
)

const VoucherErrorInsufficientFunds = "insufficient_funds"
