// caserver 是一个【独立于 p2p 框架】的最小 CA / indexServer Web 服务。
//
// 它承担网络准入方向里「证书签发」的角色（见 DESIGN_准入与计费_评估与决策.md 决策 A）：
//   - 持有一把 ECDSA(P-256) 签发密钥（首次启动生成并持久化到 -key 文件）；
//   - GET  /pubkey  返回 CA 公钥 PEM，供 relay 启动时拉取并缓存、之后离线验签；
//   - POST /issue   按申请签发一张能力证书（绑定 NodeID + 公钥 + 角色 + 有效期）。
//
// 设计边界：本服务【不】导入 p2p 框架的任何网络/节点包，只依赖 admission 这一中立包与标准库。
// 这样日后可以把它整体替换为其它语言写的正式 Web 应用，而框架侧（caclient + 离线验签）不变。
//
// 测试部署可为 /issue 配置角色隔离的 enrollment Bearer、为 /credit 配置独立 admin Bearer。
// 正式生产仍需用业务身份、审批、吊销与密钥轮换系统替代这些本地 bootstrap 凭据。
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingvoucher"
)

func main() {
	listen := flag.String("listen", ":9000", "HTTP 监听地址")
	keyFile := flag.String("key", "ca_key.pem", "CA 签发私钥 PEM 文件（不存在则生成）")
	issuer := flag.String("issuer", "bnfs-ca", "CA 标识（写入证书 Issuer / /pubkey 应答）")
	defaultTTL := flag.Int64("ttl", 24*3600, "默认证书有效期（秒），也是签发上限")
	ledgerFile := flag.String("ledger", "ca_ledger.json", "计费账本落盘文件（不存在则新建；每次变更写回）")
	relayEnrollmentTokenFile := flag.String("relay-enrollment-token-file", "", "Relay 证书签发 Bearer 凭据文件")
	serverEnrollmentTokenFile := flag.String("server-enrollment-token-file", "", "NatServer 证书签发 Bearer 凭据文件")
	clientEnrollmentTokenFile := flag.String("client-enrollment-token-file", "", "NatClient 证书签发 Bearer 凭据文件")
	adminTokenFile := flag.String("admin-token-file", "", "/credit 管理 Bearer 凭据文件")
	flag.Parse()
	authentication, err := loadCAAuthentication(map[admission.Role]string{
		admission.RoleRelay:  *relayEnrollmentTokenFile,
		admission.RoleServer: *serverEnrollmentTokenFile,
		admission.RoleClient: *clientEnrollmentTokenFile,
	}, *adminTokenFile)
	if err != nil {
		log.Fatalf("[caserver] 加载管理凭据失败: %v", err)
	}

	priv, err := loadOrCreateKey(*keyFile)
	if err != nil {
		log.Fatalf("[caserver] 加载/生成签发密钥失败: %v", err)
	}
	pubPEM, err := admission.MarshalCAPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		log.Fatalf("[caserver] 编码公钥失败: %v", err)
	}
	log.Printf("[caserver] CA 就绪 issuer=%s listen=%s key=%s", *issuer, *listen, *keyFile)
	log.Printf("[caserver] CA 公钥 PEM:\n%s", pubPEM)

	ledger := newLedger(*ledgerFile)
	if ledger.loadErr != nil {
		log.Fatalf("[caserver] 加载计费账本失败: %v", ledger.loadErr)
	}

	srv := &http.Server{
		Addr:         *listen,
		Handler:      newCAHandler(priv, pubPEM, *issuer, *defaultTTL, ledger, authentication),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[caserver] 服务退出: %v", err)
	}
}

func newCAHandler(priv *ecdsa.PrivateKey, pubPEM, issuer string, defaultTTL int64, ledger *ledger, authOptions ...caAuthentication) http.Handler {
	authentication := caAuthentication{}
	if len(authOptions) > 0 {
		authentication = authOptions[0]
	}
	mux := http.NewServeMux()
	mux.HandleFunc(admission.PathPubKey, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, admission.PubKeyResp{PubKeyPEM: pubPEM, Issuer: issuer})
	})
	mux.HandleFunc(admission.PathIssue, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		authorizedRole, required, authorized := authentication.authenticateEnrollment(r)
		if required && !authorized {
			writeAuthenticationError(w, http.StatusUnauthorized, admission.IssueResponse{Error: "unauthorized"})
			return
		}
		var req admission.IssueRequest
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, admission.IssueResponse{Error: err.Error()})
			return
		}
		if required && req.Role != authorizedRole {
			writeAuthenticationError(w, http.StatusForbidden, admission.IssueResponse{Error: "role_not_authorized"})
			return
		}
		sc, err := issue(priv, req, issuer, defaultTTL)
		if err != nil {
			log.Printf("[caserver] /issue 拒绝: %v", err)
			writeJSON(w, http.StatusBadRequest, admission.IssueResponse{Error: err.Error()})
			return
		}
		log.Printf("[caserver] 已签发: nodeID=%.16s role=%s ttl<=%ds", sc.Cert.SubjectNodeID, sc.Cert.Role, defaultTTL)
		writeJSON(w, http.StatusOK, admission.IssueResponse{SignedCert: sc})
	})
	mux.HandleFunc(admission.PathCredit, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if authentication.adminToken != "" && !authentication.authenticateAdmin(r) {
			writeAuthenticationError(w, http.StatusUnauthorized, admission.CreditResponse{Error: "unauthorized"})
			return
		}
		var req admission.CreditRequest
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, admission.CreditResponse{Error: err.Error()})
			return
		}
		if req.NodeID == "" || req.AddBytes <= 0 {
			writeJSON(w, http.StatusBadRequest, admission.CreditResponse{Error: "node_id 不能为空且 add_bytes 必须为正数"})
			return
		}
		bal, err := ledger.creditChecked(req.NodeID, req.AddBytes)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, admission.CreditResponse{Error: err.Error()})
			return
		}
		log.Printf("[caserver] 充值: nodeID=%.16s +%dB 余额=%dB", req.NodeID, req.AddBytes, bal)
		writeJSON(w, http.StatusOK, admission.CreditResponse{Balance: bal})
	})
	mux.HandleFunc(admission.PathVoucherSettle, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req admission.VoucherSettleRequest
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, admission.VoucherSettleResponse{Error: err.Error()})
			return
		}
		validated, err := validateVoucherRequest(priv, req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, admission.VoucherSettleResponse{Error: err.Error()})
			return
		}
		response, status := ledger.settleVoucher(validated)
		writeJSON(w, status, response)
	})
	mux.HandleFunc(admission.PathBalance, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"balance": ledger.balance(r.URL.Query().Get("node"))})
	})
	mux.HandleFunc(admission.PathSettle, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusGone, admission.SettleResponse{Error: "legacy /settle is disabled; use mutually signed vouchers"})
	})
	mux.HandleFunc(admission.PathReserve, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusGone, admission.ReserveResponse{Error: "legacy /reserve is disabled; use CA-defined policy"})
	})
	return mux
}

type caAuthentication struct {
	enrollmentTokens map[admission.Role]string
	adminToken       string
}

func loadCAAuthentication(enrollmentFiles map[admission.Role]string, adminFile string) (caAuthentication, error) {
	authentication := caAuthentication{enrollmentTokens: make(map[admission.Role]string)}
	seen := make(map[string]admission.Role)
	for _, role := range []admission.Role{admission.RoleRelay, admission.RoleServer, admission.RoleClient} {
		filename := enrollmentFiles[role]
		if filename == "" {
			continue
		}
		token, err := admission.LoadBearerTokenFile(filename)
		if err != nil {
			return caAuthentication{}, fmt.Errorf("load %s enrollment credential: %w", role, err)
		}
		if existing, duplicated := seen[token]; duplicated {
			return caAuthentication{}, fmt.Errorf("enrollment credentials for %s and %s must be distinct", existing, role)
		}
		seen[token] = role
		authentication.enrollmentTokens[role] = token
	}
	if adminFile != "" {
		token, err := admission.LoadBearerTokenFile(adminFile)
		if err != nil {
			return caAuthentication{}, fmt.Errorf("load admin credential: %w", err)
		}
		if role, duplicated := seen[token]; duplicated {
			return caAuthentication{}, fmt.Errorf("admin and %s enrollment credentials must be distinct", role)
		}
		authentication.adminToken = token
	}
	return authentication, nil
}

func (a caAuthentication) authenticateEnrollment(request *http.Request) (admission.Role, bool, bool) {
	if len(a.enrollmentTokens) == 0 {
		return "", false, true
	}
	provided, ok := requestBearerToken(request)
	matchedRole := admission.Role("")
	matched := 0
	if ok {
		for _, role := range []admission.Role{admission.RoleRelay, admission.RoleServer, admission.RoleClient} {
			expected, configured := a.enrollmentTokens[role]
			if configured && secureTokenEqual(provided, expected) {
				matchedRole = role
				matched++
			}
		}
	}
	return matchedRole, true, matched == 1
}

func (a caAuthentication) authenticateAdmin(request *http.Request) bool {
	provided, ok := requestBearerToken(request)
	return ok && secureTokenEqual(provided, a.adminToken)
}

func requestBearerToken(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	return token, token != "" && !strings.ContainsAny(token, " \t\r\n")
}

func secureTokenEqual(provided, expected string) bool {
	providedDigest := sha256.Sum256([]byte(provided))
	expectedDigest := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) == 1
}

func writeAuthenticationError(w http.ResponseWriter, status int, response any) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="bnfs-ca"`)
	writeJSON(w, status, response)
}

type validatedVoucher struct {
	request admission.VoucherSettleRequest
	voucher billingvoucher.MutualVoucher
	id      billingvoucher.Identifier
}

func validateVoucherRequest(caPrivateKey *ecdsa.PrivateKey, request admission.VoucherSettleRequest) (validatedVoucher, error) {
	if caPrivateKey == nil {
		return validatedVoucher{}, errors.New("CA signing key is unavailable")
	}
	if len(request.CanonicalVoucher) == 0 {
		return validatedVoucher{}, errBadRequest("缺少 canonical_voucher")
	}
	voucher, err := billingvoucher.ParseCanonicalVoucher(request.CanonicalVoucher)
	if err != nil {
		return validatedVoucher{}, errBadRequest("canonical_voucher 非法: " + err.Error())
	}
	voucherID, err := voucher.ID()
	if err != nil {
		return validatedVoucher{}, errBadRequest("计算 voucher_id 失败: " + err.Error())
	}
	payerPublicKey, err := parseIdentityPublicKey(request.PayerPublicKey)
	if err != nil {
		return validatedVoucher{}, errBadRequest("payer_public_key 非法: " + err.Error())
	}
	relayPublicKey, err := parseIdentityPublicKey(request.RelayPublicKey)
	if err != nil {
		return validatedVoucher{}, errBadRequest("relay_public_key 非法: " + err.Error())
	}
	if request.PayerCert == nil || request.RelayCert == nil {
		return validatedVoucher{}, errBadRequest("缺少 payer_cert / relay_cert")
	}
	if request.PayerCert.Cert.SubjectPubKey != request.PayerPublicKey || request.RelayCert.Cert.SubjectPubKey != request.RelayPublicKey {
		return validatedVoucher{}, errBadRequest("证书公钥与请求公钥不一致")
	}
	payerNodeID := voucher.Body.PayerNatID.String()
	relayNodeID := voucher.Body.PayeeRelayID.String()
	if err := admission.Verify(&caPrivateKey.PublicKey, request.PayerCert, admission.VerifyOptions{
		ExpectNodeID: payerNodeID,
		ExpectRole:   admission.RoleServer,
	}); err != nil {
		return validatedVoucher{}, errBadRequest("payer_cert 校验失败: " + err.Error())
	}
	if err := admission.Verify(&caPrivateKey.PublicKey, request.RelayCert, admission.VerifyOptions{
		ExpectNodeID: relayNodeID,
		ExpectRole:   admission.RoleRelay,
	}); err != nil {
		return validatedVoucher{}, errBadRequest("relay_cert 校验失败: " + err.Error())
	}
	if voucher.Body.PolicyDigest != billingvoucher.CurrentPolicyDigest() {
		return validatedVoucher{}, errBadRequest("voucher policy_digest 与 CA 固定策略不一致")
	}
	if voucher.Body.Direction != billingvoucher.DirectionPayerOutbound {
		return validatedVoucher{}, errBadRequest("voucher direction 不是 CA 支持的 payer outbound")
	}
	if voucher.Body.AuthorizedThroughBytes != billingvoucher.MaxBillableBytes {
		return validatedVoucher{}, errBadRequest("voucher authorized_through_bytes 与 CA 固定授权上限不一致")
	}
	if err := voucher.Verify(payerPublicKey, relayPublicKey); err != nil {
		return validatedVoucher{}, errBadRequest("双签凭证校验失败: " + err.Error())
	}
	return validatedVoucher{request: request, voucher: voucher, id: voucherID}, nil
}

func parseIdentityPublicKey(value string) (*ecdh.PublicKey, error) {
	if value == "" {
		return nil, errors.New("公钥为空")
	}
	encoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(encoded) != value {
		return nil, errors.New("公钥必须使用小写 canonical hex")
	}
	identity, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil, err
	}
	return identity, nil
}

// issue 校验申请并签发证书。
func issue(priv *ecdsa.PrivateKey, req admission.IssueRequest, issuer string, defaultTTL int64) (*admission.SignedCert, error) {
	if req.SubjectPubKey == "" {
		return nil, errBadRequest("缺少 subject_pubkey")
	}
	if !req.Role.Valid() {
		return nil, errBadRequest("非法角色: " + string(req.Role))
	}
	ttl := defaultTTL
	if req.TTLSeconds > 0 && req.TTLSeconds < defaultTTL {
		ttl = req.TTLSeconds // 允许申请更短，但不超过 CA 上限
	}
	nonce, err := admission.NewNonce()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cert := admission.Cert{
		SubjectNodeID: admission.NodeIDFromPubKeyHex(req.SubjectPubKey),
		SubjectPubKey: req.SubjectPubKey,
		Role:          req.Role,
		NotBefore:     now.Add(-60 * time.Second).Unix(), // 容忍轻微时钟偏差
		NotAfter:      now.Add(time.Duration(ttl) * time.Second).Unix(),
		Nonce:         nonce,
		Issuer:        issuer,
	}
	return admission.Sign(priv, cert)
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		return admission.ParseCAPrivateKeyPEM(string(data))
	}
	priv, err := admission.GenerateCAKey()
	if err != nil {
		return nil, err
	}
	pemStr, err := admission.MarshalCAPrivateKeyPEM(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(pemStr), 0o600); err != nil {
		return nil, err
	}
	log.Printf("[caserver] 已生成新签发密钥并持久化: %s", path)
	return priv, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type badRequestErr struct{ msg string }

func (e badRequestErr) Error() string { return e.msg }
func errBadRequest(msg string) error  { return badRequestErr{msg} }

func readJSON(r *http.Request, out any) error {
	const maximumJSONBody = 1 << 16
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumJSONBody+1))
	if err != nil {
		return errBadRequest("读取请求失败: " + err.Error())
	}
	if len(body) > maximumJSONBody {
		return errBadRequest("请求体超过 64 KiB 上限")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errBadRequest("解析请求失败: " + err.Error())
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errBadRequest("解析请求失败: JSON 后存在尾随数据")
	}
	return nil
}

const (
	ledgerFormatVersion            = 3
	legacyVoucherLedgerVersion     = 2
	recentVoucherDecisionCacheSize = 16
)

type channelWatermark struct {
	SessionID          string                   `json:"session_id"`
	PayerNodeID        string                   `json:"payer_node_id"`
	RelayNodeID        string                   `json:"relay_node_id"`
	Direction          billingvoucher.Direction `json:"direction"`
	PolicyDigest       string                   `json:"policy_digest"`
	Sequence           uint64                   `json:"sequence"`
	CumulativeBytes    uint64                   `json:"cumulative_bytes"`
	VoucherID          string                   `json:"voucher_id"`
	LastVoucher        []byte                   `json:"last_voucher"`
	LastRecordSequence uint64                   `json:"last_record_sequence"`
	GrossTotal         int64                    `json:"gross_total"`
	RelayTotal         int64                    `json:"relay_total"`
	CATotal            int64                    `json:"ca_total"`
	Frozen             bool                     `json:"frozen,omitempty"`
}

type voucherDecisionRecord struct {
	ChannelKey      string                          `json:"channel_key"`
	Sequence        uint64                          `json:"sequence"`
	CumulativeBytes uint64                          `json:"cumulative_bytes"`
	HTTPStatus      int                             `json:"http_status"`
	Disposition     string                          `json:"disposition"`
	Response        admission.VoucherSettleResponse `json:"response"`
}

type voucherEvidence struct {
	VoucherID        string               `json:"voucher_id"`
	CanonicalVoucher []byte               `json:"canonical_voucher"`
	PayerPublicKey   string               `json:"payer_public_key"`
	RelayPublicKey   string               `json:"relay_public_key"`
	PayerCert        admission.SignedCert `json:"payer_cert"`
	RelayCert        admission.SignedCert `json:"relay_cert"`
	RecordedAt       int64                `json:"recorded_at"`
	Disposition      string               `json:"disposition"`
}

type ledgerDiskState struct {
	Version           int                              `json:"version"`
	TransactionSeq    uint64                           `json:"transaction_sequence"`
	Balances          map[string]int64                 `json:"balances"`
	RelayIncome       map[string]int64                 `json:"relay_income"`
	CARevenue         int64                            `json:"ca_revenue"`
	Channels          map[string]channelWatermark      `json:"channels"`
	SessionBindings   map[string]string                `json:"session_bindings"`
	AcceptedSequences map[string]string                `json:"accepted_sequences"`
	Decisions         map[string]voucherDecisionRecord `json:"decisions"`
	Evidence          map[string]voucherEvidence       `json:"evidence"`
	DecisionOrder     []string                         `json:"decision_order"`
}

// ledger is the CA's authoritative accounting state. Each voucher settlement
// appends one bounded transaction to the fsynced WAL before applying it in
// memory; periodic snapshots compact the WAL without changing commit ordering.
type ledger struct {
	mu                sync.Mutex
	balances          map[string]int64
	relayIncome       map[string]int64
	caRevenue         int64
	channels          map[string]channelWatermark
	sessionBindings   map[string]string
	acceptedSequences map[string]string
	decisions         map[string]voucherDecisionRecord
	evidence          map[string]voucherEvidence
	decisionOrder     []string
	transactionSeq    uint64
	walTransactions   uint64
	path              string
	loadErr           error
}

func newLedger(path string) *ledger {
	l := &ledger{path: path}
	l.applyStateLocked(emptyLedgerState())
	if path == "" {
		return l
	}
	migrated := false
	data, err := os.ReadFile(path)
	if err == nil {
		state, snapshotMigrated, decodeErr := decodeLedgerState(data)
		if decodeErr != nil {
			l.loadErr = decodeErr
			return l
		}
		l.applyStateLocked(state)
		migrated = snapshotMigrated
	} else if !errors.Is(err, os.ErrNotExist) {
		l.loadErr = err
		return l
	}
	state, replayed, walRecords, repaired, err := loadLedgerWAL(path, l.stateLocked())
	if err != nil {
		l.loadErr = err
		return l
	}
	l.applyStateLocked(state)
	if migrated || walRecords > 0 || repaired {
		if err := l.persistStateLocked(state); err != nil {
			l.loadErr = fmt.Errorf("压缩启动账本快照: %w", err)
			return l
		}
		if err := resetLedgerWAL(path); err != nil {
			l.loadErr = fmt.Errorf("重置启动账本 WAL: %w", err)
			return l
		}
	}
	if migrated {
		log.Printf("[caserver] 已加载并迁移旧版账本为 v%d: %s", ledgerFormatVersion, path)
	} else {
		log.Printf("[caserver] 已加载账本: %s (%d 个账户, %d 个通道, 重放 %d 笔 WAL)", path, len(l.balances), len(l.channels), replayed)
	}
	return l
}

func emptyLedgerState() ledgerDiskState {
	return ledgerDiskState{
		Version:           ledgerFormatVersion,
		Balances:          make(map[string]int64),
		RelayIncome:       make(map[string]int64),
		Channels:          make(map[string]channelWatermark),
		SessionBindings:   make(map[string]string),
		AcceptedSequences: make(map[string]string),
		Decisions:         make(map[string]voucherDecisionRecord),
		Evidence:          make(map[string]voucherEvidence),
		DecisionOrder:     make([]string, 0, recentVoucherDecisionCacheSize),
	}
}

func decodeLedgerState(data []byte) (ledgerDiskState, bool, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return ledgerDiskState{}, false, fmt.Errorf("解析账本 JSON: %w", err)
	}
	if _, modern := object["balances"]; !modern {
		var balances map[string]int64
		if err := json.Unmarshal(data, &balances); err != nil {
			return ledgerDiskState{}, false, fmt.Errorf("解析旧版余额账本: %w", err)
		}
		state := emptyLedgerState()
		state.Balances = balances
		if state.Balances == nil {
			state.Balances = make(map[string]int64)
		}
		return state, true, nil
	}
	var state ledgerDiskState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return ledgerDiskState{}, false, fmt.Errorf("解析 v%d 账本: %w", ledgerFormatVersion, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ledgerDiskState{}, false, errors.New("账本 JSON 含尾随数据")
	}
	normalizeLedgerState(&state)
	migrated := false
	switch state.Version {
	case legacyVoucherLedgerVersion:
		if err := validateLegacyVoucherLedgerState(state); err != nil {
			return ledgerDiskState{}, false, err
		}
		migrateLegacyVoucherLedgerState(&state)
		migrated = true
	case ledgerFormatVersion:
	default:
		return ledgerDiskState{}, false, fmt.Errorf("不支持的账本版本 %d", state.Version)
	}
	if err := validateLedgerState(state); err != nil {
		return ledgerDiskState{}, false, err
	}
	return state, migrated, nil
}

func normalizeLedgerState(state *ledgerDiskState) {
	if state.Balances == nil {
		state.Balances = make(map[string]int64)
	}
	if state.RelayIncome == nil {
		state.RelayIncome = make(map[string]int64)
	}
	if state.Channels == nil {
		state.Channels = make(map[string]channelWatermark)
	}
	if state.SessionBindings == nil {
		state.SessionBindings = make(map[string]string)
	}
	if state.AcceptedSequences == nil {
		state.AcceptedSequences = make(map[string]string)
	}
	if state.Decisions == nil {
		state.Decisions = make(map[string]voucherDecisionRecord)
	}
	if state.Evidence == nil {
		state.Evidence = make(map[string]voucherEvidence)
	}
	if state.DecisionOrder == nil {
		state.DecisionOrder = make([]string, 0, recentVoucherDecisionCacheSize)
	}
}

func validateLedgerState(state ledgerDiskState) error {
	if state.Version != ledgerFormatVersion {
		return fmt.Errorf("不支持的账本版本 %d", state.Version)
	}
	if err := validateLedgerAccounting(state); err != nil {
		return err
	}
	if len(state.AcceptedSequences) != len(state.Channels) || len(state.SessionBindings) != len(state.Channels) {
		return errors.New("账本当前水位索引数量与通道数量不一致")
	}
	if err := validateChannelWatermarks(state); err != nil {
		return err
	}
	if len(state.Decisions) > recentVoucherDecisionCacheSize || len(state.Evidence) > recentVoucherDecisionCacheSize ||
		len(state.DecisionOrder) > recentVoucherDecisionCacheSize {
		return errors.New("账本近期凭证裁决缓存超过上限")
	}
	if len(state.Decisions) != len(state.Evidence) || len(state.Decisions) != len(state.DecisionOrder) {
		return errors.New("账本近期凭证裁决缓存索引不一致")
	}
	seen := make(map[string]struct{}, len(state.DecisionOrder))
	for _, voucherID := range state.DecisionOrder {
		if _, duplicate := seen[voucherID]; duplicate {
			return fmt.Errorf("账本近期凭证裁决顺序含重复 ID %s", voucherID)
		}
		seen[voucherID] = struct{}{}
		decision, ok := state.Decisions[voucherID]
		if !ok {
			return fmt.Errorf("账本近期凭证裁决顺序缺少裁决 %s", voucherID)
		}
		if err := validateDecisionEvidence(voucherID, decision, state.Evidence[voucherID]); err != nil {
			return err
		}
	}
	return nil
}

func validateLegacyVoucherLedgerState(state ledgerDiskState) error {
	if state.Version != legacyVoucherLedgerVersion {
		return fmt.Errorf("不是可迁移的 v%d 凭证账本", legacyVoucherLedgerVersion)
	}
	if err := validateLedgerAccounting(state); err != nil {
		return err
	}
	if err := validateChannelWatermarks(state); err != nil {
		return err
	}
	for sequenceKey, voucherID := range state.AcceptedSequences {
		decision, ok := state.Decisions[voucherID]
		if !ok || decision.Disposition != "settled" || acceptedSequenceKey(decision.ChannelKey, decision.Sequence) != sequenceKey {
			return fmt.Errorf("凭证序列索引 %s 缺少对应结算裁决", sequenceKey)
		}
	}
	if len(state.Decisions) != len(state.Evidence) {
		return errors.New("旧版账本裁决与证据数量不一致")
	}
	for voucherID, decision := range state.Decisions {
		if err := validateDecisionEvidence(voucherID, decision, state.Evidence[voucherID]); err != nil {
			return err
		}
	}
	return nil
}

func validateLedgerAccounting(state ledgerDiskState) error {
	if state.CARevenue < 0 {
		return errors.New("账本 CA revenue 不能为负")
	}
	for relayID, income := range state.RelayIncome {
		if relayID == "" || income < 0 {
			return errors.New("账本含非法 Relay income")
		}
	}
	return nil
}

func validateChannelWatermarks(state ledgerDiskState) error {
	for key, channel := range state.Channels {
		voucher, err := billingvoucher.ParseCanonicalVoucher(channel.LastVoucher)
		if err != nil {
			return fmt.Errorf("通道 %s 的水位凭证损坏: %w", key, err)
		}
		voucherID, err := voucher.ID()
		if err != nil || voucherID.String() != channel.VoucherID {
			return fmt.Errorf("通道 %s 的水位 voucher_id 不一致", key)
		}
		if voucherChannelKey(voucher.Body) != key || voucher.Body.Sequence != channel.Sequence ||
			voucher.Body.CumulativeUniqueBytes != channel.CumulativeBytes ||
			voucher.Body.LastRecordSequence != channel.LastRecordSequence {
			return fmt.Errorf("通道 %s 的持久化绑定或水位不一致", key)
		}
		if state.SessionBindings[channel.SessionID] != key {
			return fmt.Errorf("通道 %s 缺少 session binding", key)
		}
		if state.AcceptedSequences[acceptedSequenceKey(key, channel.Sequence)] != channel.VoucherID {
			return fmt.Errorf("通道 %s 缺少最高序列凭证索引", key)
		}
		relayTotal, caTotal, err := billingvoucher.CurrentPolicyCumulativeTotals(channel.CumulativeBytes)
		if err != nil || channel.GrossTotal != int64(channel.CumulativeBytes) ||
			channel.RelayTotal != int64(relayTotal) || channel.CATotal != int64(caTotal) {
			return fmt.Errorf("通道 %s 的累计策略金额不一致", key)
		}
	}
	return nil
}

func validateDecisionEvidence(voucherID string, decision voucherDecisionRecord, evidence voucherEvidence) error {
	if evidence.VoucherID != voucherID || evidence.Disposition != decision.Disposition {
		return fmt.Errorf("裁决 %s 缺少不可变证据", voucherID)
	}
	voucher, err := billingvoucher.ParseCanonicalVoucher(evidence.CanonicalVoucher)
	if err != nil {
		return fmt.Errorf("裁决 %s 的凭证证据损坏: %w", voucherID, err)
	}
	parsedID, err := voucher.ID()
	if err != nil || parsedID.String() != voucherID || voucher.Body.Sequence != decision.Sequence ||
		voucher.Body.CumulativeUniqueBytes != decision.CumulativeBytes {
		return fmt.Errorf("裁决 %s 与凭证证据不一致", voucherID)
	}
	return nil
}

func migrateLegacyVoucherLedgerState(state *ledgerDiskState) {
	type orderedDecision struct {
		voucherID  string
		recordedAt int64
	}
	ordered := make([]orderedDecision, 0, len(state.Decisions))
	for voucherID := range state.Decisions {
		ordered = append(ordered, orderedDecision{voucherID: voucherID, recordedAt: state.Evidence[voucherID].RecordedAt})
	}
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].recordedAt == ordered[right].recordedAt {
			return ordered[left].voucherID < ordered[right].voucherID
		}
		return ordered[left].recordedAt < ordered[right].recordedAt
	})
	if len(ordered) > recentVoucherDecisionCacheSize {
		ordered = ordered[len(ordered)-recentVoucherDecisionCacheSize:]
	}
	decisions := make(map[string]voucherDecisionRecord, len(ordered))
	evidence := make(map[string]voucherEvidence, len(ordered))
	order := make([]string, 0, len(ordered))
	for _, entry := range ordered {
		decisions[entry.voucherID] = state.Decisions[entry.voucherID]
		evidence[entry.voucherID] = state.Evidence[entry.voucherID]
		order = append(order, entry.voucherID)
	}
	accepted := make(map[string]string, len(state.Channels))
	for channelKey, channel := range state.Channels {
		accepted[acceptedSequenceKey(channelKey, channel.Sequence)] = channel.VoucherID
	}
	state.Version = ledgerFormatVersion
	state.AcceptedSequences = accepted
	state.Decisions = decisions
	state.Evidence = evidence
	state.DecisionOrder = order
}

func voucherChannelKey(body billingvoucher.VoucherBody) string {
	return body.SessionID.String() + "|" + body.PayerNatID.String() + "|" + body.PayeeRelayID.String() + "|" +
		strconv.FormatUint(uint64(body.Direction), 10) + "|" + body.PolicyDigest.String()
}

func acceptedSequenceKey(channelKey string, sequence uint64) string {
	return channelKey + "|" + strconv.FormatUint(sequence, 10)
}

func (l *ledger) settleVoucher(validated validatedVoucher) (admission.VoucherSettleResponse, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.loadErr != nil {
		return admission.VoucherSettleResponse{Error: "账本不可用: " + l.loadErr.Error()}, http.StatusInternalServerError
	}
	body := validated.voucher.Body
	voucherID := validated.id.String()
	channelKey := voucherChannelKey(body)
	payerID := body.PayerNatID.String()

	if prior, ok := l.decisions[voucherID]; ok {
		response := prior.Response
		response.Delta = 0
		response.RelayCredit = 0
		response.Balance = l.balances[payerID]
		response.Replayed = true
		if channel, exists := l.channels[prior.ChannelKey]; exists {
			response.Stale = body.Sequence < channel.Sequence
			response.Frozen = response.Frozen || channel.Frozen
		}
		response.Allow = response.Error == "" && response.Balance > 0 && !response.Frozen
		status := prior.HTTPStatus
		if status == 0 {
			status = http.StatusOK
		}
		return response, status
	}

	if boundKey, exists := l.sessionBindings[body.SessionID.String()]; exists && boundKey != channelKey {
		transaction := ledgerWALTransaction{}
		if channel, ok := l.channels[boundKey]; ok {
			channel.Frozen = true
			transaction.ChannelSet = map[string]channelWatermark{boundKey: channel}
		}
		response := admission.VoucherSettleResponse{
			VoucherID: voucherID,
			Balance:   l.balances[payerID],
			Frozen:    true,
			Error:     "session 已绑定到不同 payer/payee/direction/policy，通道已冻结",
		}
		return l.commitDecisionLocked(transaction, validated, boundKey, response, http.StatusConflict, "session_binding_conflict")
	}

	channel, hasChannel := l.channels[channelKey]
	if hasChannel && channel.Frozen {
		return admission.VoucherSettleResponse{
			VoucherID: voucherID,
			Balance:   l.balances[payerID],
			Frozen:    true,
			Error:     "通道已冻结",
		}, http.StatusConflict
	}

	previousCumulative := uint64(0)
	previousRelayTotal := uint64(0)
	previousCATotal := uint64(0)
	if !hasChannel {
		if body.Sequence != 1 {
			return admission.VoucherSettleResponse{
				VoucherID: voucherID,
				Balance:   l.balances[payerID],
				Error:     "新通道必须从 sequence=1 开始",
			}, http.StatusConflict
		}
	} else {
		previousVoucher, err := billingvoucher.ParseCanonicalVoucher(channel.LastVoucher)
		if err != nil {
			return admission.VoucherSettleResponse{VoucherID: voucherID, Error: "账本前驱凭证损坏: " + err.Error()}, http.StatusInternalServerError
		}
		if body.Sequence < channel.Sequence {
			return admission.VoucherSettleResponse{
				VoucherID: voucherID,
				Balance:   l.balances[payerID],
				Allow:     l.balances[payerID] > 0,
				Replayed:  true,
				Stale:     true,
			}, http.StatusOK
		}
		if body.Sequence == channel.Sequence {
			currentBodyID, currentErr := previousVoucher.Body.BodyID()
			incomingBodyID, incomingErr := body.BodyID()
			if currentErr != nil || incomingErr != nil {
				return admission.VoucherSettleResponse{VoucherID: voucherID, Error: "计算同序凭证主体 ID 失败"}, http.StatusInternalServerError
			}
			if currentBodyID == incomingBodyID {
				return admission.VoucherSettleResponse{
					VoucherID: voucherID,
					Balance:   l.balances[payerID],
					Allow:     l.balances[payerID] > 0,
					Replayed:  true,
				}, http.StatusOK
			}
			channel.Frozen = true
			transaction := ledgerWALTransaction{ChannelSet: map[string]channelWatermark{channelKey: channel}}
			response := admission.VoucherSettleResponse{
				VoucherID: voucherID,
				Balance:   l.balances[payerID],
				Frozen:    true,
				Error:     "相同 sequence 出现不同凭证主体，通道已冻结",
			}
			return l.commitDecisionLocked(transaction, validated, channelKey, response, http.StatusConflict, "sequence_fork")
		}
		if channel.Sequence == billingvoucher.MaxSequence || body.Sequence != channel.Sequence+1 {
			return admission.VoucherSettleResponse{
				VoucherID: voucherID,
				Balance:   l.balances[payerID],
				Error:     "voucher sequence 不连续",
			}, http.StatusConflict
		}
		if err := billingvoucher.ValidateSuccessor(previousVoucher, validated.voucher); err != nil {
			return admission.VoucherSettleResponse{
				VoucherID: voucherID,
				Balance:   l.balances[payerID],
				Error:     "voucher 前驱链校验失败: " + err.Error(),
			}, http.StatusConflict
		}
		previousCumulative = channel.CumulativeBytes
		previousRelayTotal = uint64(channel.RelayTotal)
		previousCATotal = uint64(channel.CATotal)
	}

	relayTotal, caTotal, err := billingvoucher.CurrentPolicyCumulativeTotals(body.CumulativeUniqueBytes)
	if err != nil || relayTotal < previousRelayTotal || caTotal < previousCATotal || body.CumulativeUniqueBytes < previousCumulative {
		return admission.VoucherSettleResponse{VoucherID: voucherID, Error: "固定策略累计金额非法"}, http.StatusConflict
	}
	grossDelta := body.CumulativeUniqueBytes - previousCumulative
	relayDelta := relayTotal - previousRelayTotal
	caDelta := caTotal - previousCATotal
	if grossDelta > uint64(maximumInt64) || relayDelta > uint64(maximumInt64) || caDelta > uint64(maximumInt64) {
		return admission.VoucherSettleResponse{VoucherID: voucherID, Error: "结算金额超出 int64 范围"}, http.StatusConflict
	}
	payerCurrentBalance := l.balances[payerID]
	if payerCurrentBalance < 0 || uint64(payerCurrentBalance) < grossDelta {
		return admission.VoucherSettleResponse{
			VoucherID: voucherID,
			Balance:   payerCurrentBalance,
			ErrorCode: admission.VoucherErrorInsufficientFunds,
			Retryable: true,
			Error:     "payer 余额不足，充值后可重试同一凭证",
		}, http.StatusPaymentRequired
	}
	payerBalance, ok := checkedAddInt64(payerCurrentBalance, -int64(grossDelta))
	if !ok {
		return admission.VoucherSettleResponse{VoucherID: voucherID, Error: "payer 余额发生整数下溢"}, http.StatusConflict
	}
	relayID := body.PayeeRelayID.String()
	relayBalance, ok := checkedAddInt64(l.balances[relayID], int64(relayDelta))
	if !ok {
		return admission.VoucherSettleResponse{VoucherID: voucherID, Error: "Relay 余额发生整数上溢"}, http.StatusConflict
	}
	relayIncome, ok := checkedAddInt64(l.relayIncome[relayID], int64(relayDelta))
	if !ok {
		return admission.VoucherSettleResponse{VoucherID: voucherID, Error: "Relay income 发生整数上溢"}, http.StatusConflict
	}
	caRevenue, ok := checkedAddInt64(l.caRevenue, int64(caDelta))
	if !ok {
		return admission.VoucherSettleResponse{VoucherID: voucherID, Error: "CA revenue 发生整数上溢"}, http.StatusConflict
	}

	transaction := ledgerWALTransaction{
		BalanceSet:       map[string]int64{payerID: payerBalance, relayID: relayBalance},
		RelayIncomeSet:   map[string]int64{relayID: relayIncome},
		CARevenueChanged: true,
		CARevenue:        caRevenue,
		SessionBindingSet: map[string]string{
			body.SessionID.String(): channelKey,
		},
		AcceptedSequenceSet: map[string]string{
			acceptedSequenceKey(channelKey, body.Sequence): voucherID,
		},
		ChannelSet: map[string]channelWatermark{
			channelKey: {
				SessionID:          body.SessionID.String(),
				PayerNodeID:        payerID,
				RelayNodeID:        relayID,
				Direction:          body.Direction,
				PolicyDigest:       body.PolicyDigest.String(),
				Sequence:           body.Sequence,
				CumulativeBytes:    body.CumulativeUniqueBytes,
				VoucherID:          voucherID,
				LastVoucher:        bytes.Clone(validated.request.CanonicalVoucher),
				LastRecordSequence: body.LastRecordSequence,
				GrossTotal:         int64(body.CumulativeUniqueBytes),
				RelayTotal:         int64(relayTotal),
				CATotal:            int64(caTotal),
			},
		},
	}
	if hasChannel {
		transaction.AcceptedSequenceDelete = []string{acceptedSequenceKey(channelKey, channel.Sequence)}
	}
	response := admission.VoucherSettleResponse{
		VoucherID:   voucherID,
		Delta:       int64(grossDelta),
		Balance:     payerBalance,
		RelayCredit: int64(relayDelta),
		Allow:       payerBalance > 0,
	}
	response, status := l.commitDecisionLocked(transaction, validated, channelKey, response, http.StatusOK, "settled")
	if status == http.StatusOK && (body.Sequence == 1 || body.Sequence%1024 == 0 || payerBalance <= 0) {
		log.Printf("[caserver] 双签结算: voucher=%.16s payer=%.16s relay=%.16s delta=%d relay_credit=%d balance=%d",
			voucherID, payerID, relayID, grossDelta, relayDelta, payerBalance)
	}
	return response, status
}

func (l *ledger) commitDecisionLocked(
	transaction ledgerWALTransaction,
	validated validatedVoucher,
	channelKey string,
	response admission.VoucherSettleResponse,
	status int,
	disposition string,
) (admission.VoucherSettleResponse, int) {
	voucherID := validated.id.String()
	body := validated.voucher.Body
	transaction.DecisionSet = map[string]voucherDecisionRecord{voucherID: {
		ChannelKey:      channelKey,
		Sequence:        body.Sequence,
		CumulativeBytes: body.CumulativeUniqueBytes,
		HTTPStatus:      status,
		Disposition:     disposition,
		Response:        response,
	}}
	transaction.EvidenceSet = map[string]voucherEvidence{voucherID: {
		VoucherID:        voucherID,
		CanonicalVoucher: bytes.Clone(validated.request.CanonicalVoucher),
		PayerPublicKey:   validated.request.PayerPublicKey,
		RelayPublicKey:   validated.request.RelayPublicKey,
		PayerCert:        *validated.request.PayerCert,
		RelayCert:        *validated.request.RelayCert,
		RecordedAt:       time.Now().UnixNano(),
		Disposition:      disposition,
	}}
	transaction.DecisionOrderChanged = true
	transaction.DecisionOrder = append(append([]string(nil), l.decisionOrder...), voucherID)
	for len(transaction.DecisionOrder) > recentVoucherDecisionCacheSize {
		evictedID := transaction.DecisionOrder[0]
		transaction.DecisionOrder = transaction.DecisionOrder[1:]
		transaction.DecisionDelete = append(transaction.DecisionDelete, evictedID)
		transaction.EvidenceDelete = append(transaction.EvidenceDelete, evictedID)
	}
	if err := l.commitTransactionLocked(transaction); err != nil {
		return admission.VoucherSettleResponse{
			VoucherID: voucherID,
			Balance:   l.balances[body.PayerNatID.String()],
			Error:     "持久化原子结算失败: " + err.Error(),
		}, http.StatusInternalServerError
	}
	return response, status
}

const (
	maximumInt64 = int64(^uint64(0) >> 1)
	minimumInt64 = -maximumInt64 - 1
)

func checkedAddInt64(left, right int64) (int64, bool) {
	if right > 0 && left > maximumInt64-right {
		return 0, false
	}
	if right < 0 && left < minimumInt64-right {
		return 0, false
	}
	return left + right, true
}

func (l *ledger) stateLocked() ledgerDiskState {
	state := ledgerDiskState{
		Version:           ledgerFormatVersion,
		TransactionSeq:    l.transactionSeq,
		Balances:          cloneMap(l.balances),
		RelayIncome:       cloneMap(l.relayIncome),
		CARevenue:         l.caRevenue,
		Channels:          cloneMap(l.channels),
		SessionBindings:   cloneMap(l.sessionBindings),
		AcceptedSequences: cloneMap(l.acceptedSequences),
		Decisions:         cloneMap(l.decisions),
		Evidence:          cloneMap(l.evidence),
		DecisionOrder:     append([]string(nil), l.decisionOrder...),
	}
	for key, channel := range state.Channels {
		channel.LastVoucher = bytes.Clone(channel.LastVoucher)
		state.Channels[key] = channel
	}
	for key, evidence := range state.Evidence {
		evidence.CanonicalVoucher = bytes.Clone(evidence.CanonicalVoucher)
		state.Evidence[key] = evidence
	}
	return state
}

func cloneMap[K comparable, V any](source map[K]V) map[K]V {
	cloned := make(map[K]V, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func (l *ledger) applyStateLocked(state ledgerDiskState) {
	normalizeLedgerState(&state)
	l.balances = state.Balances
	l.relayIncome = state.RelayIncome
	l.caRevenue = state.CARevenue
	l.channels = state.Channels
	l.sessionBindings = state.SessionBindings
	l.acceptedSequences = state.AcceptedSequences
	l.decisions = state.Decisions
	l.evidence = state.Evidence
	l.decisionOrder = state.DecisionOrder
	l.transactionSeq = state.TransactionSeq
}

func (l *ledger) commitTransactionLocked(transaction ledgerWALTransaction) error {
	if l.loadErr != nil {
		return l.loadErr
	}
	if l.transactionSeq == ^uint64(0) {
		return errors.New("账本事务序号已耗尽")
	}
	transaction.Version = ledgerWALFormatVersion
	transaction.Sequence = l.transactionSeq + 1
	if transaction.empty() {
		return errors.New("拒绝提交空账本事务")
	}
	if l.path != "" {
		if err := appendLedgerWAL(l.path, transaction); err != nil {
			l.loadErr = fmt.Errorf("账本 WAL 提交失败: %w", err)
			return l.loadErr
		}
	}
	state := ledgerDiskState{
		Version:           ledgerFormatVersion,
		TransactionSeq:    l.transactionSeq,
		Balances:          l.balances,
		RelayIncome:       l.relayIncome,
		CARevenue:         l.caRevenue,
		Channels:          l.channels,
		SessionBindings:   l.sessionBindings,
		AcceptedSequences: l.acceptedSequences,
		Decisions:         l.decisions,
		Evidence:          l.evidence,
		DecisionOrder:     l.decisionOrder,
	}
	applyLedgerWALTransaction(&state, transaction)
	l.applyStateLocked(state)
	if l.path == "" {
		return nil
	}
	l.walTransactions++
	if l.walTransactions < ledgerWALCompactionTransactionCount {
		return nil
	}
	snapshot := l.stateLocked()
	if err := l.persistStateLocked(snapshot); err != nil {
		l.loadErr = fmt.Errorf("账本 WAL 压缩快照失败: %w", err)
		log.Printf("[caserver] %v；当前事务已由 WAL 持久化，后续写入 fail-closed", l.loadErr)
		return nil
	}
	if err := resetLedgerWAL(l.path); err != nil {
		l.loadErr = fmt.Errorf("账本 WAL 压缩后重置失败: %w", err)
		log.Printf("[caserver] %v；当前事务已进入快照，后续写入 fail-closed", l.loadErr)
		return nil
	}
	l.walTransactions = 0
	return nil
}

func (l *ledger) persistStateLocked(state ledgerDiskState) error {
	if err := validateLedgerState(state); err != nil {
		return fmt.Errorf("拒绝持久化非法账本: %w", err)
	}
	if l.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("编码账本: %w", err)
	}
	data = append(data, '\n')
	directory := filepath.Dir(l.path)
	temporary, err := os.CreateTemp(directory, ".ca-ledger-*.tmp")
	if err != nil {
		return fmt.Errorf("创建账本临时文件: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("设置账本临时文件权限: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("写账本临时文件: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("同步账本临时文件: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("关闭账本临时文件: %w", err)
	}
	if err := os.Rename(temporaryPath, l.path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("原子替换账本: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("打开账本目录: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("同步账本目录: %w", err)
	}
	return nil
}

func (l *ledger) creditChecked(nodeID string, add int64) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.loadErr != nil {
		return 0, l.loadErr
	}
	if add <= 0 {
		return l.balances[nodeID], errors.New("充值金额必须为正数")
	}
	current := l.balances[nodeID]
	balance, ok := checkedAddInt64(current, add)
	if !ok {
		return current, errors.New("余额发生整数上溢")
	}
	transaction := ledgerWALTransaction{BalanceSet: map[string]int64{nodeID: balance}}
	if err := l.commitTransactionLocked(transaction); err != nil {
		return l.balances[nodeID], err
	}
	return balance, nil
}

func (l *ledger) credit(nodeID string, add int64) int64 {
	balance, err := l.creditChecked(nodeID, add)
	if err != nil {
		log.Printf("[caserver] 充值失败: %v", err)
	}
	return balance
}

func (l *ledger) debit(nodeID string, used int64) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if used <= 0 || l.loadErr != nil {
		return l.balances[nodeID]
	}
	current := l.balances[nodeID]
	balance, ok := checkedAddInt64(current, -used)
	if !ok {
		return current
	}
	transaction := ledgerWALTransaction{BalanceSet: map[string]int64{nodeID: balance}}
	if err := l.commitTransactionLocked(transaction); err != nil {
		log.Printf("[caserver] 扣款持久化失败: %v", err)
		return l.balances[nodeID]
	}
	return balance
}

func (l *ledger) reserve(clientID string, clientFee int64, serverID string, serverFee int64) (allow bool, clientBalance, serverBalance int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	clientCurrent, serverCurrent := l.balances[clientID], l.balances[serverID]
	if clientFee < 0 || serverFee < 0 || clientCurrent < clientFee || serverCurrent < serverFee || l.loadErr != nil {
		return false, clientCurrent, serverCurrent
	}
	balances := make(map[string]int64, 2)
	balances[clientID] = clientCurrent - clientFee
	balances[serverID] = serverCurrent - serverFee
	transaction := ledgerWALTransaction{BalanceSet: balances}
	if err := l.commitTransactionLocked(transaction); err != nil {
		log.Printf("[caserver] 保证金持久化失败: %v", err)
		return false, clientCurrent, serverCurrent
	}
	return true, l.balances[clientID], l.balances[serverID]
}

func (l *ledger) balance(nodeID string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.balances[nodeID]
}

func (l *ledger) relayIncomeTotal(nodeID string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.relayIncome[nodeID]
}

func (l *ledger) caRevenueTotal() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.caRevenue
}
