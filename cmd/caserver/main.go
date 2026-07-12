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
// ⚠️ MVP 局限（生产需补全）：/issue 目前「按申请即签发」，不做申请方身份核验/付费校验/角色审批。
// 这些属于 Web 应用的业务逻辑，应在正式实现里加上；此处仅为打通端到端准入与后续计费联调。
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"bnfs_p2p/admission"
)

func main() {
	listen := flag.String("listen", ":9000", "HTTP 监听地址")
	keyFile := flag.String("key", "ca_key.pem", "CA 签发私钥 PEM 文件（不存在则生成）")
	issuer := flag.String("issuer", "bnfs-ca", "CA 标识（写入证书 Issuer / /pubkey 应答）")
	defaultTTL := flag.Int64("ttl", 24*3600, "默认证书有效期（秒），也是签发上限")
	ledgerFile := flag.String("ledger", "ca_ledger.json", "计费账本落盘文件（不存在则新建；每次变更写回）")
	flag.Parse()

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

	mux := http.NewServeMux()

	// GET /pubkey：返回 CA 公钥。relay 拉取后缓存、离线验签。
	mux.HandleFunc(admission.PathPubKey, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, admission.PubKeyResp{PubKeyPEM: pubPEM, Issuer: *issuer})
	})

	// POST /issue：签发证书。
	mux.HandleFunc(admission.PathIssue, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, admission.IssueResponse{Error: "读取请求失败: " + err.Error()})
			return
		}
		var req admission.IssueRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, admission.IssueResponse{Error: "解析请求失败: " + err.Error()})
			return
		}
		sc, err := issue(priv, req, *issuer, *defaultTTL)
		if err != nil {
			log.Printf("[caserver] /issue 拒绝: %v", err)
			writeJSON(w, http.StatusBadRequest, admission.IssueResponse{Error: err.Error()})
			return
		}
		log.Printf("[caserver] 已签发: nodeID=%.16s role=%s ttl<=%ds", sc.Cert.SubjectNodeID, sc.Cert.Role, *defaultTTL)
		writeJSON(w, http.StatusOK, admission.IssueResponse{SignedCert: sc})
	})

	// 计费账本（阶段4）：CA web 服务持有权威余额。
	ledger := newLedger(*ledgerFile)

	// POST /credit：给某节点充值（MVP/测试；生产由支付系统驱动）。
	mux.HandleFunc(admission.PathCredit, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req admission.CreditRequest
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, admission.CreditResponse{Error: err.Error()})
			return
		}
		if req.NodeID == "" {
			writeJSON(w, http.StatusBadRequest, admission.CreditResponse{Error: "缺少 node_id"})
			return
		}
		bal := ledger.credit(req.NodeID, req.AddBytes)
		log.Printf("[caserver] 充值: nodeID=%.16s +%dB 余额=%dB", req.NodeID, req.AddBytes, bal)
		writeJSON(w, http.StatusOK, admission.CreditResponse{Balance: bal})
	})

	// POST /settle：relay 上报某节点上行用量增量，扣减余额并裁决是否放行。
	mux.HandleFunc(admission.PathSettle, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req admission.SettleRequest
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, admission.SettleResponse{Error: err.Error()})
			return
		}
		if req.NodeID == "" {
			writeJSON(w, http.StatusBadRequest, admission.SettleResponse{Error: "缺少 node_id"})
			return
		}
		bal := ledger.debit(req.NodeID, req.UsedDelta)
		allow := bal > 0
		log.Printf("[caserver] 结算: nodeID=%.16s relay=%.16s used+=%dB 余额=%dB allow=%v",
			req.NodeID, req.RelayNodeID, req.UsedDelta, bal, allow)
		writeJSON(w, http.StatusOK, admission.SettleResponse{Balance: bal, Allow: allow})
	})

	// GET /balance?node=<id>：查询某节点余额（排障/展示）。
	mux.HandleFunc(admission.PathBalance, func(w http.ResponseWriter, r *http.Request) {
		node := r.URL.Query().Get("node")
		writeJSON(w, http.StatusOK, map[string]int64{"balance": ledger.balance(node)})
	})

	// POST /reserve：连接保证金双扣。建连时对 client/server 各扣一笔入场费，任一方不足则拒绝。
	mux.HandleFunc(admission.PathReserve, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req admission.ReserveRequest
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, admission.ReserveResponse{Error: err.Error()})
			return
		}
		if req.ClientNodeID == "" || req.ServerNodeID == "" {
			writeJSON(w, http.StatusBadRequest, admission.ReserveResponse{Error: "缺少 client_node_id / server_node_id"})
			return
		}
		allow, cBal, sBal := ledger.reserve(req.ClientNodeID, req.ClientFee, req.ServerNodeID, req.ServerFee)
		log.Printf("[caserver] 连接保证金: conn=%s client=%.16s(-%dB→%dB) server=%.16s(-%dB→%dB) allow=%v",
			req.ConnID, req.ClientNodeID, req.ClientFee, cBal, req.ServerNodeID, req.ServerFee, sBal, allow)
		writeJSON(w, http.StatusOK, admission.ReserveResponse{Allow: allow, ClientBalance: cBal, ServerBalance: sBal})
	})

	srv := &http.Server{
		Addr:         *listen,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[caserver] 服务退出: %v", err)
	}
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
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		return errBadRequest("读取请求失败: " + err.Error())
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errBadRequest("解析请求失败: " + err.Error())
	}
	return nil
}

// ledger 是 CA 侧的权威计费账本。key = 节点 NodeId，value = 余额字节。
//
// 落盘：每次变更后写回 JSON 文件（path），进程/机器重启后 load 恢复余额——
// 连接保证金/上行结算的余额是唯一真相源，不能随进程丢失（修复报告 §4/P2）。
// 余额可为负（透支），由 /settle 的 Allow 裁决是否继续放行。
type ledger struct {
	mu       sync.Mutex
	balances map[string]int64
	path     string
}

// newLedger 创建账本；若 path 存在则加载已有余额。
func newLedger(path string) *ledger {
	l := &ledger{balances: make(map[string]int64), path: path}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, &l.balances); err != nil {
				log.Printf("[caserver] 账本文件解析失败(忽略, 从空开始): %v", err)
				l.balances = make(map[string]int64)
			} else {
				log.Printf("[caserver] 已加载账本: %s (%d 个账户)", path, len(l.balances))
			}
		}
	}
	return l
}

// persistLocked 把当前余额写回落盘文件。调用方须持有 l.mu。
func (l *ledger) persistLocked() {
	if l.path == "" {
		return
	}
	data, err := json.MarshalIndent(l.balances, "", "  ")
	if err != nil {
		log.Printf("[caserver] 账本编码失败: %v", err)
		return
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("[caserver] 账本写临时文件失败: %v", err)
		return
	}
	if err := os.Rename(tmp, l.path); err != nil { // 原子替换，避免写一半崩溃损坏账本
		log.Printf("[caserver] 账本原子替换失败: %v", err)
	}
}

// credit 增加余额，返回新余额。
func (l *ledger) credit(nodeID string, add int64) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.balances[nodeID] += add
	l.persistLocked()
	return l.balances[nodeID]
}

// debit 扣减用量，返回扣减后余额（可为负）。
func (l *ledger) debit(nodeID string, used int64) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.balances[nodeID] -= used
	l.persistLocked()
	return l.balances[nodeID]
}

// reserve 是连接保证金的【原子双扣】：仅当 client 与 server 余额【都】足够各自的入场费时，
// 才一起扣减并返回 allow=true；任一方不足则都不扣、返回 allow=false（附当前未扣余额）。
func (l *ledger) reserve(clientID string, clientFee int64, serverID string, serverFee int64) (allow bool, cBal, sBal int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cCur, sCur := l.balances[clientID], l.balances[serverID]
	if cCur < clientFee || sCur < serverFee {
		return false, cCur, sCur // 任一方不足：都不扣
	}
	l.balances[clientID] = cCur - clientFee
	l.balances[serverID] = sCur - serverFee
	l.persistLocked()
	return true, l.balances[clientID], l.balances[serverID]
}

// balance 返回当前余额。
func (l *ledger) balance(nodeID string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.balances[nodeID]
}
