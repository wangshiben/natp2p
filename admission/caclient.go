package admission

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CAClient 是框架侧访问独立 CA/indexServer Web 服务的轻客户端。
//
// 职责（决策 A 的框架侧）：
//   - RefreshPubKey：向 CA 拉取最新公钥并【缓存】；
//   - Verify：用缓存的公钥【离线】验签，之后不再请求 CA；
//   - Issue（可选）：帮节点向 CA 申请证书（多数场景由运维离线申请，此方法便于测试/自动化）。
//
// 与框架其它包解耦：只依赖标准库 + 本包。
type CAClient struct {
	baseURL string
	http    *http.Client

	mu         sync.RWMutex
	caPub      *ecdsa.PublicKey
	issuer     string
	issueToken string
	adminToken string
}

// SetIssueBearerToken configures the role-scoped credential used only for
// certificate enrollment. It is never attached to settlement requests.
func (c *CAClient) SetIssueBearerToken(token string) error {
	if err := ValidateBearerToken(token); err != nil {
		return err
	}
	c.mu.Lock()
	c.issueToken = token
	c.mu.Unlock()
	return nil
}

// SetIssueBearerTokenFile loads the enrollment credential from a private
// file, keeping it out of command lines and generated Compose documents.
func (c *CAClient) SetIssueBearerTokenFile(filename string) error {
	token, err := LoadBearerTokenFile(filename)
	if err != nil {
		return err
	}
	return c.SetIssueBearerToken(token)
}

// SetAdminBearerToken configures the credential for explicit administrative
// mutations such as /credit.
func (c *CAClient) SetAdminBearerToken(token string) error {
	if err := ValidateBearerToken(token); err != nil {
		return err
	}
	c.mu.Lock()
	c.adminToken = token
	c.mu.Unlock()
	return nil
}

// SetAdminBearerTokenFile loads the administrative credential from disk.
func (c *CAClient) SetAdminBearerTokenFile(filename string) error {
	token, err := LoadBearerTokenFile(filename)
	if err != nil {
		return err
	}
	return c.SetAdminBearerToken(token)
}

// NewCAClient 创建一个指向 baseURL（如 "http://203.0.113.10:9000"）的 CA 客户端。
func NewCAClient(baseURL string) *CAClient {
	return &CAClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// RefreshPubKey 从 CA 拉取最新公钥并缓存。relay 启动/注册时调用一次即可。
func (c *CAClient) RefreshPubKey(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+PathPubKey, nil)
	if err != nil {
		return fmt.Errorf("admission: 构造 /pubkey 请求失败: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("admission: 请求 CA /pubkey 失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("admission: 读取 /pubkey 应答失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admission: CA /pubkey 返回 %d: %s", resp.StatusCode, string(body))
	}
	var pr PubKeyResp
	if err := json.Unmarshal(body, &pr); err != nil {
		return fmt.Errorf("admission: 解析 /pubkey 应答失败: %w", err)
	}
	pub, err := ParseCAPublicKeyPEM(pr.PubKeyPEM)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.caPub = pub
	c.issuer = pr.Issuer
	c.mu.Unlock()
	return nil
}

// SetPubKeyPEM 直接注入 CA 公钥 PEM（用于「用启动参数内置公钥」的回退分发信道，
// 或测试）。与 RefreshPubKey 二选一即可。
func (c *CAClient) SetPubKeyPEM(pemStr string) error {
	pub, err := ParseCAPublicKeyPEM(pemStr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.caPub = pub
	c.mu.Unlock()
	return nil
}

// HasPubKey 报告是否已缓存 CA 公钥（可离线验签）。
func (c *CAClient) HasPubKey() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.caPub != nil
}

// Verify 用缓存的 CA 公钥离线验签。未缓存公钥时返回错误。
func (c *CAClient) Verify(sc *SignedCert, opts VerifyOptions) error {
	c.mu.RLock()
	pub := c.caPub
	c.mu.RUnlock()
	if pub == nil {
		return fmt.Errorf("admission: 尚未缓存 CA 公钥, 无法验签（请先 RefreshPubKey 或 SetPubKeyPEM）")
	}
	return Verify(pub, sc, opts)
}

// Issue 向 CA 申请一张证书（便于测试/自动化；生产中申请多为离线人工流程）。
func (c *CAClient) Issue(ctx context.Context, reqBody IssueRequest) (*SignedCert, error) {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("admission: 编码 /issue 请求失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+PathIssue, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("admission: 构造 /issue 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.authorize(req, PathIssue)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admission: 请求 CA /issue 失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("admission: 读取 /issue 应答失败: %w", err)
	}
	var ir IssueResponse
	if err := json.Unmarshal(body, &ir); err != nil {
		return nil, fmt.Errorf("admission: 解析 /issue 应答失败 (status=%d body=%s): %w", resp.StatusCode, string(body), err)
	}
	if ir.Error != "" {
		return nil, fmt.Errorf("admission: CA 签发失败: %s", ir.Error)
	}
	if ir.SignedCert == nil {
		return nil, fmt.Errorf("admission: CA 未返回证书 (status=%d)", resp.StatusCode)
	}
	return ir.SignedCert, nil
}

// AuthorizeNode 使用节点身份与用户扣费密钥的双重持有证明申请绑定证书。
// 该端点不使用 Enrollment Token，授权能力来自扣费私钥签名本身。
func (c *CAClient) AuthorizeNode(ctx context.Context, request NodeAuthorizationRequest) (*NodeAuthorizationResponse, error) {
	var response NodeAuthorizationResponse
	status, err := c.postJSONStatus(ctx, PathAuthorizeNode, request, &response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return &response, fmt.Errorf("admission: CA 节点授权失败: %s", response.Error)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return &response, fmt.Errorf("admission: CA 节点授权返回 %d", status)
	}
	if response.SignedCert == nil || response.AuthorizationID == "" || response.NodeID == "" {
		return nil, errors.New("admission: CA 节点授权应答不完整")
	}
	return &response, nil
}

// Settle 向 CA 上报某 serverNode 的上行用量增量并取回余额裁决。
// relay 的周期结算循环调用它；返回的 SettleResponse.Allow=false 表示应熔断该节点。
func (c *CAClient) Settle(ctx context.Context, req SettleRequest) (*SettleResponse, error) {
	var out SettleResponse
	if err := c.postJSON(ctx, PathSettle, req, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return nil, fmt.Errorf("admission: CA 结算失败: %s", out.Error)
	}
	return &out, nil
}

// SettleVoucher submits a canonical double-signed cumulative voucher to the
// CA. When the CA rejects it, the response is returned together with the error
// so callers can distinguish retryable conditions from terminal rejections.
func (c *CAClient) SettleVoucher(ctx context.Context, req VoucherSettleRequest) (*VoucherSettleResponse, error) {
	var out VoucherSettleResponse
	status, err := c.postJSONStatus(ctx, PathVoucherSettle, req, &out)
	if err != nil {
		if status >= http.StatusInternalServerError {
			return &VoucherSettleResponse{
				Retryable: true, ErrorCode: VoucherErrorTemporarilyUnavailable,
				Error: fmt.Sprintf("CA 暂时不可用 (status=%d)", status),
			}, fmt.Errorf("admission: CA 双签凭证结算暂时失败: %w", err)
		}
		return nil, err
	}
	if status >= http.StatusInternalServerError {
		out.Retryable = true
		out.ErrorCode = VoucherErrorTemporarilyUnavailable
		if out.Error == "" {
			out.Error = fmt.Sprintf("CA 暂时不可用 (status=%d)", status)
		}
	}
	if out.Error != "" {
		return &out, fmt.Errorf("admission: CA 双签凭证结算失败: %s", out.Error)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		out.Error = fmt.Sprintf("CA 拒绝双签凭证结算 (status=%d)", status)
		return &out, fmt.Errorf("admission: %s", out.Error)
	}
	return &out, nil
}

// Reserve 在建立一条业务连接时向 CA 请求「连接保证金」双扣（client 与 server 各扣一笔入场费）。
// 返回 Allow=false 表示至少一方余额不足、应拒绝建连。
func (c *CAClient) Reserve(ctx context.Context, req ReserveRequest) (*ReserveResponse, error) {
	var out ReserveResponse
	if err := c.postJSON(ctx, PathReserve, req, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return nil, fmt.Errorf("admission: CA 连接保证金预扣失败: %s", out.Error)
	}
	return &out, nil
}

// Credit 给某节点充值（增加余额）。MVP/测试用。
func (c *CAClient) Credit(ctx context.Context, req CreditRequest) (*CreditResponse, error) {
	var out CreditResponse
	if err := c.postJSON(ctx, PathCredit, req, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return nil, fmt.Errorf("admission: CA 充值失败: %s", out.Error)
	}
	return &out, nil
}

// postJSON 是内部 helper：POST 一个 JSON body 并把应答解码进 out。
func (c *CAClient) postJSON(ctx context.Context, path string, body any, out any) error {
	status, err := c.postJSONStatus(ctx, path, body, out)
	if err != nil {
		return err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return fmt.Errorf("admission: CA %s 返回 %d", path, status)
	}
	return nil
}

func (c *CAClient) postJSONStatus(ctx context.Context, path string, body any, out any) (int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("admission: 编码 %s 请求失败: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("admission: 构造 %s 请求失败: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.authorize(req, path)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("admission: 请求 %s 失败: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("admission: 读取 %s 应答失败: %w", path, err)
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return resp.StatusCode, fmt.Errorf("admission: 解析 %s 应答失败 (status=%d body=%s): %w", path, resp.StatusCode, string(respBody), err)
	}
	return resp.StatusCode, nil
}

func (c *CAClient) authorize(request *http.Request, path string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	token := ""
	switch path {
	case PathIssue:
		token = c.issueToken
	case PathCredit:
		token = c.adminToken
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
}
