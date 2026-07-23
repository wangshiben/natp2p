package relaynode

// 本文件是对外部 CA 服务的可选活体回归测试：
// 仅当环境变量 BNFS_LIVE_CA 指向测试端点（可经延迟代理）时运行，否则跳过。
//
// 它验证部署 CA 已将两个单边计费写端点永久退役：/reserve 与 /settle 都必须返回 410；
// 当前扣款只能由双签累计凭证端点完成。
//
// 运行:
//   BNFS_LIVE_CA=http://127.0.0.1:9001 go test ./p2pnode/impl/relaynode/ \
//       -run TestLiveLegacyBillingEndpointsAreGone -v -count=1

import (
	"bnfs_p2p/admission"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveLegacyBillingEndpointsAreGone(t *testing.T) {
	caURL := strings.TrimRight(os.Getenv("BNFS_LIVE_CA"), "/")
	if caURL == "" {
		t.Skip("设置 BNFS_LIVE_CA=http://127.0.0.1:9001（可选延迟代理测试端点）才运行活体演示")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, endpoint := range []string{admission.PathReserve, admission.PathSettle} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, caURL+endpoint, strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("构造 %s 探测请求失败: %v", endpoint, err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("请求部署 CA %s 失败: %v", endpoint, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatalf("读取部署 CA %s 响应失败: %v", endpoint, readErr)
		}
		if resp.StatusCode != http.StatusGone {
			t.Fatalf("部署 CA %s status=%d, want 410; body=%s", endpoint, resp.StatusCode, string(body))
		}
	}
}
