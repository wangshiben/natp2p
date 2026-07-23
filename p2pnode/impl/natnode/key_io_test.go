package natnode

import (
	"bnfs_p2p/crypoto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestExportLoadPrivateKey_RoundTrip 验证：
//  1. NewNATNode → ExportPrivateKeyHex → LoadPrivateKeyFromHex → NewNATNode 后,
//     新节点的 ID 与原节点完全一致（即身份恢复）;
//  2. 对应的公钥 hex 也一致。
//
// 注意：本测试不依赖网络/relay, 只用 NewNATNode 的 bootstrapRelay 占位字符串。
// 我们仅校验 identity 和 pubkey, 不调用 Listen, 不会真的拨号。
func TestExportLoadPrivateKey_RoundTrip(t *testing.T) {
	const fakeRelay = "127.0.0.1:0"

	original, err := NewNATNode(nil, fakeRelay)
	if err != nil {
		t.Fatalf("创建原节点失败: %v", err)
	}
	defer original.Close()

	hexStr := original.ExportPrivateKeyHex()
	if hexStr == "" {
		t.Fatal("ExportPrivateKeyHex 返回空")
	}
	t.Logf("原节点 ID: %s", original.ID())
	t.Logf("私钥 hex 长度: %d", len(hexStr))

	priv, err := LoadPrivateKeyFromHex(hexStr)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromHex 失败: %v", err)
	}

	restored, err := NewNATNode(priv, fakeRelay)
	if err != nil {
		t.Fatalf("用还原私钥创建节点失败: %v", err)
	}
	defer restored.Close()

	if original.ID() != restored.ID() {
		t.Fatalf("还原节点 ID 不一致:\n原: %s\n新: %s", original.ID(), restored.ID())
	}
	if original.identity.Pubkey() != restored.identity.Pubkey() {
		t.Fatalf("还原节点 公钥 不一致")
	}
	// 对称性：再次导出应当得到相同的 hex
	if hexStr != restored.ExportPrivateKeyHex() {
		t.Fatal("再次导出私钥与首次不一致")
	}
}

func TestLoadOrCreatePrivateKeyFileConcurrentStableIdentity(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "identities", "relay.key")
	const workers = 32
	keys := make([]string, workers)
	errorsByWorker := make([]error, workers)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			privateKey, err := LoadOrCreatePrivateKeyFile(keyPath)
			errorsByWorker[index] = err
			if err == nil {
				keys[index] = crypoto.GetPrivKeyStr(privateKey)
			}
		}(worker)
	}
	waitGroup.Wait()
	for worker, err := range errorsByWorker {
		if err != nil {
			t.Fatalf("worker %d: %v", worker, err)
		}
		if keys[worker] != keys[0] {
			t.Fatalf("worker %d returned a different Relay identity", worker)
		}
	}
	restarted, err := LoadOrCreatePrivateKeyFile(keyPath)
	if err != nil {
		t.Fatalf("restart load: %v", err)
	}
	if crypoto.GetPrivKeyStr(restarted) != keys[0] {
		t.Fatal("restart did not reuse the persisted Relay identity")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestLoadOrCreatePrivateKeyFileCorruptFailsClosed(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "relay.key")
	if err := os.WriteFile(keyPath, []byte("corrupt-identity"), 0o600); err != nil {
		t.Fatalf("seed corrupt identity: %v", err)
	}
	if _, err := LoadOrCreatePrivateKeyFile(keyPath); err == nil {
		t.Fatal("corrupt persisted identity must fail closed")
	}
	contents, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read corrupt identity: %v", err)
	}
	if string(contents) != "corrupt-identity" {
		t.Fatal("corrupt identity was overwritten")
	}
}

func TestLoadPrivateKeyFromFileAcceptsRawP256Identity(t *testing.T) {
	privateKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatalf("生成测试身份失败: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "raw-identity.key")
	if err := os.WriteFile(keyPath, privateKey.Bytes(), 0o600); err != nil {
		t.Fatalf("写入原始身份失败: %v", err)
	}
	loaded, err := LoadPrivateKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("加载原始身份失败: %v", err)
	}
	if crypoto.GetPrivKeyStr(loaded) != crypoto.GetPrivKeyStr(privateKey) {
		t.Fatal("原始身份加载后发生变化")
	}
}

// TestSavePrivateKey_FileRoundTrip 验证 SavePrivateKey + LoadPrivateKeyFromFile 的端到端往返。
// 同时覆盖文件权限（0600）和首尾空白被 trim 的容错。
func TestSavePrivateKey_FileRoundTrip(t *testing.T) {
	const fakeRelay = "127.0.0.1:0"
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")

	original, err := NewNATNode(nil, fakeRelay)
	if err != nil {
		t.Fatalf("创建节点失败: %v", err)
	}
	defer original.Close()

	if err := original.SavePrivateKey(keyPath); err != nil {
		t.Fatalf("SavePrivateKey 失败: %v", err)
	}

	// 文件确实存在且非空
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat 文件失败: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("私钥文件为空")
	}

	// 直接从文件加载并校验恢复后的身份
	priv, err := LoadPrivateKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile 失败: %v", err)
	}
	restored, err := NewNATNode(priv, fakeRelay)
	if err != nil {
		t.Fatalf("用还原私钥创建节点失败: %v", err)
	}
	defer restored.Close()

	if original.ID() != restored.ID() {
		t.Fatalf("还原节点 ID 不一致:\n原: %s\n新: %s", original.ID(), restored.ID())
	}

	// 容错：手动写入带前后空白的副本, LoadPrivateKeyFromFile 仍应解析成功
	pollutedPath := filepath.Join(dir, "node_padded.key")
	hexStr := original.ExportPrivateKeyHex()
	padded := "  \n\t" + hexStr + "\n\n"
	if err := os.WriteFile(pollutedPath, []byte(padded), 0o600); err != nil {
		t.Fatalf("写带空白的私钥文件失败: %v", err)
	}
	priv2, err := LoadPrivateKeyFromFile(pollutedPath)
	if err != nil {
		t.Fatalf("加载带空白的私钥文件失败: %v", err)
	}
	if crypoto.GetPrivKeyStr(priv2) != hexStr {
		t.Fatal("带空白的私钥文件还原结果与原私钥不符")
	}
}

// TestLoadPrivateKey_Errors 覆盖错误路径，避免 silent failure 时
// 控制台只打印「创建节点失败」却不知道原因。
func TestLoadPrivateKey_Errors(t *testing.T) {
	t.Run("空 hex", func(t *testing.T) {
		if _, err := LoadPrivateKeyFromHex(""); err == nil {
			t.Fatal("空字符串应返回 error")
		}
	})

	t.Run("非法 hex", func(t *testing.T) {
		_, err := LoadPrivateKeyFromHex("zzz-not-hex")
		if err == nil || !strings.Contains(err.Error(), "解析私钥") {
			t.Fatalf("期望含「解析私钥」的 error, 实际: %v", err)
		}
	})

	t.Run("文件不存在", func(t *testing.T) {
		_, err := LoadPrivateKeyFromFile(filepath.Join(t.TempDir(), "no_such.key"))
		if err == nil || !strings.Contains(err.Error(), "读取私钥文件") {
			t.Fatalf("期望含「读取私钥文件」的 error, 实际: %v", err)
		}
	})

	t.Run("空路径", func(t *testing.T) {
		if _, err := LoadPrivateKeyFromFile(""); err == nil {
			t.Fatal("空路径应返回 error")
		}
	})
}

// TestSavePrivateKey_EmptyPath 简单守护：避免误传空 path 导致写到当前目录的奇怪文件名。
func TestSavePrivateKey_EmptyPath(t *testing.T) {
	node, err := NewNATNode(nil, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("创建节点失败: %v", err)
	}
	defer node.Close()
	if err := node.SavePrivateKey(""); err == nil {
		t.Fatal("SavePrivateKey 接收空路径应返回 error")
	}
}
