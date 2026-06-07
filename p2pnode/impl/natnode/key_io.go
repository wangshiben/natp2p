package natnode

import (
	"bnfs_p2p/crypoto"
	"crypto/ecdh"
	"fmt"
	"os"
	"strings"
)

// ExportPrivateKeyHex 返回本节点私钥的 hex 字符串（与 NewNATNode 接收的 *ecdh.PrivateKey 等价表达）。
// 持有该字符串就持有节点身份，妥善保管。
func (n *NATNode) ExportPrivateKeyHex() string {
	return crypoto.GetPrivKeyStr(n.privKey)
}

// SavePrivateKey 把本节点私钥以 hex 形式写入指定文件。
// 文件权限为 0600，仅本机当前用户可读写，避免无意泄漏。
func (n *NATNode) SavePrivateKey(path string) error {
	if path == "" {
		return fmt.Errorf("natnode: SavePrivateKey 路径为空")
	}
	hexStr := n.ExportPrivateKeyHex()
	if err := os.WriteFile(path, []byte(hexStr), 0o600); err != nil {
		return fmt.Errorf("natnode: 保存私钥到 %s 失败: %w", path, err)
	}
	return nil
}

// LoadPrivateKeyFromHex 从 hex 字符串还原 *ecdh.PrivateKey，可直接传给 NewNATNode。
func LoadPrivateKeyFromHex(hexStr string) (*ecdh.PrivateKey, error) {
	hexStr = strings.TrimSpace(hexStr)
	if hexStr == "" {
		return nil, fmt.Errorf("natnode: 私钥 hex 为空")
	}
	priv, err := crypoto.ExtractPrivateKeyFromHex(hexStr)
	if err != nil {
		return nil, fmt.Errorf("natnode: 解析私钥 hex 失败: %w", err)
	}
	return priv, nil
}

// LoadPrivateKeyFromFile 从文件读取 hex 私钥并还原。
// 文件内容应为 GetPrivKeyStr / ExportPrivateKeyHex 产出的 hex 字符串
// （首尾空白会被自动 trim）。
func LoadPrivateKeyFromFile(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("natnode: LoadPrivateKeyFromFile 路径为空")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("natnode: 读取私钥文件 %s 失败: %w", path, err)
	}
	return LoadPrivateKeyFromHex(string(data))
}
