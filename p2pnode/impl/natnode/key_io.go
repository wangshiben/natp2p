package natnode

import (
	"bnfs_p2p/crypoto"
	"crypto/ecdh"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if len(data) == 32 {
		privateKey, rawErr := ecdh.P256().NewPrivateKey(data)
		if rawErr != nil {
			return nil, fmt.Errorf("natnode: 解析私钥原始字节失败: %w", rawErr)
		}
		return privateKey, nil
	}
	return LoadPrivateKeyFromHex(string(data))
}

// LoadOrCreatePrivateKeyFile 加载稳定节点身份，不存在时只创建一次。
// 创建时先完整同步临时文件，再通过原子硬链接发布；并发创建者读取胜出文件且绝不覆盖旧密钥。
func LoadOrCreatePrivateKeyFile(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("natnode: identity key path is empty")
	}
	privateKey, err := LoadPrivateKeyFromFile(path)
	if err == nil {
		return privateKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("natnode: create identity directory: %w", err)
	}
	privateKey, err = crypoto.MakeKeyPair()
	if err != nil {
		return nil, fmt.Errorf("natnode: generate identity key: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".identity-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("natnode: create temporary identity: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return nil, fmt.Errorf("natnode: protect temporary identity: %w", err)
	}
	encoded := []byte(crypoto.GetPrivKeyStr(privateKey))
	if written, err := temporary.Write(encoded); err != nil || written != len(encoded) {
		temporary.Close()
		if err == nil {
			err = fmt.Errorf("short write: %d of %d", written, len(encoded))
		}
		return nil, fmt.Errorf("natnode: write temporary identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return nil, fmt.Errorf("natnode: sync temporary identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return nil, fmt.Errorf("natnode: close temporary identity: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadPrivateKeyFromFile(path)
		}
		return nil, fmt.Errorf("natnode: publish identity key: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return nil, fmt.Errorf("natnode: open identity directory: %w", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		directoryHandle.Close()
		return nil, fmt.Errorf("natnode: sync identity directory: %w", err)
	}
	if err := directoryHandle.Close(); err != nil {
		return nil, fmt.Errorf("natnode: close identity directory: %w", err)
	}
	return privateKey, nil
}
