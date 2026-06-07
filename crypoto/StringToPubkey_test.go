package crypoto

import (
	"log"
	"testing"
)

func TestExtractPublicKeyFromHex(t *testing.T) {
	pair, err := MakeKeyPair()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
		return
	}
	pubKeyStr := GetPubKeyStr(pair.PublicKey())
	t.Logf("公钥:\n %s", pubKeyStr)
	fromHex, err := ExtractPublicKeyFromHex(pubKeyStr)
	if err != nil {
		t.Fatalf("提取公钥失败: %v", err)
		return
	}
	keyStr2 := GetPubKeyStr(fromHex)
	if keyStr2 != pubKeyStr {
		t.Fatalf("公钥不一致")
		return
	}
	t.Logf("公钥2:\n %s", keyStr2)
}

func TestExtractPublicKeyFromHex2(t *testing.T) {
	pubKey := "045938a88208ef46f2cd01682279aab8660184a768e6d97ed1628eda3d442c35d15bcb660775fdeac0c23b1e67ae787cb7d87242029fc4d3675252a80a0f3a453a"
	hex, err := ExtractPublicKeyFromHex(pubKey)
	if err != nil {
		t.Fatalf("提取公钥失败: %v", err)
		return
	}
	t.Logf("公钥:\n %s", GetPubKeyStr(hex))
}

func TestReceiveSecureMessage(t *testing.T) {
	t.Logf("=== 开始 ECDH + AES 加密通信测试 ===\n")

	// 1. 初始化阶段：B 生成密钥对，并将公钥公开给 A
	// (实际场景中，B 的公钥可能预置在 A 的代码里，或者通过证书分发)
	bPriv, _ := MakeKeyPair()
	bPubHex := GetPubKeyStr(bPriv.PublicKey())
	t.Logf("[系统] B 的公钥 (Hex): %s\n\n", bPubHex)

	// 2. A 发送加密消息 "ClientHello"
	// A 只需要知道 B 的公钥 Hex 字符串
	packet, err := clientASend(bPubHex, "ClientHello: 这是一个安全的握手1请求！")
	if err != nil {
		log.Fatal("发送失败:", err)
	}

	// 3. B 接收并解密
	// B 使用自己的私钥处理收到的包
	if err := clientBReceive(bPriv, packet); err != nil {
		log.Fatal("接收失败:", err)
	}

	t.Logf("=== 测试结束 ===")
}

// TestPrivateKeyHexRoundTrip 验证私钥 → hex → 私钥 的对称往返。
// 关键校验点是「派生出来的公钥与原私钥派生公钥完全一致」——
// 这等价于 ECDH 标量恢复正确，节点身份(NodeID = SHA256(pubKeyHex)) 也一致。
func TestPrivateKeyHexRoundTrip(t *testing.T) {
	priv, err := MakeKeyPair()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	hexStr := GetPrivKeyStr(priv)
	if len(hexStr) == 0 {
		t.Fatalf("GetPrivKeyStr 返回空字符串")
	}
	t.Logf("私钥 hex (%d chars): %s...", len(hexStr), hexStr[:16])

	restored, err := ExtractPrivateKeyFromHex(hexStr)
	if err != nil {
		t.Fatalf("ExtractPrivateKeyFromHex 失败: %v", err)
	}

	// 对称性：再次序列化结果必须与首次一致。
	if hexStr != GetPrivKeyStr(restored) {
		t.Fatalf("私钥往返不一致")
	}

	// 派生公钥必须与原始私钥派生公钥一致。
	if GetPubKeyStr(priv.PublicKey()) != GetPubKeyStr(restored.PublicKey()) {
		t.Fatalf("还原私钥派生的公钥与原私钥不一致")
	}
}

// TestExtractPrivateKeyFromHex_Invalid 验证非法 hex 与长度不符时返回错误。
func TestExtractPrivateKeyFromHex_Invalid(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"非hex", "ZZZnotHex"},
		{"奇数位", "abc"},
		{"空串", ""},
		{"长度错误", "deadbeef"}, // 仅 4 字节, ECDH P-256 要求 32 字节标量
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := ExtractPrivateKeyFromHex(c.input); err == nil {
				t.Fatalf("input=%q 应返回 error, 实际 nil", c.input)
			}
		})
	}
}
