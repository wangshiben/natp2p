package crypoto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"bnfs_p2p/logx"
)

// aesGCMEncrypt 使用 AES-GCM 模式加密数据
func aesGCMEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 生成随机 Nonce (12字节是 GCM 的标准长度)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// 加密：结果包含 Nonce + 密文
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// aesGCMDecrypt 使用 AES-GCM 模式解密数据
func aesGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("密文太短")
	}

	// 提取 Nonce 和 密文
	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// 解密
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// --- 核心业务逻辑 ---

// 模拟 Client A (发送方)
func clientASend(clientB_PubKeyHex string, message string) ([]byte, error) {
	logx.Infof(">>> [Client A] 准备发送消息...")

	// 1. 解析 B 的公钥
	bPubKey, err := ExtractPublicKeyFromHex(clientB_PubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("解析 B 公钥失败: %v", err)
	}

	// 2. A 生成临时密钥对
	tempPriv, err := MakeKeyPair()
	if err != nil {
		return nil, err
	}

	// 3. 计算共享秘密 (替换 ScalarMult)
	// 直接使用 .ECDH() 方法
	sharedSecret, err := tempPriv.ECDH(bPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH 计算失败: %v", err)
	}

	// 4. 派生 AES 密钥
	// sharedSecret 已经是 []byte 类型，直接使用
	aesKey := sha256.Sum256(sharedSecret)

	// 5. 加密 (使用之前的辅助函数)
	encryptedData, err := aesGCMEncrypt([]byte(message), aesKey[:])
	if err != nil {
		return nil, err
	}

	// 6. 组装数据包
	myPubHex := GetPubKeyStr(tempPriv.PublicKey())
	pubBytes := []byte(myPubHex)
	finalPacket := append(pubBytes, encryptedData...)

	return finalPacket, nil
}

// 模拟 Client B (接收方)
func clientBReceive(myPriv *ecdh.PrivateKey, packet []byte) error {
	logx.Infof("<<< [Client B] 收到数据包，开始解密...")

	// 1. 解析数据包
	pubKeyHexLen := 130 // P-256 公钥 Hex 长度固定为 130
	if len(packet) < pubKeyHexLen {
		return fmt.Errorf("数据包太短")
	}

	senderPubHex := string(packet[:pubKeyHexLen])
	ciphertext := packet[pubKeyHexLen:]

	// 2. 还原 A 的临时公钥
	aPubKey, err := ExtractPublicKeyFromHex(senderPubHex)
	if err != nil {
		return fmt.Errorf("解析 A 公钥失败: %v", err)
	}

	// 3. 计算共享秘密 (替换 ScalarMult)
	// 同样使用 .ECDH() 方法
	sharedSecret, err := myPriv.ECDH(aPubKey)
	if err != nil {
		return fmt.Errorf("ECDH 计算失败: %v", err)
	}

	// 4. 派生 AES 密钥
	aesKey := sha256.Sum256(sharedSecret)

	// 5. 解密
	plaintext, err := aesGCMDecrypt(ciphertext, aesKey[:])
	if err != nil {
		return fmt.Errorf("解密失败: %v", err)
	}

	logx.Infof("<<< [Client B] 解密成功！消息内容: %s", string(plaintext))
	return nil
}
