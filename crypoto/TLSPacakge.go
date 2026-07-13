package crypoto

import (
	"bnfs_p2p/network"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	// 假设你有对方的公钥字节数组 peerPublicKeyBytes
)

var e2eEnvelopeMagic = []byte("BNFSE2E1")

const e2eEnvelopeHeaderLength = 8 + 32 + 8

type TLSCrypto struct {
	publicKey        *ecdh.PublicKey // 本节点的公钥
	targetPublicKey  *ecdh.PublicKey // 通信对方的公钥
	aesGCMEncryptKey []byte          // 本次通信中的AES密钥
	e2eConnectionID  [32]byte
	messageSeq       atomic.Uint64
}

func (t *TLSCrypto) Encrypt(Payload []byte) ([]byte, error) {
	ciphertext, _, err := t.EncryptWithMessageID(Payload, nil)
	return ciphertext, err
}

func (t *TLSCrypto) NewMessageID() []byte {
	seq := t.messageSeq.Add(1)
	messageID := make([]byte, 40)
	copy(messageID[:32], t.e2eConnectionID[:])
	binary.BigEndian.PutUint64(messageID[32:40], seq)
	return messageID
}

func (t *TLSCrypto) EncryptWithMessageID(Payload []byte, messageID []byte) ([]byte, []byte, error) {
	if len(Payload) == 0 {
		return Payload, nil, nil
	}
	if len(messageID) != 40 {
		messageID = t.NewMessageID()
	} else {
		messageID = append([]byte(nil), messageID...)
	}
	envelope := make([]byte, e2eEnvelopeHeaderLength+len(Payload))
	copy(envelope[:8], e2eEnvelopeMagic)
	copy(envelope[8:40], messageID[:32])
	copy(envelope[40:48], messageID[32:40])
	copy(envelope[e2eEnvelopeHeaderLength:], Payload)
	encrypt, err := aesGCMEncrypt(envelope, t.aesGCMEncryptKey)
	if err != nil {
		return nil, nil, err
	}
	return encrypt, messageID, nil
}

func (t *TLSCrypto) Decrypt(Payload []byte) ([]byte, error) {
	plaintext, _, _, err := t.DecryptWithMessageID(Payload)
	return plaintext, err
}

func (t *TLSCrypto) DecryptWithMessageID(Payload []byte) ([]byte, []byte, bool, error) {
	if len(Payload) == 0 {
		return Payload, nil, false, nil
	}
	decrypt, err := aesGCMDecrypt(Payload, t.aesGCMEncryptKey)
	if err != nil {
		return nil, nil, false, err
	}
	if len(decrypt) < e2eEnvelopeHeaderLength || !bytes.Equal(decrypt[:8], e2eEnvelopeMagic) {
		return decrypt, nil, false, nil
	}
	messageID := make([]byte, 40)
	copy(messageID[:32], decrypt[8:40])
	copy(messageID[32:], decrypt[40:48])
	return decrypt[e2eEnvelopeHeaderLength:], messageID, true, nil
}

func slatGenorate() (string, error) {
	// 1. 定义盐的长度：256位 = 32字节
	saltLength := 32

	// 2. 创建一个字节切片来存储随机数
	salt := make([]byte, saltLength)

	// 3. 使用 crypto/rand.Read 填充切片
	// rand.Read 会返回读取的字节数和可能的错误
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// 4. 将二进制盐值转换为十六进制字符串 (方便存入数据库)
	// 32字节的二进制数据会变成 64个字符的十六进制字符串
	saltStr := hex.EncodeToString(salt)
	return saltStr, nil
}
func getHashHex(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// NewTLSCrypto 创建 TLSCrypto 实例 : 发生在Client和中继节点建立连接之后，需要建立和真正Target之间的通信，第一条消息必须由Client端发送
// stream: 网络流
// nodePrivateKey: 本节点的私钥
// IsClient: 是否是客户端
func NewTLSCrypto(targetStream network.Stream, nodePrivateKey *ecdh.PrivateKey) (*TLSCrypto, error) {
	return NewTLSCryptoContext(context.Background(), targetStream, nodePrivateKey)
}

// NewTLSCryptoContext 与 NewTLSCrypto 执行相同的端到端握手，但所有网络等待均受 ctx
// 约束，确保 Relay 拒绝或半开连接不会让建连调用永久阻塞。
func NewTLSCryptoContext(ctx context.Context, targetStream network.Stream, nodePrivateKey *ecdh.PrivateKey) (*TLSCrypto, error) {
	// 1. 发送自己的公钥，验明自身
	MessageHeader := &network.Header{
		RouteName:     "",
		NodeId:        targetStream.NodeId(),
		NodeIdVersion: 0,
		PayLoadLength: 0,
		ConnectionId:  targetStream.ConnectionId(),
		OriginData:    nil,
	}
	pubKeyStr := GetPubKeyStr(nodePrivateKey.PublicKey())

	FirstMessageBody := &network.Message{
		Header:  MessageHeader,
		Payload: []byte(pubKeyStr),
	}
	err := targetStream.SendMessage(ctx, FirstMessageBody)
	if err != nil {
		return nil, err
	}
	message, err := targetStream.NextMessage(ctx)
	if err != nil {
		return nil, err
	}
	pubKeyHex := string(message.Payload)
	if !verifyPubKeyToPubKey(targetStream.NodeId(), pubKeyHex) {
		return nil, errors.New("wrong Stream maybe you stream on a mid node")
	}
	targetPublicKey, err := ExtractPublicKeyFromHex(pubKeyHex)
	if err != nil {
		return nil, err
	}
	// 1.双方随机生成Slat值，用于生成 AES 密钥
	salt, err := slatGenorate()
	if err != nil {
		return nil, err
	}
	signData := getHashHex(salt + pubKeyStr)
	// 2.交换Salt值
	if err := targetStream.SendMessage(ctx, &network.Message{
		Header:  MessageHeader,
		Payload: []byte(fmt.Sprintf("%s|%s", salt, signData)),
	}); err != nil {
		return nil, err
	}
	// 3. 接收对方发来的Salt值
	message, err = targetStream.NextMessage(ctx)
	if err != nil {
		return nil, err
	}
	SaltData := message.Payload
	SlatSign := strings.Split(string(SaltData), "|")
	if len(SlatSign) < 2 {
		return nil, fmt.Errorf("wrong Salt format: 期望 \"salt|sign\", 收到 %d 段 (payloadLen=%d)", len(SlatSign), len(SaltData))
	}
	targetPubKeyStr := GetPubKeyStr(targetPublicKey)
	slatDataSign := getHashHex(SlatSign[0] + targetPubKeyStr)
	if slatDataSign != SlatSign[1] {

		return nil, fmt.Errorf("wrong Salt,need Slat %s,but get %s", SlatSign[1], slatDataSign)
	}
	targetSlat := SlatSign[0]
	finalSlat := min(targetSlat, salt) + max(targetSlat, salt)
	sharedSecret, err := nodePrivateKey.ECDH(targetPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH 计算失败: %v", err)
	}
	finalKeyOrignal := append(sharedSecret, []byte(finalSlat)...)
	// 4. 派生 AES 密钥
	// sharedSecret 已经是 []byte 类型，直接使用
	aesKey := sha256.Sum256(finalKeyOrignal)
	e2eConnectionID := sha256.Sum256(aesKey[:])
	return &TLSCrypto{
		publicKey:        nodePrivateKey.PublicKey(),
		targetPublicKey:  targetPublicKey,
		aesGCMEncryptKey: aesKey[:],
		e2eConnectionID:  e2eConnectionID,
	}, nil
}
func verifyPubKeyToPubKey(targetId, PubkeyStr string) bool {
	hash := sha256.Sum256([]byte(PubkeyStr))
	originalNodeId := hex.EncodeToString(hash[:])
	return targetId == originalNodeId
}

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
	log.Printf(">>> [Client A] 准备发送消息...")

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
	log.Printf("<<< [Client B] 收到数据包，开始解密...")

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

	log.Printf("<<< [Client B] 解密成功！消息内容: %s\n", string(plaintext))
	return nil
}
