package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/google/uuid"
	"testing"
)

func TestMessageSerialization(t *testing.T) {
	// 构造测试数据
	// 对任意字符串进行 SHA256 运算得到 64 字符的 Hex ID
	originalNodeIdSource := "test-node-id-source-string"
	hash := sha256.Sum256([]byte(originalNodeIdSource))
	originalNodeId := hex.EncodeToString(hash[:]) // 长度固定为 64

	originalRouteName := "/api/v1/test"
	originalPayload := []byte("hello world this is a test payload")
	connectionId := uuid.New().String()
	legSessionId := uuid.New().String()
	// 创建原始消息
	originalMsg := &Message{
		Header: &Header{
			NodeId:        originalNodeId,
			NodeIdVersion: 1,
			RouteName:     originalRouteName,
			PayLoadLength: uint(len(originalPayload)),
			ConnectionId:  connectionId,
			LegSessionId:  legSessionId,
		},
		Payload: originalPayload,
	}

	// 1. 序列化为字节流
	serializedBytes, err := originalMsg.ParseToBytes()
	if err != nil {
		t.Fatalf("Failed to serialize message: %v", err)
	}

	// 验证总长度是否正确 (Header 256 + Payload)
	expectedTotalLen := HeaderLength + len(originalPayload)
	if len(serializedBytes) != expectedTotalLen {
		t.Errorf("Expected total length %d, got %d", expectedTotalLen, len(serializedBytes))
	}

	// 2. 反序列化回消息对象
	parsedMsg, err := ParseMessage(serializedBytes)
	if err != nil {
		t.Fatalf("Failed to parse message: %v", err)
	}

	// 3. 验证字段一致性
	if parsedMsg.Header.NodeId != originalNodeId {
		t.Errorf("NodeId mismatch: expected %s, got %s", originalNodeId, parsedMsg.Header.NodeId)
	}

	if parsedMsg.Header.NodeIdVersion != 1 {
		t.Errorf("NodeIdVersion mismatch: expected 1, got %d", parsedMsg.Header.NodeIdVersion)
	}

	if parsedMsg.Header.RouteName != originalRouteName {
		t.Errorf("RouteName mismatch: expected %s, got %s", originalRouteName, parsedMsg.Header.RouteName)
	}

	if parsedMsg.Header.PayLoadLength != uint(len(originalPayload)) {
		t.Errorf("PayLoadLength mismatch: expected %d, got %d", len(originalPayload), parsedMsg.Header.PayLoadLength)
	}

	if !bytes.Equal(parsedMsg.Payload, originalPayload) {
		t.Errorf("Payload mismatch: expected %v, got %v", originalPayload, parsedMsg.Payload)
	}
	if parsedMsg.Header.ConnectionId != connectionId {
		t.Errorf("ConnectionId mismatch: expected %s, got %s", connectionId, parsedMsg.Header.ConnectionId)
	}
	if parsedMsg.Header.LegSessionId != legSessionId {
		t.Errorf("LegSessionId mismatch: expected %s, got %s", legSessionId, parsedMsg.Header.LegSessionId)
	}

	t.Logf("Serialization and Deserialization successful.")
}

func TestMessageSerializationRejectsMissingMessageState(t *testing.T) {
	var missingMessage *Message
	if _, err := missingMessage.ParseToBytes(); err == nil {
		t.Fatal("nil message must return an error")
	}
	if _, err := (&Message{}).ParseToBytes(); err == nil {
		t.Fatal("missing message header must return an error")
	}
}
