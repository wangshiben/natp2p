package natnode

import (
	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
	"encoding/json"
)

const (
	routeHandshakeInfo = "/p2p/handshake-info"
	routeMessage       = "/p2p/message"
)

// handshakePayload 在 Noise E2E 握手后交换，携带节点身份与 relay 地址列表。
type handshakePayload struct {
	PeerID string   `json:"peer_id"`
	Relays []string `json:"relays"`
}

func encodeHandshakePayload(peerID string, relays []string) []byte {
	payload, _ := json.Marshal(handshakePayload{
		PeerID: peerID,
		Relays: relays,
	})
	return payload
}

func decodeHandshakePayload(data []byte) (peerID string, relays []string, err error) {
	var p handshakePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return "", nil, err
	}
	return p.PeerID, p.Relays, nil
}

// EncodeMessage 将 p2pnode.Message 转为网络层 network.Message。
func EncodeMessage(msg *p2pnode.Message, nodeID, connectionID string) *network.Message {
	payload, _ := json.Marshal(msg)
	return &network.Message{
		Header: &network.Header{
			RouteName:     routeMessage,
			NodeId:        nodeID,
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: payload,
	}
}

// DecodeMessage 将 network.Message 还原为 p2pnode.Message。
func DecodeMessage(netMsg *network.Message) (*p2pnode.Message, error) {
	var msg p2pnode.Message
	if err := json.Unmarshal(netMsg.Payload, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// IsHandshakeInfo 判断一条 network.Message 是否为握手后元数据交换消息。
func IsHandshakeInfo(netMsg *network.Message) bool {
	return netMsg.Header.RouteName == routeHandshakeInfo
}

// newHandshakeMessage 构造携带握手后元数据的 network.Message。
func newHandshakeMessage(peerID, connectionID string, relays []string) *network.Message {
	return &network.Message{
		Header: &network.Header{
			RouteName:     routeHandshakeInfo,
			NodeId:        peerID,
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: encodeHandshakePayload(peerID, relays),
	}
}
