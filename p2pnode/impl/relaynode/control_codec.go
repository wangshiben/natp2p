package relaynode

import (
	"bnfs_p2p/network"
	"encoding/json"
	"fmt"
)

// RelayControlRoute 是 relay→relay 控制链路的 RouteName 标记。
//
// 当一台 relay 向另一台 relay 发起业务连接时，把首条 hello 的 Header.RouteName 设为本值，
// 对端 relay 的 MissingGroupHandler 据此区分「这是控制链路接入」还是「客户端要连接某个
// 本地未托管的 nat 节点」。控制链路建立后，后续所有控制消息也复用此 RouteName。
const RelayControlRoute = "/relay/control"

// 控制消息类型。
const (
	ctrlHello    = "HELLO"     // 交换 relay 身份与公网业务地址
	ctrlFind     = "FIND"      // 查询某个 nat 节点是否托管在对端 relay
	ctrlFindResp = "FIND_RESP" // FIND 的应答
)

// controlMessage 是 relay↔relay 控制链路上交换的统一信封。
//
//	Type        消息类型（ctrlHello / ctrlFind / ctrlFindResp）。
//	ReqID       请求标识，用于把 FIND_RESP 匹配回发起的 FIND；HELLO 不使用。
//	NodeId      HELLO: 发送方 relay 的 NodeId。
//	Addr        HELLO: 发送方 relay 的公网业务监听地址；FIND_RESP: 托管目标的 relay 地址。
//	Target      FIND: 要查找的 nat 节点 NodeId。
//	Hosts       FIND_RESP: 对端是否托管该 nat 节点。
//	ObservedAddr HELLO(被动回应): 本端(如 index)从底层连接观察到的【对端公网可路由地址】
//	             (observedRemoteIP + 对端自报端口)。relay 收到后用它覆盖自己的对外地址,
//	             使其后续上报给 natNode 的 relay 列表是可路由的, 而非 ":9000" 占位。
type controlMessage struct {
	Type         string `json:"type"`
	ReqID        uint64 `json:"req_id,omitempty"`
	NodeId       string `json:"node_id,omitempty"`
	Addr         string `json:"addr,omitempty"`
	Target       string `json:"target,omitempty"`
	Hosts        bool   `json:"hosts,omitempty"`
	ObservedAddr string `json:"observed_addr,omitempty"`
}

// encodeControl 把控制消息编码为一条 network.Message。
// nodeId/connectionId 由调用方传入用于填充 Header；StreamClient.SendMessage 会覆盖 ConnectionId。
func encodeControl(cm *controlMessage, nodeId, connectionId string) *network.Message {
	payload, _ := json.Marshal(cm)
	return &network.Message{
		Header: &network.Header{
			RouteName:     RelayControlRoute,
			NodeId:        nodeId,
			NodeIdVersion: 1,
			ConnectionId:  connectionId,
		},
		Payload: payload,
	}
}

// decodeControl 从 network.Message 还原控制消息。
func decodeControl(msg *network.Message) (*controlMessage, error) {
	var cm controlMessage
	if err := json.Unmarshal(msg.Payload, &cm); err != nil {
		return nil, fmt.Errorf("relaynode: 解码控制消息失败: %w", err)
	}
	return &cm, nil
}
