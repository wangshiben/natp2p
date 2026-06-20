// Package relayquery 定义「NAT 节点向 index 拉取已知 relay 列表」的一次性请求/应答线格式。
//
// 它被 relaynode（应答方/index）与 natnode（请求方）共同引用。单独成包是为了让二者共享同一份
// 线格式而互不依赖——否则 natnode 直接 import relaynode 会与 relaynode 的集成测试(import natnode)
// 形成测试期导入环。relayquery 只依赖最底层的 network 包, 不会引入环。
package relayquery

import (
	"bnfs_p2p/network"
	"encoding/json"
	"fmt"
)

// Route 是查询请求/应答复用的 RouteName。
//
// natNode 用此 RouteName 向 index 拨一条控制流, index 在 MissingGroupHandler 里据此识别为
// relay 列表查询, 回一条 ListResp 后即关闭 stream。
//
// 注意: networkFrameWork/TransportCoverStream.go 里有一份同值常量 relayQueryRouteHint,
// 用于把本 RouteName 排除出「裸字节桥接」判定(否则读写循环不启动, 应答收不到), 两处需保持同步。
const Route = "/relay/query"

// Info 描述一个 relay 节点的可达信息。
type Info struct {
	NodeID string `json:"node_id"` // relay 的 NodeId (64 hex)
	Addr   string `json:"addr"`    // relay 的公网业务地址 (host:port)
}

// ListResp 是 index 对查询请求的应答: 它已知的 relay 列表。
// 列表通常包含 index 自身, 以便 natNode 在没有/无法连接其它子 relay 时回退注册到 index。
type ListResp struct {
	Relays []Info `json:"relays"`
}

// EncodeListResp 把 relay 列表编码为一条 network.Message(RouteName=Route)。
// nodeId 用应答方(index)的 NodeId 占位; StreamClient.SendMessage 会覆盖 ConnectionId。
func EncodeListResp(resp *ListResp, nodeId string) *network.Message {
	payload, _ := json.Marshal(resp)
	return &network.Message{
		Header: &network.Header{
			RouteName:     Route,
			NodeId:        nodeId,
			NodeIdVersion: 1,
		},
		Payload: payload,
	}
}

// DecodeListResp 从 network.Message 还原 relay 列表应答。
func DecodeListResp(msg *network.Message) (*ListResp, error) {
	var resp ListResp
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		return nil, fmt.Errorf("relayquery: 解码 relay 列表应答失败: %w", err)
	}
	return &resp, nil
}
