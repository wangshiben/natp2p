package natnode

import (
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"context"
	"fmt"
)

// NATTransport 实现 p2pnode.Transport，委托给 networkFrameWork 的拨号/注册函数。
type NATTransport struct {
	pubKeyHex string
	// signJSON 是本节点持有的 CA 签发准入证书(indexSign, admission.SignedCert JSON)，可空。
	// 注册时随注册消息携带, relay 离线验签并据证书 Role 区分 client/server。空则走裸公钥(无准入)。
	signJSON      []byte
	relayState    *relayFailoverState
	reconnectGate networkFrameWork.ReconnectGate
}

type fixedRelayDialPolicy struct {
	address string
	gate    networkFrameWork.ReconnectGate
	role    string
}

func (policy fixedRelayDialPolicy) CurrentRelay() (networkFrameWork.RelayDialTarget, error) {
	return networkFrameWork.RelayDialTarget{Address: policy.address}, nil
}

func (fixedRelayDialPolicy) ReportRelayDialResult(networkFrameWork.RelayDialTarget, error) {}

func (policy fixedRelayDialPolicy) ReconnectGate() networkFrameWork.ReconnectGate {
	return policy.gate
}

func (policy fixedRelayDialPolicy) ReconnectRole() string {
	return policy.role
}

// NewNATTransport 创建使用指定公钥 hex 进行 relay 通信的 Transport。
func NewNATTransport(pubKeyHex string, relayState ...*relayFailoverState) *NATTransport {
	transport := &NATTransport{
		pubKeyHex:     pubKeyHex,
		reconnectGate: networkFrameWork.NewReconnectGateFromEnvironment(),
	}
	if len(relayState) > 0 {
		transport.relayState = relayState[0]
	}
	return transport
}

func (t *NATTransport) ReconnectGate() networkFrameWork.ReconnectGate {
	return t.reconnectGate
}

func (t *NATTransport) WaitForReconnect(ctx context.Context, request networkFrameWork.ReconnectGateRequest) error {
	if t.reconnectGate == nil {
		return nil
	}
	return t.reconnectGate.Wait(ctx, request)
}

func (t *NATTransport) CurrentRelay() (networkFrameWork.RelayDialTarget, error) {
	if t.relayState == nil {
		return networkFrameWork.RelayDialTarget{}, fmt.Errorf("natnode: relay failover state is unavailable")
	}
	target, err := t.relayState.currentTarget()
	if err != nil {
		return networkFrameWork.RelayDialTarget{}, err
	}
	return networkFrameWork.RelayDialTarget{Address: target.address, Generation: target.generation}, nil
}

func (t *NATTransport) ReportRelayDialResult(target networkFrameWork.RelayDialTarget, dialErr error) {
	if t.relayState != nil {
		t.relayState.reportResult(relayDialTarget{address: target.Address, generation: target.Generation}, dialErr)
	}
}

func (t *NATTransport) RelayChangeSignal() <-chan struct{} {
	if t.relayState == nil {
		return nil
	}
	return t.relayState.relayChangeSignal()
}

// SetIndexSign 设置注册时携带的准入证书(indexSign) JSON。空则不携带（无准入）。
func (t *NATTransport) SetIndexSign(signJSON []byte) {
	t.signJSON = signJSON
}

// Register 将本节点注册为 relay 可达目标（dual: KCP + TCP 双 leg）。
//
// 恢复 dual 注册以获得 KCP 跨境高吞吐。跨中继桥接侧通过「确定性只桥接 KCP(send-preferred)
// leg」规避双 leg 在 relayStream / 桥接 active 字段上的 failover 竞态
// （见 relaynode.findAndBridge 的 KCP 优先建桥逻辑）。
func (t *NATTransport) Register(ctx context.Context, relayAddr string, publicKeyHex string) (network.Stream, error) {
	// 带 indexSign 注册（signJSON 为空时等价于裸公钥注册，与旧行为逐字节一致）。
	if t.relayState != nil {
		return networkFrameWork.TryRegisterRelayStreamWithSignAndRelayPolicy(publicKeyHex, t.signJSON, t)
	}
	if t.reconnectGate != nil {
		return networkFrameWork.TryRegisterRelayStreamWithSignAndRelayPolicy(
			publicKeyHex,
			t.signJSON,
			fixedRelayDialPolicy{address: relayAddr, gate: t.reconnectGate, role: "natserver"},
		)
	}
	return networkFrameWork.TryRegisterRelayStreamWithSign(publicKeyHex, relayAddr, t.signJSON)
}

// RegisterAtRelay bypasses the single-active Relay failover policy and registers
// at exactly relayAddr. Persistent service listeners use this path so multiple
// independent carriers cannot accidentally converge on CurrentRelay().
func (t *NATTransport) RegisterAtRelay(ctx context.Context, relayAddr string, publicKeyHex string) (network.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if t.reconnectGate != nil {
		return networkFrameWork.TryRegisterRelayStreamWithSignAndRelayPolicy(
			publicKeyHex,
			t.signJSON,
			fixedRelayDialPolicy{address: relayAddr, gate: t.reconnectGate, role: "natserver"},
		)
	}
	return networkFrameWork.TryRegisterRelayStreamWithSign(publicKeyHex, relayAddr, t.signJSON)
}

// Dial 经指定 relay 连接到目标节点（dual: KCP + TCP 双 leg）。
// 返回原始流（首条 hello 已发送）和连接 ID。
func (t *NATTransport) Dial(ctx context.Context, relayAddr string, targetID p2pnode.NodeID) (network.Stream, string, error) {
	if t.relayState != nil {
		return networkFrameWork.TryConnectTCPStreamWithRelayPolicy(t, string(targetID), t.pubKeyHex)
	}
	if t.reconnectGate != nil {
		return networkFrameWork.TryConnectTCPStreamWithRelayPolicy(
			fixedRelayDialPolicy{address: relayAddr, gate: t.reconnectGate, role: "natclient"},
			string(targetID),
			t.pubKeyHex,
		)
	}
	return networkFrameWork.TryConnectTCPStream(relayAddr, string(targetID), t.pubKeyHex)
}
