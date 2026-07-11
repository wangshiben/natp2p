package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/logx"
	"bnfs_p2p/networkFrameWork"
	"context"
	"fmt"
	"time"
)

// 本文件实现 serverNode 流量计量（计费方向的数据面采集）。
//
// 计量口径：serverNode 经本 relay 转发的净荷，双向均计：
//   - relay_to_clients（服务端→客户端）：服务端提供下载服务；
//   - client_to_relay（客户端→服务端）：客户端向服务端上传——同样消耗 relay 转发资源。
//
// 双向计量后，原"只计 relay_to_clients"导致 client_to_relay 方向永不计费的漏洞已封堵。
//
// 每个被托管节点是独立 StreamGroup（按 nodeId），hook 经 ForwardStats.NodeID 天然按节点归因。

// meteringThresholdBytes 是计量 hook 的触发粒度（每累计这么多净荷回调一次）。
// 取一个较小值以便测试/演示能较快看到累计；生产可按时间片经济学调大。
const meteringThresholdBytes int64 = 256 * 1024

// installMeteringHook 在准入启用时安装 serverNode 双向流量计量 hook。
//
// 仅当用户未自行设置 forwardHookConfig 时安装（避免覆盖用户 hook）。
func (n *RelayNode) installMeteringHook() {
	n.mu.RLock()
	already := n.forwardHookConfig != nil
	n.mu.RUnlock()
	if already {
		logx.Infof("[relaynode] 已存在 forward hook, 跳过内置计量 hook 安装")
		return
	}
	n.SetForwardHook(&networkFrameWork.ForwardHookConfig{
		ThresholdBytes: meteringThresholdBytes,
		Hook:           n.meteringHook,
	})
}

// meteringHook 是计量回调：只计 serverNode 的【上行】方向（relay_to_clients = 服务端向客户端
// 发送）净荷，累加到账户表；client_to_relay（客户端上传）【不计量】——按既定模型，client 流量
// 不计费，一切由 server 上行扣费，client 的白嫖成本由建连保证金兜底（见 onBusinessConnect）。
// 该节点已被 CA 裁决熔断（余额耗尽）时返回 error 停止转发（触发 forward pump 停）。
func (n *RelayNode) meteringHook(ctx context.Context, stats *networkFrameWork.ForwardStats) error {
	// 只计 server 上行方向；client 上传方向与空 NodeID 一律不计。
	if stats.Direction != "relay_to_clients" || stats.NodeID == "" {
		return nil
	}
	if n.accounts.role(stats.NodeID) != admission.RoleServer {
		return nil // 非 server 角色不计费
	}
	// 熔断：CA 已裁决余额耗尽 → 返回 error，forward pump 停止该方向转发。
	if n.accounts.isCutoff(stats.NodeID) {
		return fmt.Errorf("serverNode %.16s 余额耗尽, 熔断转发", stats.NodeID)
	}
	total := n.accounts.addUplink(stats.NodeID, stats.TotalBytes)
	logx.Debugf("[relaynode] serverNode 上行计量: %.16s +%dB 累计=%dB", stats.NodeID, stats.TotalBytes, total)
	return nil
}

// settleInterval 是周期结算的时间片长度（每隔它向 CA 上报一次增量用量、取回余额裁决）。
const settleInterval = 10 * time.Second

// startSettlementLoop 启动周期结算循环（决策：账本在 CA web 服务）。
//
// 每隔 settleInterval：遍历所有 server 节点，取自上次上报以来的上行增量，用 caclient.Settle
// 上报给 CA；CA 扣减余额并返回 Allow。Allow=false（余额耗尽）→ 置该节点 cutoff，metering hook
// 随即熔断其转发。这实现「每隔 N 个时间片向 index/CA 请求一次是否仍有余额」的需求，且数据面
// 不被每字节的 CA 往返拖慢（本地累计、片边界结算）。
//
// 仅在准入启用且配置了 CA 验证器（*admission.CAClient）时运行。ctx 取消即退出。
func (n *RelayNode) startSettlementLoop() {
	cfg := n.admissionConfig()
	if cfg == nil || cfg.Mode == AdmissionOff {
		return
	}
	settler, ok := cfg.Verifier.(*admission.CAClient)
	if !ok || settler == nil {
		logx.Infof("[relaynode] 未配置 CA 结算客户端, 跳过周期结算（仅计量不熔断）")
		return
	}
	n.settleLoopOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(settleInterval)
			defer ticker.Stop()
			for {
				select {
				case <-n.ctx.Done():
					return
				case <-ticker.C:
					n.settleOnce(settler)
				}
			}
		}()
		logx.Infof("[relaynode] 周期结算循环已启动, 间隔=%s", settleInterval)
	})
}

// settleOnce 执行一轮结算：对每个有上行增量的 server 节点上报增量，据 CA 裁决更新 cutoff。
// Allow=false（余额耗尽）→ 熔断该节点后续 server 上行转发；余额恢复（管理员 /credit）后
// 下一片有增量时（或首帧计量触发）自然放行。client 流量不参与结算（不计费）。
func (n *RelayNode) settleOnce(settler *admission.CAClient) {
	for _, nodeID := range n.accounts.serverNodes() {
		delta := n.accounts.takeUnsettled(nodeID)
		if delta <= 0 {
			continue // 本片无新增上行, 不上报
		}
		ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
		resp, err := settler.Settle(ctx, admission.SettleRequest{
			NodeID:      nodeID,
			RelayNodeID: n.idStr(),
			UsedDelta:   delta,
		})
		cancel()
		if err != nil {
			// 结算失败（CA 不可达等）：本片不熔断, 保守放行, 下片重试。
			logx.Warnf("[relaynode] 结算失败 node=%.16s delta=%dB: %v", nodeID, delta, err)
			continue
		}
		n.accounts.setCutoff(nodeID, !resp.Allow)
		if !resp.Allow {
			logx.Warnf("[relaynode] serverNode %.16s 余额耗尽(余额=%dB), 已熔断", nodeID, resp.Balance)
		} else {
			logx.Infof("[relaynode] 结算 node=%.16s used+=%dB 余额=%dB", nodeID, delta, resp.Balance)
		}
	}

	// 恢复探针：对已熔断的 server 节点发 delta=0 探针查余额。熔断后其上行被 hook 停掉、
	// 不再产生增量，正常结算分支永远跳过它 → 若不探针则管理员充值后也无法恢复。
	// 探针只查不扣；余额>0 即解除熔断，节点恢复服务。
	for _, nodeID := range n.accounts.cutoffServerNodes() {
		ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
		resp, err := settler.Settle(ctx, admission.SettleRequest{
			NodeID: nodeID, RelayNodeID: n.idStr(), UsedDelta: 0,
		})
		cancel()
		if err != nil {
			logx.Warnf("[relaynode] 余额探针失败 node=%.16s: %v", nodeID, err)
			continue
		}
		if resp.Allow {
			n.accounts.setCutoff(nodeID, false)
			logx.Infof("[relaynode] serverNode %.16s 余额已恢复(=%dB), 解除熔断", nodeID, resp.Balance)
		}
	}
}
