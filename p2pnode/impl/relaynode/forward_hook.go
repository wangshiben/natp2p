package relaynode

import (
	"bnfs_p2p/networkFrameWork"
)

// 转发 hook 相关类型直接复用 networkFrameWork 包的定义，避免重复定义与类型转换。
//
// 用法示例：
//
//	node.SetForwardHook(&relaynode.ForwardHookConfig{
//	    ThresholdBytes: 1 << 20, // 每转发 1MB 调用一次 hook
//	    Hook: func(ctx context.Context, stats *relaynode.ForwardStats) error {
//	        // 业务逻辑，返回 nil 继续转发，返回 error 触发 ErrorHook 并停止该方向转发
//	        return nil
//	    },
//	    ErrorHook: func(ctx context.Context, info *relaynode.ForwardErrorInfo) {
//	        // 错误处理：info 是一个结构体参数，包含 Stats / Err / Direction
//	    },
//	})

// ForwardHookFunc 每转发到指定大小时调用的 hook。
// 返回 nil 继续转发；返回 error 触发 ErrorHook 并停止该方向的转发。
type ForwardHookFunc = networkFrameWork.ForwardHookFunc

// ForwardErrorHookFunc 转发 hook 返回 error 时调用的错误处理函数。
// 参数是一个结构体指针 ForwardErrorInfo，承载错误上下文。
type ForwardErrorHookFunc = networkFrameWork.ForwardErrorHookFunc

// ForwardErrorInfo 错误处理 hook 的结构体参数。
type ForwardErrorInfo = networkFrameWork.ForwardErrorInfo

// ForwardStats 转发统计信息。
type ForwardStats = networkFrameWork.ForwardStats

// ForwardHookConfig 转发 hook 配置。
type ForwardHookConfig = networkFrameWork.ForwardHookConfig
