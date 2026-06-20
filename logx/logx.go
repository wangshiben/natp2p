// Package logx 提供带等级的轻量日志封装, 统一替换框架内散落的 log.Printf。
//
// 设计目标:
//   - 默认行为与原 log.Printf 一致(等级 Info, 输出到标准 logger), 不破坏现有可观测性。
//   - index / relay server 可在启动时调 SetLevel(LevelError), 抑制注册/登记/转发/桥接
//     等监控类 Info/Debug 噪声, 只保留 Warn/Error。
//   - Error 级自动附带【当前时刻的调用堆栈】, 便于定位报错现场。
//
// 等级阈值: 只有 >= 当前 level 的日志才会输出。顺序 Debug < Info < Warn < Error。
package logx

import (
	"log"
	"runtime"
	"sync/atomic"
)

// Level 日志等级。
type Level int32

const (
	// LevelDebug 最详细, 含逐帧/逐连接的内部细节。
	LevelDebug Level = iota
	// LevelInfo 常规运行信息(注册、登记、桥接建立等监控类)。默认等级。
	LevelInfo
	// LevelWarn 可恢复的异常 / 需要关注但不致命。
	LevelWarn
	// LevelError 错误, 输出时附带调用堆栈。
	LevelError
)

// level 当前全局阈值, 原子访问以支持运行期并发读写。
var level atomic.Int32

func init() { level.Store(int32(LevelInfo)) }

// SetLevel 设置全局日志阈值。低于该阈值的日志被丢弃。
func SetLevel(l Level) { level.Store(int32(l)) }

// GetLevel 返回当前全局阈值。
func GetLevel() Level { return Level(level.Load()) }

// enabled 报告给定等级是否应输出。
func enabled(l Level) bool { return l >= Level(level.Load()) }

// Debugf 输出 Debug 级日志(最详细的内部细节)。
func Debugf(format string, args ...interface{}) {
	if enabled(LevelDebug) {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// Infof 输出 Info 级日志(常规监控信息)。
func Infof(format string, args ...interface{}) {
	if enabled(LevelInfo) {
		log.Printf("[INFO] "+format, args...)
	}
}

// Warnf 输出 Warn 级日志。
func Warnf(format string, args ...interface{}) {
	if enabled(LevelWarn) {
		log.Printf("[WARN] "+format, args...)
	}
}

// Errorf 输出 Error 级日志, 并附带当前时刻的调用堆栈, 便于定位报错现场。
func Errorf(format string, args ...interface{}) {
	if enabled(LevelError) {
		log.Printf("[ERROR] "+format+"\n%s", append(args, stack())...)
	}
}

// stack 抓取当前 goroutine 的调用堆栈(裁掉 logx 自身的帧)。
func stack() string {
	buf := make([]byte, 8192)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}
