package logx

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	level             atomic.Int32
	errorStackEnabled atomic.Bool
	activeSink        atomic.Pointer[splitSink]
	configurationMu   sync.Mutex
)

func init() {
	level.Store(int32(LevelInfo))
	errorStackEnabled.Store(true)
	configured, configuredLevel, err := configurationFromEnvironment()
	if err != nil {
		log.Printf("[WARN] logx environment configuration rejected: %v", err)
		configured = DefaultConfig()
	}
	level.Store(int32(configuredLevel))
	sink, err := openSplitSink(configured)
	if err != nil {
		log.Printf("[ERROR] logx file output unavailable: %v", err)
		sink, _ = openSplitSink(DefaultConfig())
	}
	errorStackEnabled.Store(configured.IncludeErrorStack)
	activeSink.Store(sink)
}

func SetLevel(configured Level) {
	if configured < LevelDebug || configured > LevelError {
		return
	}
	level.Store(int32(configured))
}

func GetLevel() Level {
	return Level(level.Load())
}

func ParseLevel(value string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return LevelDebug, nil
	case "", "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("logx: unsupported level %q", value)
	}
}

func Configure(config Config) error {
	sink, err := openSplitSink(config)
	if err != nil {
		return err
	}
	configurationMu.Lock()
	previous := activeSink.Swap(sink)
	errorStackEnabled.Store(config.IncludeErrorStack)
	configurationMu.Unlock()
	if previous != nil {
		return previous.Close()
	}
	return nil
}

func ConfigureFromEnvironment() error {
	config, configuredLevel, err := configurationFromEnvironment()
	if err != nil {
		return err
	}
	if err := Configure(config); err != nil {
		return err
	}
	SetLevel(configuredLevel)
	return nil
}

func Close() error {
	configurationMu.Lock()
	previous := activeSink.Swap(nil)
	configurationMu.Unlock()
	if previous == nil {
		return nil
	}
	return previous.Close()
}

func Debugf(format string, args ...any) {
	write(LevelDebug, format, args...)
}

func Infof(format string, args ...any) {
	write(LevelInfo, format, args...)
}

func Warnf(format string, args ...any) {
	write(LevelWarn, format, args...)
}

func Errorf(format string, args ...any) {
	if !enabled(LevelError) {
		return
	}
	message := fmt.Sprintf(format, args...)
	if errorStackEnabled.Load() {
		message += "\n" + stack()
	}
	writeMessage(LevelError, message)
}

func enabled(configured Level) bool {
	return configured >= Level(level.Load())
}

func write(configured Level, format string, args ...any) {
	if !enabled(configured) {
		return
	}
	writeMessage(configured, fmt.Sprintf(format, args...))
}

func writeMessage(configured Level, message string) {
	sink := activeSink.Load()
	if sink == nil {
		log.Printf("[%s] %s", configured, message)
		return
	}
	sink.Write(configured, message)
}

func (configured Level) String() string {
	switch configured {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

func stack() string {
	buffer := make([]byte, 8192)
	written := runtime.Stack(buffer, false)
	return string(buffer[:written])
}
