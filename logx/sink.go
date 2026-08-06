package logx

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Directory         string
	MaxSizeBytes      int64
	RotateInterval    time.Duration
	Retention         time.Duration
	Console           bool
	IncludeErrorStack bool
}

type splitSink struct {
	mutex            sync.Mutex
	files            map[Level]*levelFile
	directory        string
	archiveDirectory string
	pendingDirectory string
	maxSizeBytes     int64
	rotateInterval   time.Duration
	retention        time.Duration
	console          bool
	archiveQueue     chan archiveTask
	archiveTasks     sync.WaitGroup
	archiveStop      chan struct{}
	archiveDone      chan struct{}
	rotationStop     chan struct{}
	rotationDone     chan struct{}
	background       bool
	closed           bool
	sequence         atomic.Uint64
	closeOnce        sync.Once
	closeError       error
	backgroundMutex  sync.Mutex
	backgroundErrors []error
}

type levelFile struct {
	level    Level
	path     string
	file     *os.File
	size     int64
	openedAt time.Time
}

type archiveTask struct {
	source string
	level  Level
}

func DefaultConfig() Config {
	return Config{
		MaxSizeBytes: 64 << 20, RotateInterval: 24 * time.Hour,
		Retention: 30 * 24 * time.Hour, Console: true, IncludeErrorStack: true,
	}
}

func configurationFromEnvironment() (Config, Level, error) {
	config := DefaultConfig()
	config.Directory = strings.TrimSpace(os.Getenv("BNFS_LOG_DIRECTORY"))
	configuredLevel, err := ParseLevel(os.Getenv("BNFS_LOG_LEVEL"))
	if err != nil {
		return Config{}, LevelInfo, err
	}
	if value := strings.TrimSpace(os.Getenv("BNFS_LOG_MAX_SIZE_MIB")); value != "" {
		megabytes, err := strconv.ParseInt(value, 10, 64)
		if err != nil || megabytes < 1 || megabytes > 4096 {
			return Config{}, LevelInfo, errors.New("BNFS_LOG_MAX_SIZE_MIB must be between 1 and 4096")
		}
		config.MaxSizeBytes = megabytes << 20
	}
	if value := strings.TrimSpace(os.Getenv("BNFS_LOG_ROTATE_INTERVAL")); value != "" {
		interval, err := time.ParseDuration(value)
		if err != nil || interval <= 0 {
			return Config{}, LevelInfo, errors.New("BNFS_LOG_ROTATE_INTERVAL must be a positive duration")
		}
		config.RotateInterval = interval
	}
	if value := strings.TrimSpace(os.Getenv("BNFS_LOG_RETENTION")); value != "" {
		retention, err := time.ParseDuration(value)
		if err != nil || retention < 0 {
			return Config{}, LevelInfo, errors.New("BNFS_LOG_RETENTION must be a non-negative duration")
		}
		config.Retention = retention
	}
	var parseErr error
	config.Console, parseErr = environmentBool("BNFS_LOG_CONSOLE", config.Console)
	if parseErr != nil {
		return Config{}, LevelInfo, parseErr
	}
	config.IncludeErrorStack, parseErr = environmentBool("BNFS_LOG_ERROR_STACK", config.IncludeErrorStack)
	if parseErr != nil {
		return Config{}, LevelInfo, parseErr
	}
	return config, configuredLevel, nil
}

func environmentBool(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func openSplitSink(config Config) (*splitSink, error) {
	if config.MaxSizeBytes < 0 || config.RotateInterval < 0 || config.Retention < 0 {
		return nil, errors.New("logx: size, rotation interval and retention must not be negative")
	}
	sink := &splitSink{
		files: make(map[Level]*levelFile, 4), maxSizeBytes: config.MaxSizeBytes,
		rotateInterval: config.RotateInterval, retention: config.Retention, console: config.Console,
		archiveQueue: make(chan archiveTask, 64), archiveStop: make(chan struct{}),
		archiveDone: make(chan struct{}), rotationStop: make(chan struct{}), rotationDone: make(chan struct{}),
	}
	if strings.TrimSpace(config.Directory) == "" {
		return sink, nil
	}
	directory, err := filepath.Abs(config.Directory)
	if err != nil {
		return nil, fmt.Errorf("logx: resolve log directory: %w", err)
	}
	sink.directory = directory
	sink.archiveDirectory = filepath.Join(directory, "archive")
	sink.pendingDirectory = filepath.Join(directory, ".pending")
	for _, path := range []string{directory, sink.archiveDirectory, sink.pendingDirectory} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			sink.closeOpenFiles()
			return nil, fmt.Errorf("logx: create directory %s: %w", path, err)
		}
	}
	now := time.Now().UTC()
	for _, configuredLevel := range []Level{LevelDebug, LevelInfo, LevelWarn, LevelError} {
		opened, err := openLevelFile(directory, configuredLevel, now)
		if err != nil {
			sink.closeOpenFiles()
			return nil, err
		}
		sink.files[configuredLevel] = opened
	}
	sink.background = true
	go sink.archiveLoop()
	go sink.rotationLoop()
	sink.recoverPendingArchives()
	sink.rotateExpired(now)
	return sink, nil
}

func (sink *splitSink) Write(configuredLevel Level, message string) {
	message = strings.TrimRight(message, "\r\n")
	encoded := []byte(fmt.Sprintf("%s [%s] %s\n", time.Now().UTC().Format(time.RFC3339Nano), configuredLevel, message))
	now := time.Now().UTC()
	var tasks []archiveTask
	var writeErrors []error
	sink.mutex.Lock()
	if sink.closed {
		sink.mutex.Unlock()
		return
	}
	if opened := sink.files[configuredLevel]; opened != nil {
		if sink.rotationDue(opened, now, int64(len(encoded))) {
			task, err := sink.rotateLocked(opened, now)
			if err != nil {
				writeErrors = append(writeErrors, err)
			} else if task.source != "" {
				tasks = append(tasks, task)
			}
		}
		written, err := opened.file.Write(encoded)
		opened.size += int64(written)
		if err != nil {
			writeErrors = append(writeErrors, fmt.Errorf("logx: write %s log: %w", configuredLevel, err))
		}
		if sink.maxSizeBytes > 0 && opened.size >= sink.maxSizeBytes {
			task, err := sink.rotateLocked(opened, now)
			if err != nil {
				writeErrors = append(writeErrors, err)
			} else if task.source != "" {
				tasks = append(tasks, task)
			}
		}
	}
	sink.mutex.Unlock()
	if sink.console {
		log.Printf("[%s] %s", configuredLevel, message)
	}
	for _, task := range tasks {
		sink.archiveQueue <- task
	}
	for _, err := range writeErrors {
		sink.reportInternal(err)
	}
}

func (sink *splitSink) Close() error {
	sink.closeOnce.Do(func() {
		if sink.background {
			close(sink.rotationStop)
			<-sink.rotationDone
		}
		sink.mutex.Lock()
		sink.closed = true
		var closeErrors []error
		for _, opened := range sink.files {
			if err := opened.file.Close(); err != nil {
				closeErrors = append(closeErrors, fmt.Errorf("logx: close %s log: %w", opened.level, err))
			}
		}
		sink.mutex.Unlock()
		if sink.background {
			sink.archiveTasks.Wait()
			close(sink.archiveStop)
			<-sink.archiveDone
		}
		sink.backgroundMutex.Lock()
		closeErrors = append(closeErrors, sink.backgroundErrors...)
		sink.backgroundMutex.Unlock()
		sink.closeError = errors.Join(closeErrors...)
	})
	return sink.closeError
}

func (sink *splitSink) rotationDue(opened *levelFile, now time.Time, incoming int64) bool {
	if opened.size <= 0 {
		return false
	}
	if sink.maxSizeBytes > 0 && opened.size+incoming > sink.maxSizeBytes {
		return true
	}
	return sink.rotateInterval > 0 && !now.Before(opened.openedAt.Add(sink.rotateInterval))
}

func (sink *splitSink) rotateLocked(opened *levelFile, now time.Time) (archiveTask, error) {
	if opened.size <= 0 {
		opened.openedAt = now
		return archiveTask{}, nil
	}
	if err := opened.file.Close(); err != nil {
		return archiveTask{}, fmt.Errorf("logx: close %s before rotation: %w", opened.level, err)
	}
	sequence := sink.sequence.Add(1)
	name := fmt.Sprintf("%s-%s-%06d.log", strings.ToLower(opened.level.String()), now.Format("20060102T150405.000000000Z"), sequence)
	pendingPath := filepath.Join(sink.pendingDirectory, name)
	if err := os.Rename(opened.path, pendingPath); err != nil {
		reopened, reopenErr := os.OpenFile(opened.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if reopenErr == nil {
			opened.file = reopened
		}
		return archiveTask{}, errors.Join(fmt.Errorf("logx: rotate %s log: %w", opened.level, err), wrapSinkError("reopen active log", reopenErr))
	}
	reopened, err := os.OpenFile(opened.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		rollbackErr := os.Rename(pendingPath, opened.path)
		fallback, fallbackErr := os.OpenFile(opened.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if fallbackErr == nil {
			opened.file = fallback
		}
		return archiveTask{}, errors.Join(
			fmt.Errorf("logx: reopen %s after rotation: %w", opened.level, err),
			wrapSinkError("restore active log", rollbackErr), wrapSinkError("open active log fallback", fallbackErr),
		)
	}
	opened.file = reopened
	opened.size = 0
	opened.openedAt = now
	sink.archiveTasks.Add(1)
	return archiveTask{source: pendingPath, level: opened.level}, nil
}

func (sink *splitSink) rotateExpired(now time.Time) {
	if sink.rotateInterval <= 0 {
		return
	}
	var tasks []archiveTask
	var rotationErrors []error
	sink.mutex.Lock()
	if sink.closed {
		sink.mutex.Unlock()
		return
	}
	for _, configuredLevel := range []Level{LevelDebug, LevelInfo, LevelWarn, LevelError} {
		opened := sink.files[configuredLevel]
		if opened == nil || opened.size <= 0 || now.Before(opened.openedAt.Add(sink.rotateInterval)) {
			continue
		}
		task, err := sink.rotateLocked(opened, now)
		if err != nil {
			rotationErrors = append(rotationErrors, err)
		} else if task.source != "" {
			tasks = append(tasks, task)
		}
	}
	sink.mutex.Unlock()
	for _, task := range tasks {
		sink.archiveQueue <- task
	}
	for _, err := range rotationErrors {
		sink.reportInternal(err)
	}
}

func (sink *splitSink) rotationLoop() {
	defer close(sink.rotationDone)
	if sink.rotateInterval <= 0 {
		<-sink.rotationStop
		return
	}
	checkInterval := sink.rotateInterval / 4
	if checkInterval > time.Minute {
		checkInterval = time.Minute
	}
	if checkInterval < 10*time.Millisecond {
		checkInterval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			sink.rotateExpired(now.UTC())
		case <-sink.rotationStop:
			return
		}
	}
}

func (sink *splitSink) archiveLoop() {
	defer close(sink.archiveDone)
	for {
		select {
		case task := <-sink.archiveQueue:
			if err := sink.createArchive(task); err != nil {
				sink.recordBackgroundError(err)
				sink.reportInternal(err)
			}
			sink.archiveTasks.Done()
		case <-sink.archiveStop:
			return
		}
	}
}

func (sink *splitSink) recoverPendingArchives() {
	entries, err := os.ReadDir(sink.pendingDirectory)
	if err != nil {
		sink.recordBackgroundError(fmt.Errorf("logx: scan pending archives: %w", err))
		return
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		configuredLevel, valid := levelFromArchiveName(entry.Name())
		if !valid {
			continue
		}
		sink.archiveTasks.Add(1)
		sink.archiveQueue <- archiveTask{source: filepath.Join(sink.pendingDirectory, entry.Name()), level: configuredLevel}
	}
}

func levelFromArchiveName(name string) (Level, bool) {
	prefix := strings.ToLower(strings.SplitN(name, "-", 2)[0])
	switch prefix {
	case "debug":
		return LevelDebug, true
	case "info":
		return LevelInfo, true
	case "warn":
		return LevelWarn, true
	case "error":
		return LevelError, true
	default:
		return LevelInfo, false
	}
}

func openLevelFile(directory string, configuredLevel Level, now time.Time) (*levelFile, error) {
	path := filepath.Join(directory, strings.ToLower(configuredLevel.String())+".log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("logx: open %s log: %w", configuredLevel, err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("logx: protect %s log: %w", configuredLevel, err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("logx: inspect %s log: %w", configuredLevel, err)
	}
	openedAt := info.ModTime().UTC()
	if info.Size() == 0 || openedAt.IsZero() {
		openedAt = now
	}
	return &levelFile{level: configuredLevel, path: path, file: file, size: info.Size(), openedAt: openedAt}, nil
}

func (sink *splitSink) reportInternal(err error) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "logx internal error: %v\n", err)
	}
}

func (sink *splitSink) recordBackgroundError(err error) {
	if err == nil {
		return
	}
	sink.backgroundMutex.Lock()
	defer sink.backgroundMutex.Unlock()
	if len(sink.backgroundErrors) >= 32 {
		copy(sink.backgroundErrors, sink.backgroundErrors[1:])
		sink.backgroundErrors[len(sink.backgroundErrors)-1] = err
		return
	}
	sink.backgroundErrors = append(sink.backgroundErrors, err)
}

func (sink *splitSink) closeOpenFiles() {
	for _, opened := range sink.files {
		_ = opened.file.Close()
	}
}

func wrapSinkError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("logx: %s: %w", operation, err)
}
