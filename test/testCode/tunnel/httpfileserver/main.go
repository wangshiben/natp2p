// Command httpfileserver 是一个简单的 HTTP 文件服务器，用于隧道转发测试。
//
// 它提供:
//   - GET /health        健康检查，返回 {"status":"ok"}
//   - GET /file          下载测试文件（启动时生成的指定大小随机文件）
//   - GET /              首页，列出可用端点
//
// 用法:
//
//	httpfileserver -port 5173 -size 100 -max-size 200
//
// -size 是默认大小，-max-size 是允许通过 ?size_mb=N 请求的最大值，
// 两者单位均为 MiB。每个尺寸都有对应的 SHA256，便于校验完整性。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"bnfs_p2p/logx"
)

const bytesPerMiB = 1024 * 1024

type aggregateRateLimiter struct {
	mu             sync.Mutex
	bytesPerSecond int64
	nextWriteAt    time.Time
}

func newAggregateRateLimiter(bytesPerSecond int64) *aggregateRateLimiter {
	if bytesPerSecond <= 0 {
		return nil
	}
	return &aggregateRateLimiter{bytesPerSecond: bytesPerSecond}
}

func (limiter *aggregateRateLimiter) wait(ctx context.Context, byteCount int) error {
	if limiter == nil || byteCount <= 0 {
		return nil
	}
	now := time.Now()
	limiter.mu.Lock()
	writeAt := limiter.nextWriteAt
	if writeAt.Before(now) {
		writeAt = now
	}
	interval := time.Duration(int64(byteCount) * int64(time.Second) / limiter.bytesPerSecond)
	limiter.nextWriteAt = writeAt.Add(interval)
	limiter.mu.Unlock()

	if delay := time.Until(writeAt); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func writePayload(writer io.Writer, payload []byte, rateBytesPerSecond int64) (int, error) {
	return writeVariantPayload(writer, payload, rateBytesPerSecond, "")
}

func writeVariantPayload(writer io.Writer, payload []byte, rateBytesPerSecond int64, variant string) (int, error) {
	return writeVariantPayloadWithLimiter(
		context.Background(), writer, payload, newAggregateRateLimiter(rateBytesPerSecond), variant,
	)
}

func writeVariantPayloadWithLimiter(
	ctx context.Context,
	writer io.Writer,
	payload []byte,
	limiter *aggregateRateLimiter,
	variant string,
) (int, error) {
	if limiter == nil {
		if variant == "" {
			return writer.Write(payload)
		}
	}

	const chunkSize = 64 * 1024
	var variantSeed [sha256.Size]byte
	var transformed []byte
	if variant != "" {
		variantSeed = sha256.Sum256([]byte(variant))
		transformed = make([]byte, chunkSize)
	}
	written := 0
	for written < len(payload) {
		end := written + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[written:end]
		if variant != "" {
			variantChunk := transformed[:len(chunk)]
			for index, value := range chunk {
				variantChunk[index] = value ^ variantSeed[(written+index)%len(variantSeed)]
			}
			chunk = variantChunk
		}
		if err := limiter.wait(ctx, len(chunk)); err != nil {
			return written, err
		}
		n, err := writer.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func checksumPayload(payload []byte, variant string) string {
	hasher := sha256.New()
	if variant == "" {
		_, _ = hasher.Write(payload)
	} else {
		const chunkSize = 64 * 1024
		variantSeed := sha256.Sum256([]byte(variant))
		transformed := make([]byte, chunkSize)
		for offset := 0; offset < len(payload); offset += chunkSize {
			end := offset + chunkSize
			if end > len(payload) {
				end = len(payload)
			}
			variantChunk := transformed[:end-offset]
			for index, value := range payload[offset:end] {
				variantChunk[index] = value ^ variantSeed[(offset+index)%len(variantSeed)]
			}
			_, _ = hasher.Write(variantChunk)
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func requestedSizeMB(r *http.Request, defaultSizeMB, maxSizeMB int) (int, error) {
	raw := r.URL.Query().Get("size_mb")
	if raw == "" {
		return defaultSizeMB, nil
	}
	sizeMB, err := strconv.Atoi(raw)
	if err != nil || sizeMB < 1 || sizeMB > maxSizeMB {
		return 0, fmt.Errorf("size_mb must be an integer in [1, %d]", maxSizeMB)
	}
	return sizeMB, nil
}

func requestedVariant(r *http.Request) (string, error) {
	variant := r.URL.Query().Get("variant")
	if len(variant) > 128 {
		return "", fmt.Errorf("variant must not exceed 128 characters")
	}
	for _, character := range variant {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return "", fmt.Errorf("variant contains an unsupported character")
	}
	return variant, nil
}

func main() {
	port := flag.String("port", "5173", "HTTP listen port")
	bind := flag.String("bind", "127.0.0.1", "bind address (use 0.0.0.0 to listen on all interfaces)")
	sizeMB := flag.Int("size", 20, "test file size in MB")
	maxSizeMB := flag.Int("max-size", 0, "maximum size accepted through ?size_mb=N (default: -size)")
	sendRateMiBPS := flag.Int("send-rate-mibps", 0, "aggregate NatServer response rate in MiB/s (0 disables throttling)")
	sendRateKiBPS := flag.Int("send-rate-kibps", 0, "aggregate NatServer response rate in KiB/s (0 disables; mutually exclusive with -send-rate-mibps)")
	flag.Parse()
	if *maxSizeMB == 0 {
		*maxSizeMB = *sizeMB
	}
	maxIntMiB := int64(^uint(0)>>1) / bytesPerMiB
	sendRateBytesPerSecond, rateErr := resolveSendRateBytes(*sendRateMiBPS, *sendRateKiBPS)
	if *sizeMB < 1 || *maxSizeMB < *sizeMB || int64(*maxSizeMB) > maxIntMiB || rateErr != nil {
		logx.Errorf("invalid server configuration: default=%d MB max=%d MB send-rate=%d MiB/s send-rate=%d KiB/s",
			*sizeMB, *maxSizeMB, *sendRateMiBPS, *sendRateKiBPS)
		os.Exit(2)
	}

	// 生成最大尺寸的随机数据。按需求返回前缀，使同一个 NAT 数据源
	// 可以在不重启隧道的情况下提供不同大小的完整性校验文件。
	maxSize := *maxSizeMB * bytesPerMiB
	fmt.Printf("生成 %d MB 测试数据（默认 %d MB）...\n", *maxSizeMB, *sizeMB)
	data := make([]byte, maxSize)
	if _, err := rand.Read(data); err != nil {
		logx.Errorf("生成测试数据失败: %v", err)
		os.Exit(1)
	}
	type checksumKey struct {
		sizeMB  int
		variant string
	}
	checksums := make(map[checksumKey]string)
	var checksumMu sync.Mutex
	checksumFor := func(requestedMB int, variant string) string {
		checksumMu.Lock()
		defer checksumMu.Unlock()
		key := checksumKey{sizeMB: requestedMB, variant: variant}
		if checksum, ok := checksums[key]; ok {
			return checksum
		}

		checksum := checksumPayload(data[:requestedMB*bytesPerMiB], variant)
		checksums[key] = checksum
		return checksum
	}
	defaultChecksum := checksumFor(*sizeMB, "")
	fmt.Printf("测试文件 SHA256: %s\n", defaultChecksum)
	fmt.Printf("测试文件大小: %d 字节\n", *sizeMB*bytesPerMiB)
	sendLimiter := newAggregateRateLimiter(sendRateBytesPerSecond)
	if sendLimiter != nil {
		fmt.Printf("NatServer 聚合发送上限: %d 字节/秒（所有响应共享）\n", sendRateBytesPerSecond)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	// /checksum 返回测试文件的 SHA256，供客户端校验。
	mux.HandleFunc("/checksum", func(w http.ResponseWriter, r *http.Request) {
		requestedMB, err := requestedSizeMB(r, *sizeMB, *maxSizeMB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		variant, err := requestedVariant(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, checksumFor(requestedMB, variant))
	})

	// /file 提供测试文件下载。
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		requestedMB, err := requestedSizeMB(r, *sizeMB, *maxSizeMB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		variant, err := requestedVariant(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requestedSize := requestedMB * bytesPerMiB
		checksum := checksumFor(requestedMB, variant)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", requestedSize))
		w.Header().Set("X-Checksum-SHA256", checksum)
		w.Header().Set("X-File-Size-MiB", strconv.Itoa(requestedMB))
		w.Header().Set("X-File-Variant", variant)
		if sendLimiter != nil {
			w.Header().Set("X-Rate-Limit-Scope", "nat-server-aggregate")
			w.Header().Set("X-Rate-Limit-Bytes-Per-Second", strconv.FormatInt(sendRateBytesPerSecond, 10))
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="bnfs-%dMiB-%s.bin"`, requestedMB, checksum))
		start := time.Now()
		n, writeErr := writeVariantPayloadWithLimiter(r.Context(), w, data[:requestedSize], sendLimiter, variant)
		fmt.Printf("[%s] 已发送 %d/%d 字节 (%d MiB), variant=%s sha256=%s 耗时 %v, err=%v\n",
			time.Now().Format("15:04:05"), n, requestedSize, requestedMB, variant, checksum,
			time.Since(start).Round(time.Millisecond), writeErr)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "HTTP File Server\n\n")
		fmt.Fprintf(w, "端点:\n")
		fmt.Fprintf(w, "  GET /health    健康检查\n")
		fmt.Fprintf(w, "  GET /checksum  测试文件 SHA256\n")
		fmt.Fprintf(w, "  GET /file      下载测试文件 (%d MB)\n", *sizeMB)
		fmt.Fprintf(w, "  GET /file?size_mb=N&variant=ID  下载 1..%d MiB 唯一变体文件\n", *maxSizeMB)
		fmt.Fprintf(w, "\nSHA256: %s\n", defaultChecksum)
	})

	addr := *bind + ":" + *port
	fmt.Printf("HTTP 文件服务器监听: http://%s\n", addr)
	fmt.Printf("  下载测试文件: http://%s/file\n", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		// 高并发限速传输可能受 Relay 总带宽约束，避免完整性测试被
		// HTTP 层先于传输截止时间中断。
		WriteTimeout: 24 * time.Hour,
		ReadTimeout:  1 * time.Minute,
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logx.Errorf("HTTP 文件服务器运行循环退出，未执行强制退出: %v", err)
	}
}

func resolveSendRateBytes(mibPerSecond, kibPerSecond int) (int64, error) {
	if mibPerSecond < 0 || kibPerSecond < 0 || (mibPerSecond > 0 && kibPerSecond > 0) {
		return 0, fmt.Errorf("send rate must use exactly one non-negative unit")
	}
	if mibPerSecond > 0 {
		if int64(mibPerSecond) > int64(^uint(0)>>1)/bytesPerMiB {
			return 0, fmt.Errorf("MiB/s rate is too large")
		}
		return int64(mibPerSecond) * bytesPerMiB, nil
	}
	const bytesPerKiB = 1024
	if int64(kibPerSecond) > int64(^uint(0)>>1)/bytesPerKiB {
		return 0, fmt.Errorf("KiB/s rate is too large")
	}
	return int64(kibPerSecond) * bytesPerKiB, nil
}
