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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const bytesPerMiB = 1024 * 1024

func writePayload(writer io.Writer, payload []byte, rateBytesPerSecond int64) (int, error) {
	if rateBytesPerSecond <= 0 {
		return writer.Write(payload)
	}

	const chunkSize = 64 * 1024
	started := time.Now()
	written := 0
	for written < len(payload) {
		end := written + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		n, err := writer.Write(payload[written:end])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}

		targetElapsed := time.Duration(int64(written) * int64(time.Second) / rateBytesPerSecond)
		if delay := targetElapsed - time.Since(started); delay > 0 {
			time.Sleep(delay)
		}
	}
	return written, nil
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

func main() {
	port := flag.String("port", "5173", "HTTP listen port")
	bind := flag.String("bind", "127.0.0.1", "bind address (use 0.0.0.0 to listen on all interfaces)")
	sizeMB := flag.Int("size", 20, "test file size in MB")
	maxSizeMB := flag.Int("max-size", 0, "maximum size accepted through ?size_mb=N (default: -size)")
	sendRateMiBPS := flag.Int("send-rate-mibps", 0, "maximum response rate in MiB/s (0 disables throttling)")
	flag.Parse()
	if *maxSizeMB == 0 {
		*maxSizeMB = *sizeMB
	}
	maxIntMiB := int64(^uint(0)>>1) / bytesPerMiB
	if *sizeMB < 1 || *maxSizeMB < *sizeMB || *sendRateMiBPS < 0 || int64(*maxSizeMB) > maxIntMiB || int64(*sendRateMiBPS) > maxIntMiB {
		fmt.Printf("invalid server configuration: default=%d MB max=%d MB send-rate=%d MiB/s\n", *sizeMB, *maxSizeMB, *sendRateMiBPS)
		os.Exit(2)
	}

	// 生成最大尺寸的随机数据。按需求返回前缀，使同一个 NAT 数据源
	// 可以在不重启隧道的情况下提供不同大小的完整性校验文件。
	maxSize := *maxSizeMB * bytesPerMiB
	fmt.Printf("生成 %d MB 测试数据（默认 %d MB）...\n", *maxSizeMB, *sizeMB)
	data := make([]byte, maxSize)
	if _, err := rand.Read(data); err != nil {
		fmt.Printf("生成测试数据失败: %v\n", err)
		os.Exit(1)
	}
	checksums := make(map[int]string)
	var checksumMu sync.Mutex
	checksumFor := func(requestedMB int) string {
		checksumMu.Lock()
		defer checksumMu.Unlock()
		if checksum, ok := checksums[requestedMB]; ok {
			return checksum
		}
		sum := sha256.Sum256(data[:requestedMB*bytesPerMiB])
		checksum := hex.EncodeToString(sum[:])
		checksums[requestedMB] = checksum
		return checksum
	}
	defaultChecksum := checksumFor(*sizeMB)
	fmt.Printf("测试文件 SHA256: %s\n", defaultChecksum)
	fmt.Printf("测试文件大小: %d 字节\n", *sizeMB*bytesPerMiB)

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
		fmt.Fprint(w, checksumFor(requestedMB))
	})

	// /file 提供测试文件下载。
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		requestedMB, err := requestedSizeMB(r, *sizeMB, *maxSizeMB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requestedSize := requestedMB * bytesPerMiB
		checksum := checksumFor(requestedMB)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", requestedSize))
		w.Header().Set("X-Checksum-SHA256", checksum)
		w.Header().Set("X-File-Size-MiB", strconv.Itoa(requestedMB))
		start := time.Now()
		n, writeErr := writePayload(w, data[:requestedSize], int64(*sendRateMiBPS)*bytesPerMiB)
		fmt.Printf("[%s] 已发送 %d/%d 字节 (%d MiB), 耗时 %v, err=%v\n",
			time.Now().Format("15:04:05"), n, requestedSize, requestedMB,
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
		fmt.Fprintf(w, "  GET /file?size_mb=N  下载 1..%d MiB 文件\n", *maxSizeMB)
		fmt.Fprintf(w, "\nSHA256: %s\n", defaultChecksum)
	})

	addr := *bind + ":" + *port
	fmt.Printf("HTTP 文件服务器监听: http://%s\n", addr)
	fmt.Printf("  下载测试文件: http://%s/file\n", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		// 大文件传输需要较长写超时。
		WriteTimeout: 15 * time.Minute,
		ReadTimeout:  1 * time.Minute,
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("服务器退出: %v\n", err)
		os.Exit(1)
	}
}
