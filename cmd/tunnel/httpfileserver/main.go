// Command httpfileserver 是一个简单的 HTTP 文件服务器，用于隧道转发测试。
//
// 它提供:
//   - GET /health        健康检查，返回 {"status":"ok"}
//   - GET /file          下载测试文件（启动时生成的指定大小随机文件）
//   - GET /              首页，列出可用端点
//
// 用法:
//
//	httpfileserver -port 5173 -size 20
//
// -size 单位 MB，启动时生成该大小的测试文件并计算 SHA256，便于校验完整性。
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := flag.String("port", "5173", "HTTP listen port")
	bind := flag.String("bind", "127.0.0.1", "bind address (use 0.0.0.0 to listen on all interfaces)")
	sizeMB := flag.Int("size", 20, "test file size in MB")
	flag.Parse()

	// 生成测试文件到内存（随机数据，便于校验）。
	size := *sizeMB * 1024 * 1024
	fmt.Printf("生成 %d MB 测试文件...\n", *sizeMB)
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		fmt.Printf("生成测试数据失败: %v\n", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(data)
	checksum := hex.EncodeToString(sum[:])
	fmt.Printf("测试文件 SHA256: %s\n", checksum)
	fmt.Printf("测试文件大小: %d 字节\n", size)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	// /checksum 返回测试文件的 SHA256，供客户端校验。
	mux.HandleFunc("/checksum", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, checksum)
	})

	// /file 提供测试文件下载。
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.Header().Set("X-Checksum-SHA256", checksum)
		start := time.Now()
		n, _ := w.Write(data)
		fmt.Printf("[%s] 已发送 %d 字节, 耗时 %v\n",
			time.Now().Format("15:04:05"), n, time.Since(start).Round(time.Millisecond))
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
		fmt.Fprintf(w, "\nSHA256: %s\n", checksum)
	})

	addr := *bind + ":" + *port
	fmt.Printf("HTTP 文件服务器监听: http://%s\n", addr)
	fmt.Printf("  下载测试文件: http://%s/file\n", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		// 大文件传输需要较长写超时。
		WriteTimeout: 5 * time.Minute,
		ReadTimeout:  1 * time.Minute,
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("服务器退出: %v\n", err)
		os.Exit(1)
	}
}
