package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// NAT P2P Tunnel 验证测试程序
// 用于验证 tunnel 功能是否正常工作

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
)

type TestResult struct {
	Name     string
	Success  bool
	Duration time.Duration
	Error    error
	Details  string
}

func main() {
	targetURL := flag.String("target", "http://127.0.0.1:5173/health", "目标 URL (原始服务)")
	tunnelURL := flag.String("tunnel", "http://127.0.0.1:15173/health", "Tunnel URL (通过隧道)")
	timeout := flag.Int("timeout", 5, "超时时间(秒)")
	continuous := flag.Bool("continuous", false, "持续监控模式")
	interval := flag.Int("interval", 10, "持续监控间隔(秒)")
	flag.Parse()

	fmt.Println("=== NAT P2P Tunnel 验证测试 ===")
	fmt.Printf("目标服务: %s\n", *targetURL)
	fmt.Printf("隧道服务: %s\n", *tunnelURL)
	fmt.Printf("超时设置: %d 秒\n\n", *timeout)

	if *continuous {
		fmt.Println("进入持续监控模式 (Ctrl+C 退出)")
		runContinuousTest(*targetURL, *tunnelURL, *timeout, *interval)
	} else {
		results := runTests(*targetURL, *tunnelURL, *timeout)
		printResults(results)
		if allPassed(results) {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}
}

func runTests(targetURL, tunnelURL string, timeout int) []TestResult {
	results := []TestResult{}

	// 测试1: 目标服务可用性
	results = append(results, testHTTP("目标服务可达性", targetURL, timeout))

	// 测试2: Tunnel 端口监听
	tunnelHost := extractHost(tunnelURL)
	results = append(results, testTCPPort("Tunnel 端口监听", tunnelHost, timeout))

	// 测试3: Tunnel HTTP 转发
	results = append(results, testHTTP("Tunnel HTTP 转发", tunnelURL, timeout))

	// 测试4: 内容一致性
	if results[0].Success && results[2].Success {
		results = append(results, testContentConsistency(targetURL, tunnelURL, timeout))
	}

	// 测试5: 延迟对比
	if results[0].Success && results[2].Success {
		results = append(results, testLatencyComparison(targetURL, tunnelURL, timeout))
	}

	return results
}

func testHTTP(name, url string, timeout int) TestResult {
	start := time.Now()
	result := TestResult{Name: name}

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	result.Success = resp.StatusCode == 200
	result.Duration = time.Since(start)
	result.Details = fmt.Sprintf("HTTP %d, Body: %s", resp.StatusCode, string(body))
	return result
}

func testTCPPort(name, host string, timeout int) TestResult {
	start := time.Now()
	result := TestResult{Name: name}

	conn, err := net.DialTimeout("tcp", host, time.Duration(timeout)*time.Second)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	conn.Close()

	result.Success = true
	result.Duration = time.Since(start)
	result.Details = fmt.Sprintf("端口 %s 可达", host)
	return result
}

func testContentConsistency(targetURL, tunnelURL string, timeout int) TestResult {
	start := time.Now()
	result := TestResult{Name: "内容一致性验证"}

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	// 获取目标内容
	resp1, err := client.Get(targetURL)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)

	// 获取 tunnel 内容
	resp2, err := client.Get(tunnelURL)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	// 对比
	result.Success = string(body1) == string(body2)
	result.Duration = time.Since(start)
	if result.Success {
		result.Details = "内容完全一致"
	} else {
		result.Details = fmt.Sprintf("内容不一致: [%s] vs [%s]", string(body1), string(body2))
	}
	return result
}

func testLatencyComparison(targetURL, tunnelURL string, timeout int) TestResult {
	start := time.Now()
	result := TestResult{Name: "延迟对比测试"}

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	// 测量目标延迟
	t1 := time.Now()
	resp1, err := client.Get(targetURL)
	latency1 := time.Since(t1)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	resp1.Body.Close()

	// 测量 tunnel 延迟
	t2 := time.Now()
	resp2, err := client.Get(tunnelURL)
	latency2 := time.Since(t2)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	resp2.Body.Close()

	overhead := latency2 - latency1
	result.Success = overhead < 500*time.Millisecond // 开销小于 500ms 算合格
	result.Duration = time.Since(start)
	result.Details = fmt.Sprintf("直连: %v, Tunnel: %v, 开销: %v",
		latency1.Round(time.Millisecond),
		latency2.Round(time.Millisecond),
		overhead.Round(time.Millisecond))
	return result
}

func runContinuousTest(targetURL, tunnelURL string, timeout, interval int) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	iteration := 0
	for {
		iteration++
		fmt.Printf("\n[迭代 %d] %s\n", iteration, time.Now().Format("2006-01-02 15:04:05"))
		results := runTests(targetURL, tunnelURL, timeout)
		printResultsCompact(results)
		<-ticker.C
	}
}

func printResults(results []TestResult) {
	fmt.Println("=== 测试结果 ===")
	fmt.Println()
	for i, r := range results {
		status := colorRed + "✗ 失败" + colorReset
		if r.Success {
			status = colorGreen + "✓ 通过" + colorReset
		}

		fmt.Printf("[测试 %d] %s\n", i+1, r.Name)
		fmt.Printf("  状态: %s\n", status)
		fmt.Printf("  耗时: %v\n", r.Duration.Round(time.Millisecond))
		if r.Details != "" {
			fmt.Printf("  详情: %s\n", r.Details)
		}
		if r.Error != nil {
			fmt.Printf("  错误: %s%v%s\n", colorRed, r.Error, colorReset)
		}
		fmt.Println()
	}

	passed := 0
	for _, r := range results {
		if r.Success {
			passed++
		}
	}
	fmt.Printf("总结: %d/%d 通过\n", passed, len(results))
}

func printResultsCompact(results []TestResult) {
	for _, r := range results {
		status := colorRed + "✗" + colorReset
		if r.Success {
			status = colorGreen + "✓" + colorReset
		}
		fmt.Printf("  %s %-20s %6v %s\n",
			status, r.Name, r.Duration.Round(time.Millisecond), r.Details)
	}
}

func allPassed(results []TestResult) bool {
	for _, r := range results {
		if !r.Success {
			return false
		}
	}
	return true
}

func extractHost(url string) string {
	// 简单提取 host:port 从 http://host:port/path
	url = url[7:] // 去掉 http://
	for i, c := range url {
		if c == '/' {
			return url[:i]
		}
	}
	return url
}
