// Command nodeserver 是一个非交互式的 index/relay 启动器，便于自动化测试脚本管理。
//
// 用法:
//
//	nodeserver -mode index -listen :9000
//	nodeserver -mode relay -listen :9001 -index 127.0.0.1:9000 -public 127.0.0.1:9001
//
// index 模式: 启动一个不向任何节点注册的中继中心(relay 的上级)。
// relay 模式: 启动一个中转服务器，并向指定 index 注册。
//
// 进程阻塞运行直到收到 SIGINT/SIGTERM。
package main

import (
	"crypto/ecdh"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"bnfs_p2p/admissioncli"
	"bnfs_p2p/logx"
	"bnfs_p2p/p2pnode/impl/natnode"
	"bnfs_p2p/p2pnode/impl/relaynode"
)

func main() {
	mode := flag.String("mode", "index", "node mode: index | relay")
	listen := flag.String("listen", ":9000", "listen address")
	public := flag.String("public", "", "public address (relay only, auto-inferred if empty)")
	indexAddr := flag.String("index", "", "index address to register to (relay only)")
	peerAddrs := flag.String("peer", "", "additional relay peer addresses, comma separated (relay only)")
	bridgeWidth := flag.Int("bridge-width", 0, "cross-relay striping width: 0=auto(throughput-driven), 1=off, >1=force M legs")
	caURL := flag.String("ca", "", "CA/indexServer web 地址(如 http://IP:9000); 给了即启用网络准入+计费")
	admissionMode := flag.String("admission", "", "准入级别: off|warn|enforce (默认: 有 -ca 则 enforce)")
	keyPath := flag.String("key", "", "Relay 身份私钥文件；不存在时原子生成并持久化")
	billingQueue := flag.String("billing-queue", "", "双签凭证 waitSubmit 持久文件")
	flag.Parse()

	logx.SetLevel(logx.LevelInfo)

	var privateKey *ecdh.PrivateKey
	var err error
	if *keyPath != "" {
		privateKey, err = natnode.LoadOrCreatePrivateKeyFile(*keyPath)
		if err != nil {
			fmt.Printf("加载或创建 Relay 身份失败: %v\n", err)
			os.Exit(1)
		}
	}
	rn, err := relaynode.NewRelayNode(privateKey, *listen, *public)
	if err != nil {
		fmt.Printf("创建节点失败: %v\n", err)
		os.Exit(1)
	}
	if *bridgeWidth > 0 {
		rn.SetBridgeWidth(*bridgeWidth)
		fmt.Printf("跨中继条带化宽度(强制): %d\n", *bridgeWidth)
	}
	if err := rn.SetBillingQueuePath(*billingQueue); err != nil {
		fmt.Printf("配置 waitSubmit 持久文件失败: %v\n", err)
		os.Exit(1)
	}

	// 网络准入 + 计费（-ca 给了才启用；index 与 relay 都需持 relay 角色证书）。
	if err := admissioncli.SetupRelay(rn, *caURL, *admissionMode); err != nil {
		fmt.Printf("启用网络准入失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Node Server (%s) ===\n", *mode)
	fmt.Printf("节点 ID: %s\n", rn.ID())
	fmt.Printf("监听: %s  对外地址: %s\n", *listen, rn.Addr())

	if *mode == "relay" && *indexAddr != "" {
		fmt.Printf("正在向 index 注册: %s\n", *indexAddr)
		rn.RegisterToIndex(*indexAddr, func(indexID, addr string) {
			fmt.Printf("已注册到 index: id=%s addr=%s\n", indexID, addr)
		})
	}
	if *mode == "relay" {
		for _, addr := range strings.Split(*peerAddrs, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" || addr == *indexAddr {
				continue
			}
			rn.ConnectPeer(addr)
			fmt.Printf("维持到对端 relay 的控制链路: %s\n", addr)
		}
	}

	go rn.Start()

	// 等待启动完成。
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("%s 已就绪\n", *mode)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("正在关闭...")
	_ = rn.Close()
}
