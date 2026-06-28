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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bnfs_p2p/logx"
	"bnfs_p2p/p2pnode/impl/relaynode"
)

func main() {
	mode := flag.String("mode", "index", "node mode: index | relay")
	listen := flag.String("listen", ":9000", "listen address")
	public := flag.String("public", "", "public address (relay only, auto-inferred if empty)")
	indexAddr := flag.String("index", "", "index address to register to (relay only)")
	bridgeWidth := flag.Int("bridge-width", 0, "cross-relay striping width: 0=auto(throughput-driven), 1=off, >1=force M legs")
	flag.Parse()

	logx.SetLevel(logx.LevelInfo)

	rn, err := relaynode.NewRelayNode(nil, *listen, *public)
	if err != nil {
		fmt.Printf("创建节点失败: %v\n", err)
		os.Exit(1)
	}
	if *bridgeWidth > 0 {
		rn.SetBridgeWidth(*bridgeWidth)
		fmt.Printf("跨中继条带化宽度(强制): %d\n", *bridgeWidth)
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
