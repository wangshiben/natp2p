package main

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func Server() {
	starter := networkFrameWork.NewRelayStarter(":9000")
	starter.StartListen()
}
func main() {
	CMDClient()

}

func CMDClient() {
	address := flag.String("server", "127.0.0.1:9000", "relay Server address")
	mode := flag.String("mode", "relayServer", "relay Server address")
	targetId := flag.String("targetId", "targetId", "relay Server address")
	size := flag.Int("size", 14*1024, "Message Payload size in bytes")
	flag.Parse()
	fmt.Printf("mode: %s, address: %s, targetId: %s, size: %d\n", *mode, *address, *targetId, *size)
	switch *mode {
	case "relayServer":
		fmt.Println("Starting relay server...")
		server := RelayServer(*address, *size)
		hash := sha256.Sum256([]byte(server))
		originalNodeId := hex.EncodeToString(hash[:])
		fmt.Println(originalNodeId)
		select {}
	case "client":
		RelayClient(*address, *targetId, *size)
	case "server":
		Server()
	}
}

func RelayClient(relayAddress, targetId string, size int) {
	pair, err := crypoto.MakeKeyPair()
	if err != nil {
		panic(err)
	}
	relay, connectionId, err := client.ConnectNodeWithTargetRelay(targetId, relayAddress, pair)
	if err != nil {
		panic(err)
	}
	fmt.Printf("relay connect success connectionID: %s \n", connectionId)
	keyStr := crypoto.GetPubKeyStr(pair.PublicKey())
	sum256 := sha256.Sum256([]byte(keyStr))
	t := &TrafficMonitor{
		stopCh:             make(chan struct{}),
		nodeId:             hex.EncodeToString(sum256[:]),
		targetConnectionId: connectionId,
	}
	t.Start(relay, size, 100*time.Second)
}

// RelayServer 注册成可被中继的节点：连上 relay 服务器后等首条消息（来自某个 client 的 hello），
// 用 client 公钥推导出对端 nodeId 并把流绑定上去，再做 TLS 握手 + 流量测试。
func RelayServer(addr string, size int) string {
	pair, err := crypoto.MakeKeyPair()
	if err != nil {
		panic(err)
	}
	keyStr := crypoto.GetPubKeyStr(pair.PublicKey())
	stream, err := networkFrameWork.TryRegisterRelayStream(keyStr, addr)
	if err != nil {
		panic(err)
	}
	go func() {
		message, err := stream.NextMessage(context.Background())
		if err != nil {
			panic(err)
		}
		fmt.Println("receive message")
		hash := sha256.Sum256(message.Payload)
		clientNodeId := hex.EncodeToString(hash[:])
		tcpStream := stream.(*networkFrameWork.TcpStream)
		tcpStream.SetIdentity(clientNodeId, message.Header.ConnectionId)
		crypto, err := crypoto.NewTLSCrypto(tcpStream, pair)
		if err != nil {
			panic(err)
		}
		tcpStream.SetCryptoSuite(crypto)
		CurrentNodeHex := crypoto.GetPubKeyStr(pair.PublicKey())
		sum256 := sha256.Sum256([]byte(CurrentNodeHex))
		t := &TrafficMonitor{
			stopCh:             make(chan struct{}),
			nodeId:             hex.EncodeToString(sum256[:]),
			targetConnectionId: message.Header.ConnectionId,
		}
		fmt.Println("waiting crypto message")
		t.Start(tcpStream, size, 100*time.Second)
	}()
	return keyStr
}

// TrafficMonitor 流量监控器
const senderWorkers = 2

type TrafficMonitor struct {
	TxBytes   int64
	TxPackets int64
	RxBytes   int64
	RxPackets int64

	PeakTxSpeed int64
	PeakRxSpeed int64

	TotalTxBytes   int64
	TotalTxPackets int64
	TotalRxBytes   int64
	TotalRxPackets int64

	stopCh             chan struct{}
	nodeId             string
	targetConnectionId string
	fileSend           *os.File
	fileReceive        *os.File
	wg                 sync.WaitGroup
}

func (tm *TrafficMonitor) Start(stream network.Stream, packetSize int, duration time.Duration) {
	tm.stopCh = make(chan struct{})
	tm.wg.Add(senderWorkers + 2)
	for i := 0; i < senderWorkers; i++ {
		go tm.sender(stream, packetSize)
	}
	go tm.receiver(stream)
	go tm.monitor()

	go func() {
		time.Sleep(duration)
		fmt.Println("\n⏰ 测试时间到，正在关闭...")
		close(tm.stopCh)
	}()

	fmt.Printf("🚀 测试开始... sender workers=%d\n", senderWorkers)
	tm.Wait()
}

func (tm *TrafficMonitor) Wait() {
	tm.wg.Wait()
	tm.printReport()
}

func (tm *TrafficMonitor) monitor() {
	defer tm.wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tm.stopCh:
			return
		case <-ticker.C:
			txBytesDelta := atomic.SwapInt64(&tm.TxBytes, 0)
			rxBytesDelta := atomic.SwapInt64(&tm.RxBytes, 0)
			txPacketsDelta := atomic.SwapInt64(&tm.TxPackets, 0)
			rxPacketsDelta := atomic.SwapInt64(&tm.RxPackets, 0)

			atomic.AddInt64(&tm.TotalTxBytes, txBytesDelta)
			atomic.AddInt64(&tm.TotalTxPackets, txPacketsDelta)
			atomic.AddInt64(&tm.TotalRxBytes, rxBytesDelta)
			atomic.AddInt64(&tm.TotalRxPackets, rxPacketsDelta)

			if txBytesDelta > atomic.LoadInt64(&tm.PeakTxSpeed) {
				atomic.StoreInt64(&tm.PeakTxSpeed, txBytesDelta)
			}
			if rxBytesDelta > atomic.LoadInt64(&tm.PeakRxSpeed) {
				atomic.StoreInt64(&tm.PeakRxSpeed, rxBytesDelta)
			}

			fmt.Printf("\r⏱️ 实时: ⬆️ %s/s (%d pkts) | ⬇️ %s/s (%d pkts)    ",
				formatBytes(txBytesDelta), txPacketsDelta,
				formatBytes(rxBytesDelta), rxPacketsDelta)
		}
	}
}

// sender 固定并发 worker：每个 worker 自己串行阻塞发送，整体形成固定 10 线程压测。
func (tm *TrafficMonitor) sender(stream network.Stream, size int) {
	defer tm.wg.Done()

	payload := make([]byte, size)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-tm.stopCh
		cancel()
	}()

	for {
		select {
		case <-tm.stopCh:
			return
		default:
		}
		targetConnectionId := tm.targetConnectionId
		if targetConnectionId == "" {
			targetConnectionId = stream.ConnectionId()
		}
		msg := &network.Message{
			Header: &network.Header{
				ConnectionId: targetConnectionId,
				NodeId:       stream.NodeId(),
			},
			Payload: payload,
		}
		if err := stream.SendMessage(ctx, msg); err != nil {
			fmt.Println("sender error:", err)
			return
		}
		atomic.AddInt64(&tm.TxBytes, int64(size+network.HeaderLength))
		atomic.AddInt64(&tm.TxPackets, 1)
	}
}

// receiver NextMessage 现在直接吃 ctx，stopCh 触发后 cancel 即可解除阻塞。
func (tm *TrafficMonitor) receiver(stream network.Stream) {
	defer tm.wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-tm.stopCh
		cancel()
	}()

	for {
		msg, err := stream.NextMessage(ctx)
		if err != nil {
			return
		}
		atomic.AddInt64(&tm.RxBytes, int64(len(msg.Payload)+network.HeaderLength))
		atomic.AddInt64(&tm.RxPackets, 1)
	}
}

func (tm *TrafficMonitor) printReport() {
	fmt.Println("\n\n📊 --- 测试完成 ---")
	fmt.Printf("🏆 峰值上传: %s/s\n", formatBytes(atomic.LoadInt64(&tm.PeakTxSpeed)))
	fmt.Printf("🏆 峰值下载: %s/s\n", formatBytes(atomic.LoadInt64(&tm.PeakRxSpeed)))

	fmt.Printf("📈 总上传: %s (%d 个包)\n", formatBytes(atomic.LoadInt64(&tm.TotalTxBytes)), atomic.LoadInt64(&tm.TotalTxPackets))
	fmt.Printf("📈 总下载: %s (%d 个包)\n", formatBytes(atomic.LoadInt64(&tm.TotalRxBytes)), atomic.LoadInt64(&tm.TotalRxPackets))
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
