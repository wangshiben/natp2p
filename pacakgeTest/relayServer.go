package main

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func Server(listenAddr string) {
	starter := networkFrameWork.NewRelayStarter(listenAddr)
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
		server, done := RelayServer(*address, *size)
		hash := sha256.Sum256([]byte(server))
		originalNodeId := hex.EncodeToString(hash[:])
		fmt.Println(originalNodeId)
		<-done
	case "client":
		RelayClient(*address, *targetId, *size)
	case "server":
		Server(*address)
	}
}

func RelayClient(relayAddress, targetId string, size int) {
	pair, err := crypoto.MakeKeyPair()
	if err != nil {
		panic(err)
	}
	streamClient, connectionId, err := client.ConnectNodeWithTargetRelay(targetId, relayAddress, pair)
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
	t.Start(streamClient, size, 100*time.Second)
}

// RelayServer 注册成可被中继的节点：连上 relay 服务器后等首条消息（来自某个 client 的 hello），
// 用 client 公钥推导出对端 nodeId 并把流绑定上去，再做 TLS 握手 + 流量测试。
func RelayServer(addr string, size int) (string, <-chan struct{}) {
	done := make(chan struct{})
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
		defer close(done)
		message, err := stream.NextMessage(context.Background())
		if err != nil {
			panic(err)
		}
		fmt.Println("receive message")
		hash := sha256.Sum256(message.Payload)
		clientNodeId := hex.EncodeToString(hash[:])
		if !networkFrameWork.SetStreamIdentity(stream, clientNodeId, message.Header.ConnectionId) {
			panic("SetStreamIdentity failed")
		}
		streamClient := client.NewStreamClient(stream)
		crypto, err := crypoto.NewTLSCrypto(streamClient, pair)
		if err != nil {
			panic(err)
		}
		streamClient.SetCryptoSuite(crypto)
		CurrentNodeHex := crypoto.GetPubKeyStr(pair.PublicKey())
		sum256 := sha256.Sum256([]byte(CurrentNodeHex))
		t := &TrafficMonitor{
			stopCh:             make(chan struct{}),
			nodeId:             hex.EncodeToString(sum256[:]),
			targetConnectionId: message.Header.ConnectionId,
		}
		fmt.Println("waiting crypto message")
		t.Start(streamClient, size, 100*time.Second)
	}()
	return keyStr, done
}

// TrafficMonitor 流量监控器
const (
	senderWorkers     = 8  // 增加并发发送 worker，从 2 提升到 8
	traceHeaderLength = 32
)

var traceMagic = [8]byte{'B', 'N', 'F', 'S', 'T', 'R', 'C', '1'}

type tracePacketKey struct {
	senderID uint64
	workerID uint32
	seq      uint64
}

type traceStreamKey struct {
	senderID uint64
	workerID uint32
}

type traceStreamStats struct {
	count  int
	maxSeq uint64
}

type TrafficMonitor struct {
	// TxBytes / TxPackets 是当前 1 秒实时窗口内的发送统计；monitor() 每秒 Swap 清零一次。
	// 这里的 packet 指一次 SendMessage 发出的业务消息，不是底层网络 Frame。
	TxBytes   int64
	TxPackets int64

	// RxBytes / RxPackets 是当前 1 秒实时窗口内的接收统计；monitor() 每秒 Swap 清零一次。
	// 这里的 packet 指一次 NextMessage 收到的完整业务消息，不是底层网络 Frame。
	RxBytes   int64
	RxPackets int64

	// PeakTxSpeed / PeakRxSpeed 记录测试期间出现过的最大 1 秒窗口字节数，用来打印峰值速率。
	PeakTxSpeed int64
	PeakRxSpeed int64

	// TotalTxBytes / TotalTxPackets 是 monitor() 从实时窗口累计出来的总发送量。
	// 注意：当前实现只在 monitor tick 时汇总，测试结束前最后不足 1 秒的窗口可能还没被加进来。
	TotalTxBytes   int64
	TotalTxPackets int64

	// TotalRxBytes / TotalRxPackets 是 monitor() 从实时窗口累计出来的总接收量。
	// 注意：这个口径和 Trace 的逐包记录不同，结束瞬间也可能漏掉最后一个未 flush 的窗口。
	TotalRxBytes   int64
	TotalRxPackets int64

	// stopCh 用来广播测试结束；sender、receiver、monitor 都监听它退出。
	stopCh chan struct{}

	// nodeId 是本端节点 ID；senderID 会从它派生，用于在 payload trace 里标记“是谁发的包”。
	nodeId string

	// targetConnectionId 是发包时写入 Header.ConnectionId 的目标连接；为空时回退到 stream.ConnectionId()。
	targetConnectionId string

	// senderID 是从 nodeId 派生出的 64 位发送者标识，会写进每个 trace payload。
	senderID uint64

	// fileSend / fileReceive 预留给后续落盘记录发送/接收数据；当前压测逻辑没有使用。
	fileSend    *os.File
	fileReceive *os.File

	// wg 等待 sender workers、receiver、monitor 全部退出后再打印报告。
	wg sync.WaitGroup

	// traceMu 保护下面所有 trace 统计 map / slice / counter。
	traceMu sync.Mutex

	// seenTrace 记录每个 trace 包出现过几次；key = senderID + workerID + seq，用来判断重复包。
	seenTrace map[tracePacketKey]int

	// streamTraceStats 按 senderID + workerID 聚合接收数量和最大 seq，用来估算是否缺包。
	streamTraceStats map[traceStreamKey]*traceStreamStats

	// duplicateSamples 保存少量重复包样本，方便报告里定位重复来自哪个 sender / worker / seq。
	duplicateSamples []tracePacketKey

	// parseFailures 记录收到的 payload 不能解析成 trace 格式的次数。
	parseFailures int
}

func (tm *TrafficMonitor) Start(stream network.Stream, packetSize int, duration time.Duration) {
	tm.stopCh = make(chan struct{})
	tm.senderID = traceSenderID(tm.nodeId)
	tm.seenTrace = make(map[tracePacketKey]int)
	tm.streamTraceStats = make(map[traceStreamKey]*traceStreamStats)
	tm.wg.Add(senderWorkers + 2)
	for i := 0; i < senderWorkers; i++ {
		go tm.sender(stream, packetSize, uint32(i))
	}
	go tm.receiver(stream)
	go tm.monitor()

	go func() {
		time.Sleep(duration)
		fmt.Println("\n⏰ 测试时间到，正在关闭...")
		close(tm.stopCh)
		_ = stream.Close()
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
func (tm *TrafficMonitor) sender(stream network.Stream, size int, workerID uint32) {
	defer tm.wg.Done()

	payload := make([]byte, size)
	var seq uint64

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
		seq++
		writeTracePayload(payload, tm.senderID, workerID, seq)
		targetConnectionId := tm.targetConnectionId
		if targetConnectionId == "" {
			targetConnectionId = stream.ConnectionId()
		}
		msg := &network.Message{
			Header: &network.Header{
				ConnectionId: targetConnectionId,
				NodeId:       stream.NodeId(),
			},
			Payload: append([]byte(nil), payload...),
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
		tm.recordTrace(msg.Payload)
		atomic.AddInt64(&tm.RxBytes, int64(len(msg.Payload)+network.HeaderLength))
		atomic.AddInt64(&tm.RxPackets, 1)
	}
}

func (tm *TrafficMonitor) recordTrace(payload []byte) {
	key, ok := parseTracePayload(payload)
	tm.traceMu.Lock()
	defer tm.traceMu.Unlock()
	if !ok {
		tm.parseFailures++
		return
	}
	if tm.seenTrace == nil {
		tm.seenTrace = make(map[tracePacketKey]int)
	}
	if tm.streamTraceStats == nil {
		tm.streamTraceStats = make(map[traceStreamKey]*traceStreamStats)
	}
	tm.seenTrace[key]++
	if tm.seenTrace[key] == 2 && len(tm.duplicateSamples) < 10 {
		tm.duplicateSamples = append(tm.duplicateSamples, key)
	}
	streamKey := traceStreamKey{senderID: key.senderID, workerID: key.workerID}
	stats := tm.streamTraceStats[streamKey]
	if stats == nil {
		stats = &traceStreamStats{}
		tm.streamTraceStats[streamKey] = stats
	}
	stats.count++
	if key.seq > stats.maxSeq {
		stats.maxSeq = key.seq
	}
}

func (tm *TrafficMonitor) traceSnapshot() (unique int, duplicates int, parseFailures int, streams map[traceStreamKey]traceStreamStats, samples []tracePacketKey) {
	tm.traceMu.Lock()
	defer tm.traceMu.Unlock()
	streams = make(map[traceStreamKey]traceStreamStats, len(tm.streamTraceStats))
	for key, stats := range tm.streamTraceStats {
		streams[key] = *stats
	}
	for _, count := range tm.seenTrace {
		if count > 0 {
			unique++
		}
		if count > 1 {
			duplicates += count - 1
		}
	}
	samples = append(samples, tm.duplicateSamples...)
	return unique, duplicates, tm.parseFailures, streams, samples
}

func (tm *TrafficMonitor) printReport() {
	fmt.Println("\n\n📊 --- 测试完成 ---")
	fmt.Printf("🏆 峰值上传: %s/s\n", formatBytes(atomic.LoadInt64(&tm.PeakTxSpeed)))
	fmt.Printf("🏆 峰值下载: %s/s\n", formatBytes(atomic.LoadInt64(&tm.PeakRxSpeed)))

	fmt.Printf("📈 总上传: %s (%d 个包)\n", formatBytes(atomic.LoadInt64(&tm.TotalTxBytes)), atomic.LoadInt64(&tm.TotalTxPackets))
	fmt.Printf("📈 总下载: %s (%d 个包)\n", formatBytes(atomic.LoadInt64(&tm.TotalRxBytes)), atomic.LoadInt64(&tm.TotalRxPackets))

	unique, duplicates, parseFailures, streams, samples := tm.traceSnapshot()
	fmt.Printf("🔎 Trace: unique_rx=%d duplicate_rx=%d parse_failures=%d sender_id=%016x\n", unique, duplicates, parseFailures, tm.senderID)
	keys := make([]traceStreamKey, 0, len(streams))
	for key := range streams {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].senderID == keys[j].senderID {
			return keys[i].workerID < keys[j].workerID
		}
		return keys[i].senderID < keys[j].senderID
	})
	for _, key := range keys {
		stats := streams[key]
		missing := int64(stats.maxSeq) - int64(stats.count)
		if missing < 0 {
			missing = 0
		}
		fmt.Printf("🔎 Trace stream sender=%016x worker=%d unique=%d max_seq=%d missing_est=%d\n", key.senderID, key.workerID, stats.count, stats.maxSeq, missing)
	}
	for i, sample := range samples {
		fmt.Printf("🔎 Duplicate sample[%d]: sender=%016x worker=%d seq=%d\n", i, sample.senderID, sample.workerID, sample.seq)
	}
}

func traceSenderID(nodeID string) uint64 {
	hash := sha256.Sum256([]byte(nodeID))
	return binary.BigEndian.Uint64(hash[:8])
}

func writeTracePayload(payload []byte, senderID uint64, workerID uint32, seq uint64) {
	if len(payload) < traceHeaderLength {
		return
	}
	copy(payload[:8], traceMagic[:])
	binary.BigEndian.PutUint64(payload[8:16], senderID)
	binary.BigEndian.PutUint32(payload[16:20], workerID)
	binary.BigEndian.PutUint64(payload[20:28], seq)
	binary.BigEndian.PutUint32(payload[28:32], uint32(len(payload)))
}

func parseTracePayload(payload []byte) (tracePacketKey, bool) {
	if len(payload) < traceHeaderLength || string(payload[:8]) != string(traceMagic[:]) {
		return tracePacketKey{}, false
	}
	declaredSize := binary.BigEndian.Uint32(payload[28:32])
	if declaredSize != uint32(len(payload)) {
		return tracePacketKey{}, false
	}
	return tracePacketKey{
		senderID: binary.BigEndian.Uint64(payload[8:16]),
		workerID: binary.BigEndian.Uint32(payload[16:20]),
		seq:      binary.BigEndian.Uint64(payload[20:28]),
	}, true
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
