package main

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// migrateRoute 是 callee→client 的"迁移指令"消息的 RouteName；payload 为新的专用 identity nodeId。
const migrateRoute = "/test/migrate"

// Server 启动中转 relay，并装 ForwardHook：每累计 hookThreshold 字节调用一次，
// 打印累计 ForwardStats + 该批最后一帧的 connectionId（用于证明共享 group 与各重流专用 group 都被统计）。
func Server(listenAddr string, hookThreshold int64) {
	starter := networkFrameWork.NewRelayStarter(listenAddr)
	var totalFwd int64
	cfg := &networkFrameWork.ForwardHookConfig{
		ThresholdBytes: hookThreshold,
		Hook: func(ctx context.Context, stats *networkFrameWork.ForwardStats) error {
			t := atomic.AddInt64(&totalFwd, stats.TotalBytes)
			connId := ""
			if stats.LastFrame != nil {
				connId = stats.LastFrame.ConnectionId
			}
			fmt.Printf("[ForwardHook] +%s (%d 帧) connId=%s | server端累计转发=%s\n",
				formatBytes(stats.TotalBytes), stats.TotalFrames, connId, formatBytes(t))
			return nil
		},
		ErrorHook: func(ctx context.Context, info *networkFrameWork.ForwardErrorInfo) {
			fmt.Printf("[ForwardHook][ERR] dir=%s err=%v\n", info.Direction, info.Err)
		},
	}
	starter.Cover().SetForwardHook(cfg)
	fmt.Printf("ForwardHook 已装: 每 %s 累计上报一次\n", formatBytes(hookThreshold))
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
	durationSec := flag.Int("duration", 300, "压测时长(秒)")
	floodDelaySec := flag.Int("floodDelay", 3, "client 建连后延迟多少秒再开始满发(给各流先在共享连接上握手, 避免握手期 HOL)")
	elephantMB := flag.Int("elephantMB", 2, "callee 侧大象流判定阈值(MB): 某共享流累计收到超过此值即迁到独立连接")
	hookThresholdKB := flag.Int("hookThresholdKB", 512, "relay ForwardHook 每累计多少 KB 上报一次")
	flag.Parse()
	duration := time.Duration(*durationSec) * time.Second
	floodDelay := time.Duration(*floodDelaySec) * time.Second
	fmt.Printf("mode: %s, address: %s, targetId: %s, size: %d, duration: %s, floodDelay: %s, elephantMB: %d\n",
		*mode, *address, *targetId, *size, duration, floodDelay, *elephantMB)
	switch *mode {
	case "relayServer":
		fmt.Println("Starting relay server...")
		server, done := RelayServer(*address, *size, duration, floodDelay, int64(*elephantMB)*1024*1024)
		hash := sha256.Sum256([]byte(server))
		originalNodeId := hex.EncodeToString(hash[:])
		fmt.Println(originalNodeId)
		<-done
	case "client":
		// 单端发起：client 进程标记为 follower —— 不主动发起帧大小变更，
		// 由 server 端掌控帧大小（见 TcpStream.frameSizeFollowerProcess）。
		os.Setenv("BNFS_FRAME_FOLLOWER", "1")
		RelayClient(*address, *targetId, *size, duration, floodDelay)
	case "server":
		Server(*address, int64(*hookThresholdKB)*1024)
	}
}

// RelayClient 连接 relay 并压测；收到 callee 的迁移指令后重连到指定的专用 identity 继续压测。
// 这就是"运行时大象流检测 + 重连迁移"里的 client 侧：先在共享连接上跑，被判为大象后迁到独立连接。
func RelayClient(relayAddress, targetId string, size int, duration time.Duration, floodDelay time.Duration) {
	deadline := time.Now().Add(duration)
	for {
		remaining := time.Until(deadline)
		if remaining <= 2*time.Second {
			return
		}
		pair, err := crypoto.MakeKeyPair()
		if err != nil {
			panic(err)
		}
		streamClient, connectionId, err := client.ConnectNodeWithTargetRelay(targetId, relayAddress, pair)
		if err != nil {
			panic(err)
		}
		fmt.Printf("relay connect success connectionID: %s target=%.16s\n", connectionId, targetId)
		keyStr := crypoto.GetPubKeyStr(pair.PublicKey())
		sum256 := sha256.Sum256([]byte(keyStr))
		t := &TrafficMonitor{
			stopCh:             make(chan struct{}),
			nodeId:             hex.EncodeToString(sum256[:]),
			targetConnectionId: connectionId,
			migrateCh:          make(chan string, 1),
		}
		t.Start(streamClient, size, remaining, floodDelay)

		select {
		case newTarget := <-t.migrateCh:
			fmt.Printf("📦 收到迁移指令 → 重连到专用 identity %.16s\n", newTarget)
			targetId = newTarget
			floodDelay = 0 // 已是专用连接, 重连后立即满发
			continue
		default:
			return // 正常到时结束
		}
	}
}

// RelayServer 注册成可被中继的节点（server 端）。
//
// n‑v‑1‑v‑1：server↔relay 维持一条连接，上面承载多个 client。用 EndpointFrameMux 按帧头
// connectionId 把这条连接帧级 demux：每见到一个新 connectionId，就 spawn 一个 goroutine 处理
// 该逻辑连接——在它各自的 muxConn 上跑一条正常 TcpStream（独立 assembler/crypto/帧大小自适应），
// 读首帧 hello 推导对端 nodeId、做各自的 TLS 握手、再跑流量测试。server 进程不设
// BNFS_FRAME_FOLLOWER，故每条逻辑连接都是帧大小发起方（server 端掌控帧大小）。
func RelayServer(addr string, size int, duration time.Duration, floodDelay time.Duration, elephantBytes int64) (string, <-chan struct{}) {
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

	serverNodeId := func() string {
		s := sha256.Sum256([]byte(crypoto.GetPubKeyStr(pair.PublicKey())))
		return hex.EncodeToString(s[:])
	}()

	mux, err := networkFrameWork.NewEndpointFrameMux(stream, func(connId string, conn net.Conn) {
		go serveMuxConn(serverNodeId, connId, conn, pair, size, duration, addr, floodDelay, elephantBytes)
	})
	if err != nil {
		panic(err)
	}
	mux.Start()
	fmt.Println("EndpointFrameMux started, waiting for client connections...")

	go func() {
		defer close(done)
		// 给最后接入的 client 留够完整时长 + 余量，再收尾。
		time.Sleep(duration + 30*time.Second)
		mux.Close()
	}()
	return keyStr, done
}

// serveMuxConn 处理共享连接上的一条逻辑连接（一个轻流候选）：在其专属 muxConn 上跑正常 TcpStream，
// 读首帧 hello、独立 TLS、跑流量测试；同时起大象检测——本流累计入站超阈值即注册独立 identity、
// 发迁移指令让 client 重连到独立连接，并停掉这条共享流（重流迁出，轻流留在共享连接，消除 HOL）。
func serveMuxConn(serverNodeId, connId string, conn net.Conn, pair *ecdh.PrivateKey, size int, duration time.Duration, relayAddr string, floodDelay time.Duration, elephantBytes int64) {
	sub := networkFrameWork.NewTCPStream("", connId, conn)
	ctx := context.Background()
	message, err := sub.NextMessage(ctx)
	if err != nil {
		fmt.Printf("[server] connId=%s 读 hello 失败: %v\n", connId, err)
		return
	}
	hash := sha256.Sum256(message.Payload)
	clientNodeId := hex.EncodeToString(hash[:])
	sub.SetIdentity(clientNodeId, connId)
	fmt.Printf("[server] connId=%s hello 收到, clientNodeId=%.16s, 开始 TLS 握手\n", connId, clientNodeId)

	streamClient := client.NewStreamClient(sub)
	crypto, err := crypoto.NewTLSCrypto(streamClient, pair)
	if err != nil {
		fmt.Printf("[server] connId=%s TLS 握手失败: %v\n", connId, err)
		return
	}
	streamClient.SetCryptoSuite(crypto)
	fmt.Printf("[server][共享] connId=%s TLS 握手完成, 开始流量测试 + 大象检测\n", connId)

	t := &TrafficMonitor{
		stopCh:             make(chan struct{}),
		nodeId:             serverNodeId,
		targetConnectionId: connId,
	}

	// 大象检测：本共享流累计入站(client→server)超过 elephantBytes 即判为大象，
	// 注册独立 identity、发迁移指令、停掉这条共享流（迁到独立连接）。
	go detectElephantAndMigrate(t, streamClient, connId, relayAddr, size, duration, elephantBytes)

	t.Start(streamClient, size, duration, floodDelay)
}

// detectElephantAndMigrate 周期采样共享流的累计入站字节；越过 elephantBytes 即触发迁移。
func detectElephantAndMigrate(t *TrafficMonitor, sc network.Stream, connId, relayAddr string, size int, duration time.Duration, elephantBytes int64) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			if atomic.LoadInt64(&t.TotalRxBytes) < elephantBytes {
				continue
			}
			// 判为大象：注册独立 identity（独立 group, 不碰 relay）→ 起 1:1 终结 handler 等迁入。
			dedicatedNodeId := runDedicatedHeavy(relayAddr, size, duration)
			fmt.Printf("🐘 [server] connId=%s 判为大象(累计入站=%s) → 迁到独立 identity %.16s\n",
				connId, formatBytes(atomic.LoadInt64(&t.TotalRxBytes)), dedicatedNodeId)
			// 发迁移指令（reliable）：client 收到后重连到该独立 identity。
			migrateMsg := &network.Message{
				Header:  &network.Header{ConnectionId: connId, NodeId: sc.NodeId(), RouteName: migrateRoute},
				Payload: []byte(dedicatedNodeId),
			}
			if err := sc.SendMessage(context.Background(), migrateMsg); err != nil {
				fmt.Printf("[server] connId=%s 发迁移指令失败: %v\n", connId, err)
			}
			// 停掉这条共享流（client 会在独立连接上重连）。
			t.stopMonitor(sc)
			return
		}
	}
}

// runDedicatedHeavy 用一个全新 identity 注册到 relay（relay 自然新建独立 StreamGroup → 带宽隔离，
// 且该 group 自动挂同一份 ForwardHook → 重流被统计），并起一个原始 1:1 终结 handler 等待迁入的重流。
// 返回该独立 identity 的 nodeId（供发给 client 重连）。
func runDedicatedHeavy(relayAddr string, size int, duration time.Duration) string {
	pair, err := crypoto.MakeKeyPair()
	if err != nil {
		panic(err)
	}
	keyStr := crypoto.GetPubKeyStr(pair.PublicKey())
	stream, err := networkFrameWork.TryRegisterRelayStream(keyStr, relayAddr)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256([]byte(keyStr))
	dedicatedNodeId := hex.EncodeToString(hash[:])

	go func() {
		message, err := stream.NextMessage(context.Background())
		if err != nil {
			fmt.Printf("[server][独连 %.16s] 读 hello 失败: %v\n", dedicatedNodeId, err)
			return
		}
		h := sha256.Sum256(message.Payload)
		clientNodeId := hex.EncodeToString(h[:])
		if !networkFrameWork.SetStreamIdentity(stream, clientNodeId, message.Header.ConnectionId) {
			fmt.Printf("[server][独连 %.16s] SetStreamIdentity 失败\n", dedicatedNodeId)
			return
		}
		sc := client.NewStreamClient(stream)
		crypto, err := crypoto.NewTLSCrypto(sc, pair)
		if err != nil {
			fmt.Printf("[server][独连 %.16s] TLS 握手失败: %v\n", dedicatedNodeId, err)
			return
		}
		sc.SetCryptoSuite(crypto)
		fmt.Printf("[server][独连 %.16s] 重流迁入完成, 独立连接开始压测\n", dedicatedNodeId)
		t := &TrafficMonitor{
			stopCh:             make(chan struct{}),
			nodeId:             clientNodeId,
			targetConnectionId: message.Header.ConnectionId,
		}
		t.Start(sc, size, duration, 0)
	}()
	return dedicatedNodeId
}

// TrafficMonitor 流量监控器
const (
	senderWorkers     = 32 // 异步流水线模式：增加到32个worker以充分利用带宽
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

	// stopOnce 保证 stopMonitor 只关一次（到时 / 迁移 可能并发触发）。
	stopOnce sync.Once

	// migrateCh 仅 client 侧用：receiver 收到 callee 的迁移指令时把新 identity nodeId 投进来，
	// RelayClient 据此重连到独立连接。callee 侧为 nil（不处理迁移指令）。
	migrateCh chan string

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

func (tm *TrafficMonitor) Start(stream network.Stream, packetSize int, duration time.Duration, floodDelay time.Duration) {
	tm.stopCh = make(chan struct{})
	tm.senderID = traceSenderID(tm.nodeId)
	tm.seenTrace = make(map[tracePacketKey]int)
	tm.streamTraceStats = make(map[traceStreamKey]*traceStreamStats)
	tm.wg.Add(senderWorkers + 2)
	for i := 0; i < senderWorkers; i++ {
		go tm.sender(stream, packetSize, uint32(i), floodDelay)
	}
	go tm.receiver(stream)
	go tm.monitor()

	go func() {
		select {
		case <-time.After(duration):
			fmt.Println("\n⏰ 测试时间到，正在关闭...")
			tm.stopMonitor(stream)
		case <-tm.stopCh:
			// 已被迁移/外部停掉
		}
	}()

	fmt.Printf("🚀 测试开始... sender workers=%d (floodDelay=%s)\n", senderWorkers, floodDelay)
	tm.Wait()
}

// stopMonitor 停掉本监控器（关 stopCh + 关流），只执行一次。到时与迁移都走它。
func (tm *TrafficMonitor) stopMonitor(stream network.Stream) {
	tm.stopOnce.Do(func() {
		close(tm.stopCh)
		if stream != nil {
			_ = stream.Close()
		}
	})
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

// sender 使用同步发送，通过增加worker数量来提升并发度。
// 32个worker可以同时阻塞等待ACK，形成流水线效果。
func (tm *TrafficMonitor) sender(stream network.Stream, size int, workerID uint32, floodDelay time.Duration) {
	defer tm.wg.Done()

	payload := make([]byte, size)
	var seq uint64

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-tm.stopCh
		cancel()
	}()

	// floodDelay：建连后先静默一段（给同一共享连接上的其它流先完成握手，避免握手期被满发 HOL），
	// 之后再开始满发。期间响应 stopCh 退出。
	if floodDelay > 0 {
		select {
		case <-tm.stopCh:
			return
		case <-time.After(floodDelay):
		}
	}

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

		// 使用同步发送（阻塞等待ACK）
		// 通过32个worker并发，每个worker阻塞时其他worker继续发送
		if err := stream.SendMessage(ctx, msg); err != nil {
			if ctx.Err() != nil {
				// context取消是正常退出
				return
			}
			fmt.Printf("\n❌ Worker %d 发送失败: %v\n", workerID, err)
			return
		}

		// 只统计成功发送的消息
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
		// 迁移指令（仅 client 侧 migrateCh 非 nil 时处理）：callee 判本流为大象，要求重连到独立连接。
		if tm.migrateCh != nil && msg.Header != nil && msg.Header.RouteName == migrateRoute {
			newTarget := string(msg.Payload)
			select {
			case tm.migrateCh <- newTarget:
			default:
			}
			tm.stopMonitor(stream)
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
