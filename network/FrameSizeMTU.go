package network

import (
	"bnfs_p2p/logx"
	"net"
)

// GetOptimalMaxFrameSize 根据网卡MTU计算最优的最大帧大小
// 考虑IP头、TCP头、TLS开销，返回安全的payload上限
func GetOptimalMaxFrameSize(conn net.Conn) int {
	// 默认值：保守的1400字节
	defaultMax := 1400

	// 尝试获取本地地址对应的网卡MTU
	localAddr := conn.LocalAddr()
	if localAddr == nil {
		logx.Debugf("[FrameSize] 无法获取本地地址，使用默认上限: %d", defaultMax)
		return defaultMax
	}

	// 解析IP地址
	tcpAddr, ok := localAddr.(*net.TCPAddr)
	if !ok {
		logx.Debugf("[FrameSize] 非TCP连接，使用默认上限: %d", defaultMax)
		return defaultMax
	}

	// 查找对应的网卡
	ifaces, err := net.Interfaces()
	if err != nil {
		logx.Debugf("[FrameSize] 获取网卡列表失败: %v，使用默认上限: %d", err, defaultMax)
		return defaultMax
	}

	// 遍历所有网卡，找到匹配的IP
	var mtu int
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// 检查IP是否匹配
			if ipNet.IP.Equal(tcpAddr.IP) {
				mtu = iface.MTU
				logx.Debugf("[FrameSize] 找到匹配网卡: %s, MTU: %d", iface.Name, mtu)
				break
			}
		}

		if mtu > 0 {
			break
		}
	}

	// 如果没找到匹配的网卡，使用默认值
	if mtu == 0 {
		logx.Debugf("[FrameSize] 未找到匹配网卡，使用默认上限: %d", defaultMax)
		return defaultMax
	}

	// 计算安全的最大帧大小（不再使用任何"验证最优值"硬编码）。
	//
	// 标准最优 = MTU 扣除各层协议开销后的可用 payload 上限：
	//   TCP payload = MTU - IP头 - TCP头        （MTU 已是 IP 层大小，不含以太网头）
	//   可用应用层 = TCP payload - TLS开销 - 我们的Frame头 - 帧头携带的 connectionId
	// 然后统一在「标准最优」基础上留 10% 安全余量（应对路径 MTU 抖动、TLS/TCP 选项浮动等）：
	//   标准多大，最优就是「标准最优」的 90%。
	const (
		ipHeader    = 20 // IP头（IPv4，IPv6为40）
		tcpHeader   = 32 // TCP头（含常见选项）
		tlsOverhead = 32 // TLS Record头(5) + Tag(16) + 预留(11)
		// connIdBytes：帧头之外还携带业务 connectionId（UUID ~36B；FrameHeaderLength 仅含其 2B 长度前缀）。
		connIdBytes = 40
	)

	// 标准最优：MTU 扣除全部协议开销后的可用 payload。
	standardOptimal := mtu - ipHeader - tcpHeader - tlsOverhead - FrameHeaderLength - connIdBytes
	// 留 10% 安全余量。
	optimal := standardOptimal - standardOptimal/10

	if optimal < 800 {
		logx.Debugf("[FrameSize] MTU(%d) 标准最优=%d 过小，使用最小值800", mtu, standardOptimal)
		return 800
	}
	// 上限保护：避免 Jumbo Frame 下单帧过大。
	if optimal > 8192 {
		logx.Debugf("[FrameSize] MTU(%d) 标准最优=%d 减10%%=%d，限制为8192", mtu, standardOptimal, optimal)
		return 8192
	}

	logx.Debugf("[FrameSize] MTU(%d) 标准最优=%d，减10%%安全余量 → 最优帧大小=%d", mtu, standardOptimal, optimal)
	return optimal
}

// DetectMaxFrameSize 自动探测最优最大帧大小
// 如果无法获取MTU，返回保守的默认值
func DetectMaxFrameSize(conn net.Conn) int {
	if conn == nil {
		return 1400 // 无连接时的默认值
	}
	return GetOptimalMaxFrameSize(conn)
}
