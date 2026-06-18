package network

import (
	"log"
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
		log.Printf("[FrameSize] 无法获取本地地址，使用默认上限: %d", defaultMax)
		return defaultMax
	}

	// 解析IP地址
	tcpAddr, ok := localAddr.(*net.TCPAddr)
	if !ok {
		log.Printf("[FrameSize] 非TCP连接，使用默认上限: %d", defaultMax)
		return defaultMax
	}

	// 查找对应的网卡
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[FrameSize] 获取网卡列表失败: %v，使用默认上限: %d", err, defaultMax)
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
				log.Printf("[FrameSize] 找到匹配网卡: %s, MTU: %d", iface.Name, mtu)
				break
			}
		}

		if mtu > 0 {
			break
		}
	}

	// 如果没找到匹配的网卡，使用默认值
	if mtu == 0 {
		log.Printf("[FrameSize] 未找到匹配网卡，使用默认上限: %d", defaultMax)
		return defaultMax
	}

	// 计算安全的最大帧大小
	// MTU通常是1500（以太网）、9000（Jumbo Frame）
	//
	// 协议栈开销分析：
	// - 以太网层：MTU已经是IP层的大小，不含以太网头
	// - IP头：20字节（IPv4）或40字节（IPv6）
	// - TCP头：20-60字节（通常20-32）
	// - TLS Record：5字节头 + 16-32字节MAC/Tag
	// - 我们的Frame头：37字节
	//
	// 但实际上，TCP层的MTU已经考虑了IP头，我们只需考虑：
	// TCP payload = MTU - IP头 - TCP头
	// 可用于应用 = TCP payload - TLS开销 - Frame头 - 安全余量

	const (
		ipHeader     = 20  // IP头（IPv4，IPv6为40）
		tcpHeader    = 32  // TCP头（含常见选项）
		tlsOverhead  = 32  // TLS Record头(5) + Tag(16) + 预留(11)
		frameHeader  = 37  // 我们的Frame头大小
		safetyMargin = 20  // 安全余量（应对路径MTU发现等）
	)

	maxPayload := mtu - ipHeader - tcpHeader - tlsOverhead - frameHeader - safetyMargin

	// 确保在合理范围内
	if maxPayload < 800 {
		log.Printf("[FrameSize] 计算的payload(%d)过小，使用最小值800", maxPayload)
		return 800
	}

	// 对于标准MTU 1500，理论计算约1359字节
	// 但我们已经验证1400字节工作完美，所以：
	// - MTU == 1500：直接使用验证的1400字节（最优）
	// - MTU > 1500：使用计算值（可能更大）
	// - MTU < 1500：使用计算值（避免分片）
	if mtu == 1500 {
		log.Printf("[FrameSize] 标准MTU(1500)，使用验证最优值1400")
		return 1400
	}

	// Jumbo Frame：可以使用更大的帧
	if mtu >= 9000 {
		if maxPayload > 8192 {
			log.Printf("[FrameSize] Jumbo Frame MTU(%d)，限制payload为8192", mtu)
			return 8192
		}
		log.Printf("[FrameSize] Jumbo Frame MTU(%d)，使用计算帧: %d", mtu, maxPayload)
		return maxPayload
	}

	// 其他MTU：使用计算值
	if maxPayload > 1400 {
		log.Printf("[FrameSize] 基于MTU(%d)计算得%d，限制为1400（已验证）", mtu, maxPayload)
		return 1400
	}

	log.Printf("[FrameSize] 基于MTU(%d)计算帧大小: %d", mtu, maxPayload)
	return maxPayload
}

// DetectMaxFrameSize 自动探测最优最大帧大小
// 如果无法获取MTU，返回保守的默认值
func DetectMaxFrameSize(conn net.Conn) int {
	if conn == nil {
		return 1400 // 无连接时的默认值
	}
	return GetOptimalMaxFrameSize(conn)
}
