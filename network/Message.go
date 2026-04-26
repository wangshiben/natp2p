package network

import (
	"encoding/binary"
	"errors"
	"log"
	"strings"
)

type Header struct {
	RouteName     string `json:"route_name"`
	NodeId        string `json:"node_id"`         // 请求的节点 ID (SHA256 Hex 格式)，当请求的ConnectionId为""时，表示
	NodeIdVersion uint8  `json:"node_id_version"` // 节点 ID 的版本号
	PayLoadLength uint   `json:"pay_load_length"`
	ConnectionId  string `json:"connection_id"` // 计划使用uuid :
	OriginData    []byte `json:"origin_data"`
}
type Message struct {
	Header  *Header `json:"header"`
	Payload []byte  `json:"payload"`
}

const MagicHeader = "bnfs-data"
const HeaderLength = 254
const (
	version1           = 1
	NodeIdHexLength    = 64 // SHA256 Hex 字符串长度为 64
	ConnectionIdLength = 36 //ConnectionId 长度
)

var MagicHeaderBytes = []byte(MagicHeader)

// ParseHeader 解析头部
// new:  [MagicHeader(9 bytes)]+ [NodeId version 1 bytes] + [node ID (64 bytes)]+[RouteNameLength(8 bytes, LittleEndian)] + [RouteName] + [PayloadLength(8 bytes, LittleEndian)]+[ConnectionId(36)] + [Padding zeros]
func ParseHeader(headerBytes []byte) (*Header, error) {
	index := 0

	// 1. 验证魔数
	for ; index < len(MagicHeaderBytes); index++ {
		if headerBytes[index] != MagicHeaderBytes[index] {
			return nil, errors.New("invalid header")
		}
	}

	// 2. 读取 NodeId Version (1 byte)
	if index >= len(headerBytes) {
		return nil, errors.New("invalid header: missing node id version")
	}
	nodeIdVersion := headerBytes[index]
	index++

	// 3. 读取 Node ID (固定长度，由 version 决定，当前版本为 64 字节 Hex 字符串)
	nodeIdLen := 0
	switch nodeIdVersion {
	case 1:
		nodeIdLen = NodeIdHexLength
	default:
		return nil, errors.New("unsupported node id version")
	}

	if index+nodeIdLen > len(headerBytes) {
		return nil, errors.New("invalid header: missing node id")
	}
	// 读取并去除末尾填充的 \x00
	nodeId := strings.TrimRight(string(headerBytes[index:index+nodeIdLen]), "\x00")
	index += nodeIdLen

	// 4. 读取路由名长度 (8 bytes, LittleEndian)
	RouteNameLength := make([]byte, 8)
	currentIndex := index
	for ; index < (8 + currentIndex); index++ {
		RouteNameLength[index-currentIndex] = headerBytes[index]
	}
	nameLength := parseBytesToInt64(RouteNameLength)

	// 5. 读取路由名
	// 检查边界：总长度 - 当前索引 - 负载长度字段 (8) - ConnectionId 字段 (36)
	if int(nameLength) < 0 || int(nameLength) > (HeaderLength-index-8-ConnectionIdLength) {
		return nil, errors.New("invalid header")
	}
	RouteName := string(headerBytes[index : index+int(nameLength)])
	index += int(nameLength)

	// 6. 读取负载长度 (8 bytes, LittleEndian)
	PayLoadLengthBytes := make([]byte, 8)
	currentIndex = index
	for ; index < (8 + currentIndex); index++ {
		PayLoadLengthBytes[index-currentIndex] = headerBytes[index]
	}
	payloadLength := parseBytesToInt64(PayLoadLengthBytes)

	// 7. 读取 ConnectionId (36 bytes)
	if index+ConnectionIdLength > len(headerBytes) {
		return nil, errors.New("invalid header: missing connection id")
	}
	connectionId := strings.TrimRight(string(headerBytes[index:index+ConnectionIdLength]), "\x00")
	index += ConnectionIdLength

	return &Header{
		RouteName:     RouteName,
		NodeId:        nodeId,
		NodeIdVersion: nodeIdVersion,
		PayLoadLength: payloadLength,
		ConnectionId:  connectionId,
		//OriginData:    headerBytes[:],
	}, nil
}

func parseBytesToInt64(data []byte) uint {
	res := binary.LittleEndian.Uint64(data)
	return uint(res)
}

// ParseToBytes 将路由名和负载长度序列化为符合协议定义的 512 字节头部
// 结构：[MagicHeader(9 bytes)]+ [NodeId version 1 bytes] + [node ID (64 bytes)]+[RouteNameLength(8 bytes, LittleEndian)] + [RouteName] + [PayloadLength(8 bytes, LittleEndian)]+[ConnectionId(36)] + [Padding zeros]
func (h *Header) ParseToBytes() ([]byte, error) {
	routeName := h.RouteName
	payloadLength := h.PayLoadLength
	headerBytes := make([]byte, HeaderLength)

	// 1. 写入魔数
	if len(MagicHeaderBytes) > HeaderLength {
		return nil, errors.New("magic header too large")
	}
	copy(headerBytes, MagicHeaderBytes)

	currentIndex := len(MagicHeaderBytes)

	// 2. 写入 NodeId Version (固定为 1)
	headerBytes[currentIndex] = 1
	currentIndex++

	// 3. 写入 Node ID (固定 64 字节，对应 SHA256 Hex 字符串)
	// 检查长度，如果不足 64 字节，右侧补 0；如果超过，截断
	nodeIdBytes := make([]byte, NodeIdHexLength)
	copy(nodeIdBytes, []byte(h.NodeId))

	if currentIndex+len(nodeIdBytes) > HeaderLength {
		return nil, errors.New("header size overflow while writing node id")
	}
	copy(headerBytes[currentIndex:], nodeIdBytes)
	currentIndex += len(nodeIdBytes)

	// 4. 检查路由名长度是否合法
	// 最大可用长度 = 总长度 - 魔数 - 版本 (1) - NodeID (64) - 路由名长度字段 (8) - 负载长度字段 (8) - ConnectionId (36)
	maxNameLength := HeaderLength - currentIndex - 8 - 8 - ConnectionIdLength
	if len(routeName) > maxNameLength {
		return nil, errors.New("route name too long")
	}

	// 5. 写入路由名长度 (8 bytes, LittleEndian)
	nameLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nameLenBytes, uint64(len(routeName)))
	copy(headerBytes[currentIndex:], nameLenBytes)
	currentIndex += 8

	// 6. 写入路由名
	copy(headerBytes[currentIndex:], routeName)
	currentIndex += len(routeName)

	// 7. 写入负载长度 (8 bytes, LittleEndian)
	payloadLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(payloadLenBytes, uint64(payloadLength))
	copy(headerBytes[currentIndex:], payloadLenBytes)
	currentIndex += 8

	// 8. 写入 ConnectionId (36 bytes)
	// 检查长度，如果不足 36 字节，右侧补 0；如果超过，截断
	connectionIdBytes := make([]byte, ConnectionIdLength)
	copy(connectionIdBytes, []byte(h.ConnectionId))

	if currentIndex+len(connectionIdBytes) > HeaderLength {
		return nil, errors.New("header size overflow while writing connection id")
	}
	copy(headerBytes[currentIndex:], connectionIdBytes)
	// 剩余部分默认为 0，无需额外操作

	return headerBytes, nil
}

func (m *Message) ParseToBytes() ([]byte, error) {
	m.Header.PayLoadLength = uint(len(m.Payload))
	defer func() {
		err := recover()
		if err != nil {
			log.Println("ERROR:" + err.(string))
			panic(err)
		}
	}()
	headerBytes, err := m.Header.ParseToBytes()
	if err != nil {
		return nil, err
	}
	return append(headerBytes, m.Payload...), nil
}
func ParseMessage(messageBytes []byte) (*Message, error) {
	header, err := ParseHeader(messageBytes[:HeaderLength])
	if err != nil {
		return nil, err
	}
	return &Message{
		Header:  header,
		Payload: messageBytes[HeaderLength:],
	}, nil
}
