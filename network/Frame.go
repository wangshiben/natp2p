package network

import (
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

// Frame 是 Message 在传输层被切分后的最小单元。
//
// 一个 Message 会被拆分成多个 Frame，每个 Frame 携带相同的 MessageId 用于在接收端重组。
// SeqId 表示该 Frame 在所属 Message 内的序号(从 0 开始)；TotalFrames 是该 Message 被拆成的总帧数。
// AckId 用于确认报文：携带它的 Frame 表示对方收到了 AckId 这一条 Frame(或 Message)，
// 具体语义由 FrameType 决定。
//
// 帧大小后期需要支持动态调整，故 PayloadLen 用 uint32 描述实际负载长度，
// 切分逻辑遵守 SplitToFrames 中传入的 maxPayload 参数。
type Frame struct {
	MessageId   uint64
	SeqId       uint32
	TotalFrames uint32
	AckId       uint64
	FrameType   uint8
	Payload     []byte
}

const (
	FrameTypeData           uint8 = 0
	FrameTypeAck            uint8 = 1
	FrameTypeRetransmit     uint8 = 2
	FrameTypeFrameSizeChange uint8 = 3 // 帧大小变更控制帧
)

// FrameMagic 区分 Frame 与裸 Message Header，避免误解析。
const FrameMagic = "bnfs-frm"

const (
	frameMagicLength       = len(FrameMagic) // 8
	frameMessageIdLength   = 8
	frameSeqIdLength       = 4
	frameTotalFramesLength = 4
	frameAckIdLength       = 8
	frameTypeLength        = 1
	framePayloadLenLength  = 4
)

// FrameHeaderLength 是序列化后帧头的固定长度。
const FrameHeaderLength = frameMagicLength + frameMessageIdLength + frameSeqIdLength +
	frameTotalFramesLength + frameAckIdLength + frameTypeLength + framePayloadLenLength

// DefaultMaxFramePayload 是默认的单帧最大负载，向调用方暴露便于动态调整。
const DefaultMaxFramePayload = 1400

var frameMagicBytes = []byte(FrameMagic)

// ParseToBytes 序列化 Frame 为二进制。
//
// 结构: [Magic(8)] [MessageId(8 LE)] [SeqId(4 LE)] [TotalFrames(4 LE)]
//
//	[AckId(8 LE)] [FrameType(1)] [PayloadLen(4 LE)] [Payload(PayloadLen)]
func (f *Frame) ParseToBytes() ([]byte, error) {
	if uint64(len(f.Payload)) > uint64(^uint32(0)) {
		return nil, errors.New("frame payload too large")
	}
	buf := make([]byte, FrameHeaderLength+len(f.Payload))
	idx := 0

	copy(buf[idx:], frameMagicBytes)
	idx += frameMagicLength

	binary.LittleEndian.PutUint64(buf[idx:idx+frameMessageIdLength], f.MessageId)
	idx += frameMessageIdLength

	binary.LittleEndian.PutUint32(buf[idx:idx+frameSeqIdLength], f.SeqId)
	idx += frameSeqIdLength

	binary.LittleEndian.PutUint32(buf[idx:idx+frameTotalFramesLength], f.TotalFrames)
	idx += frameTotalFramesLength

	binary.LittleEndian.PutUint64(buf[idx:idx+frameAckIdLength], f.AckId)
	idx += frameAckIdLength

	buf[idx] = f.FrameType
	idx += frameTypeLength

	binary.LittleEndian.PutUint32(buf[idx:idx+framePayloadLenLength], uint32(len(f.Payload)))
	idx += framePayloadLenLength

	copy(buf[idx:], f.Payload)
	return buf, nil
}

// ParseFrame 从二进制反序列化为 Frame。
func ParseFrame(data []byte) (*Frame, error) {
	if len(data) < FrameHeaderLength {
		return nil, errors.New("frame too short")
	}
	idx := 0
	for i := 0; i < frameMagicLength; i++ {
		if data[idx+i] != frameMagicBytes[i] {
			return nil, errors.New("invalid frame magic")
		}
	}
	idx += frameMagicLength

	messageId := binary.LittleEndian.Uint64(data[idx : idx+frameMessageIdLength])
	idx += frameMessageIdLength

	seqId := binary.LittleEndian.Uint32(data[idx : idx+frameSeqIdLength])
	idx += frameSeqIdLength

	total := binary.LittleEndian.Uint32(data[idx : idx+frameTotalFramesLength])
	idx += frameTotalFramesLength

	ackId := binary.LittleEndian.Uint64(data[idx : idx+frameAckIdLength])
	idx += frameAckIdLength

	frameType := data[idx]
	idx += frameTypeLength

	payloadLen := binary.LittleEndian.Uint32(data[idx : idx+framePayloadLenLength])
	idx += framePayloadLenLength

	if len(data)-idx < int(payloadLen) {
		return nil, errors.New("frame payload truncated")
	}

	payload := make([]byte, payloadLen)
	copy(payload, data[idx:idx+int(payloadLen)])

	return &Frame{
		MessageId:   messageId,
		SeqId:       seqId,
		TotalFrames: total,
		AckId:       ackId,
		FrameType:   frameType,
		Payload:     payload,
	}, nil
}

// ReadFrame 从 io.Reader 读取一帧并反序列化。
// 先读固定长度的帧头以拿到 PayloadLen，再按需读取 Payload。
func ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, FrameHeaderLength)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	for i := 0; i < frameMagicLength; i++ {
		if header[i] != frameMagicBytes[i] {
			return nil, errors.New("invalid frame magic")
		}
	}
	payloadLen := binary.LittleEndian.Uint32(header[FrameHeaderLength-framePayloadLenLength : FrameHeaderLength])
	if payloadLen == 0 {
		return ParseFrame(header)
	}
	full := make([]byte, FrameHeaderLength+int(payloadLen))
	copy(full, header)
	if _, err := io.ReadFull(r, full[FrameHeaderLength:]); err != nil {
		return nil, err
	}
	return ParseFrame(full)
}

// AssembleFrames 将同一 MessageId 的全部数据帧拼回 Message。
//
// 调用方需保证传入帧均属于同一 MessageId、TotalFrames 一致、且数量等于 TotalFrames。
// 帧顺序无要求；函数内部按 SeqId 排序后再拼装。
func AssembleFrames(frames []*Frame) (*Message, error) {
	if len(frames) == 0 {
		return nil, errors.New("no frames provided")
	}

	first := frames[0]
	total := first.TotalFrames
	if int(total) != len(frames) {
		return nil, errors.New("frame count does not match TotalFrames")
	}

	sorted := make([]*Frame, len(frames))
	copy(sorted, frames)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].SeqId < sorted[j].SeqId })

	totalLen := 0
	for i, f := range sorted {
		if f.MessageId != first.MessageId {
			return nil, errors.New("frames belong to different messages")
		}
		if f.TotalFrames != total {
			return nil, errors.New("frames disagree on TotalFrames")
		}
		if f.SeqId != uint32(i) {
			return nil, errors.New("missing or duplicate frame sequence")
		}
		if f.FrameType != FrameTypeData && f.FrameType != FrameTypeRetransmit {
			return nil, errors.New("non-data frame in assembly set")
		}
		totalLen += len(f.Payload)
	}

	body := make([]byte, 0, totalLen)
	for _, f := range sorted {
		body = append(body, f.Payload...)
	}
	if len(body) < HeaderLength {
		return nil, errors.New("assembled payload smaller than message header")
	}
	return ParseMessage(body)
}

// FrameAssembler 用于流式接收时按 MessageId 缓存帧并触发重组。
//
// 收到的帧通过 Add 投递；当某个 MessageId 的所有帧到齐时，Add 返回完整 Message
// 并清理对应缓冲。重复帧(同 MessageId+SeqId)会被丢弃，不会触发错误，方便上层
// 在重发场景下盲转发。
type FrameAssembler struct {
	mu      sync.Mutex
	buffers map[uint64]*frameBuffer
}

type frameBuffer struct {
	total  uint32
	frames map[uint32]*Frame
}

// NewFrameAssembler 构造一个空的重组器。
func NewFrameAssembler() *FrameAssembler {
	return &FrameAssembler{buffers: make(map[uint64]*frameBuffer)}
}

// Add 添加一帧。若该 MessageId 的所有帧已到齐，返回拼装好的 Message；
// 否则返回 (nil, nil)。仅处理 Data/Retransmit 类型帧；其它类型由调用方自行处理。
func (a *FrameAssembler) Add(f *Frame) (*Message, error) {
	if f == nil {
		return nil, errors.New("nil frame")
	}
	if f.FrameType != FrameTypeData && f.FrameType != FrameTypeRetransmit {
		return nil, nil
	}
	if f.TotalFrames == 0 {
		return nil, errors.New("frame TotalFrames must be > 0")
	}
	if f.SeqId >= f.TotalFrames {
		return nil, errors.New("frame SeqId out of range")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	buf, ok := a.buffers[f.MessageId]
	if !ok {
		buf = &frameBuffer{total: f.TotalFrames, frames: make(map[uint32]*Frame, f.TotalFrames)}
		a.buffers[f.MessageId] = buf
	} else if buf.total != f.TotalFrames {
		return nil, errors.New("frames disagree on TotalFrames for same MessageId")
	}

	if _, dup := buf.frames[f.SeqId]; dup {
		return nil, nil
	}
	buf.frames[f.SeqId] = f

	if uint32(len(buf.frames)) != buf.total {
		return nil, nil
	}

	all := make([]*Frame, 0, buf.total)
	for _, ff := range buf.frames {
		all = append(all, ff)
	}
	delete(a.buffers, f.MessageId)

	return AssembleFrames(all)
}

// Drop 主动丢弃某个 MessageId 的缓冲，常用于超时清理。
func (a *FrameAssembler) Drop(messageId uint64) {
	a.mu.Lock()
	delete(a.buffers, messageId)
	a.mu.Unlock()
}

// Snapshot 返回指定 MessageId 当前已收到的连续区间。若没有相应缓冲返回 ok=false。
func (a *FrameAssembler) Snapshot(messageId uint64) ([]AckRange, uint32, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	buf, ok := a.buffers[messageId]
	if !ok {
		return nil, 0, false
	}
	seqs := make([]uint32, 0, len(buf.frames))
	for s := range buf.frames {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqsToRanges(seqs), buf.total, true
}

// AckRange 描述一段连续已收到的 SeqId 区间(闭区间 [Start, End])。
type AckRange struct {
	Start uint32
	End   uint32
}

const (
	ackRangeCountSize = 2
	ackRangeEntrySize = 8
)

// EncodeAckRanges 序列化为 [count(2 LE)] [s1(4 LE) e1(4 LE)] ... 结构。
func EncodeAckRanges(ranges []AckRange) ([]byte, error) {
	if len(ranges) > int(^uint16(0)) {
		return nil, errors.New("too many ack ranges")
	}
	buf := make([]byte, ackRangeCountSize+len(ranges)*ackRangeEntrySize)
	binary.LittleEndian.PutUint16(buf[0:ackRangeCountSize], uint16(len(ranges)))
	idx := ackRangeCountSize
	for _, r := range ranges {
		binary.LittleEndian.PutUint32(buf[idx:idx+4], r.Start)
		binary.LittleEndian.PutUint32(buf[idx+4:idx+8], r.End)
		idx += ackRangeEntrySize
	}
	return buf, nil
}

// DecodeAckRanges 解析 EncodeAckRanges 写入的字节流。
func DecodeAckRanges(data []byte) ([]AckRange, error) {
	if len(data) < ackRangeCountSize {
		return nil, errors.New("ack payload too short")
	}
	count := binary.LittleEndian.Uint16(data[0:ackRangeCountSize])
	if len(data) < ackRangeCountSize+int(count)*ackRangeEntrySize {
		return nil, errors.New("ack payload truncated")
	}
	ranges := make([]AckRange, count)
	idx := ackRangeCountSize
	for i := 0; i < int(count); i++ {
		ranges[i].Start = binary.LittleEndian.Uint32(data[idx : idx+4])
		ranges[i].End = binary.LittleEndian.Uint32(data[idx+4 : idx+8])
		idx += ackRangeEntrySize
	}
	return ranges, nil
}

// BuildAckFrame 构造一个 ACK 帧，TotalFrames 字段透传以便接收侧/发送侧共享上下文。
func BuildAckFrame(messageId uint64, totalFrames uint32, ranges []AckRange) (*Frame, error) {
	payload, err := EncodeAckRanges(ranges)
	if err != nil {
		return nil, err
	}
	return &Frame{
		MessageId:   messageId,
		TotalFrames: totalFrames,
		FrameType:   FrameTypeAck,
		Payload:     payload,
	}, nil
}

// FullAckRange 返回覆盖 [0, total) 的单一区间，用于对已完成消息的兜底 ACK。
func FullAckRange(total uint32) []AckRange {
	if total == 0 {
		return nil
	}
	return []AckRange{{Start: 0, End: total - 1}}
}

func seqsToRanges(seqs []uint32) []AckRange {
	if len(seqs) == 0 {
		return nil
	}
	ranges := make([]AckRange, 0, 4)
	start := seqs[0]
	end := seqs[0]
	for i := 1; i < len(seqs); i++ {
		if seqs[i] == end+1 {
			end = seqs[i]
			continue
		}
		ranges = append(ranges, AckRange{Start: start, End: end})
		start = seqs[i]
		end = seqs[i]
	}
	ranges = append(ranges, AckRange{Start: start, End: end})
	return ranges
}

// FrameIdGenerator 单调递增地生成 MessageId / AckId，并发安全。
//
// 用 atomic.Uint64 而非裸 uint64，是为了让 Go 运行时保证该字段 8 字节对齐：
// FrameIdGenerator 会被按值嵌入到 TcpStream / DualFrameRelayEndpoint 等结构体里，
// 在 32 位平台(GOARCH=386)上裸 uint64 字段可能落在 4 字节对齐处，
// 直接对其做 64 位原子操作会触发 "unaligned 64-bit atomic operation" panic。
type FrameIdGenerator struct {
	counter atomic.Uint64
}

// Next 返回下一个 ID(从 1 开始，0 视为未设置)。
func (g *FrameIdGenerator) Next() uint64 {
	return g.counter.Add(1)
}
