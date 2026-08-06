package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"hash/maphash"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	retransmitCacheShardCount     = 64
	retransmitCacheMaxEntries     = 131072
	retransmitCacheNodeProtected  = 4096
	retransmitCacheNodeMax        = 32768
	retransmitCacheConnectionMax  = 8192
	retransmitCacheTTL            = 90 * time.Second
	retransmitCacheMaxFreeRepeats = 6
	retransmitCacheLogInterval    = 10 * time.Second
)

type retransmitFrameKey struct {
	nodeID       string
	connectionID string
	messageID    uint64
	seqID        uint32
	totalFrames  uint32
}

type retransmitConnectionKey struct {
	nodeID       string
	connectionID string
}

type retransmitMessageKey struct {
	nodeID       string
	connectionID string
	messageID    uint64
	totalFrames  uint32
}

type retransmitCacheEntry struct {
	fingerprint [16]byte
	expiresAt   int64
	freeRepeats uint8
	expiryItem  *list.Element
}

type retransmitExpiryItem struct {
	key       retransmitFrameKey
	expiresAt int64
}

type retransmitCacheShard struct {
	mu         sync.Mutex
	entries    map[retransmitFrameKey]*retransmitCacheEntry
	expiry     *list.List
	nodeCounts map[string]int
	connCounts map[retransmitConnectionKey]int
}

type retransmitCacheCounters struct {
	hits           atomic.Uint64
	misses         atomic.Uint64
	mismatches     atomic.Uint64
	chargedRepeats atomic.Uint64
	quotaDrops     atomic.Uint64
	evictions      atomic.Uint64
	expired        atomic.Uint64
	ackRemovals    atomic.Uint64
	failClosed     atomic.Uint64
	entries        atomic.Int64
	lastLogUnix    atomic.Int64
}

type retransmitCacheStats struct {
	Hits           uint64
	Misses         uint64
	Mismatches     uint64
	ChargedRepeats uint64
	QuotaDrops     uint64
	Evictions      uint64
	Expired        uint64
	AckRemovals    uint64
	FailClosed     uint64
	Entries        int64
}

type globalRetransmitCache struct {
	shards      [retransmitCacheShardCount]retransmitCacheShard
	shardSeed   maphash.Seed
	hmacPool    sync.Pool
	secret      [32]byte
	ackMu       sync.Mutex
	ackProgress map[retransmitMessageKey]uint32
	counters    retransmitCacheCounters
	available   bool
}

func newGlobalRetransmitCache() *globalRetransmitCache {
	return newGlobalRetransmitCacheWithEntropy(rand.Reader)
}

func newGlobalRetransmitCacheWithEntropy(entropy io.Reader) *globalRetransmitCache {
	cache := &globalRetransmitCache{
		shardSeed:   maphash.MakeSeed(),
		ackProgress: make(map[retransmitMessageKey]uint32),
		available:   true,
	}
	if _, err := io.ReadFull(entropy, cache.secret[:]); err != nil {
		cache.available = false
		logx.Errorf("[billing-cache] retransmit fingerprint entropy unavailable; fail-closed accounting enabled: %v", err)
	}
	for index := range cache.shards {
		cache.shards[index].entries = make(map[retransmitFrameKey]*retransmitCacheEntry)
		cache.shards[index].expiry = list.New()
		cache.shards[index].nodeCounts = make(map[string]int)
		cache.shards[index].connCounts = make(map[retransmitConnectionKey]int)
	}
	if cache.available {
		cache.hmacPool.New = func() any {
			return hmac.New(sha256.New, cache.secret[:])
		}
	}
	return cache
}

func (c *globalRetransmitCache) recordFrame(nodeID string, frame *network.Frame) bool {
	if c == nil || frame == nil || nodeID == "" || frame.ConnectionId == "" {
		return true
	}
	if !c.available {
		c.counters.failClosed.Add(1)
		c.maybeLogStats()
		return true
	}
	key := retransmitFrameKey{
		nodeID:       nodeID,
		connectionID: frame.ConnectionId,
		messageID:    frame.MessageId,
		seqID:        frame.SeqId,
		totalFrames:  frame.TotalFrames,
	}
	fingerprint := c.fingerprint(key, frame.Payload)
	shard := &c.shards[c.shardIndex(key)]
	now := time.Now().UnixNano()

	shard.mu.Lock()
	c.expireLocked(shard, now)
	if entry := shard.entries[key]; entry != nil {
		if !hmac.Equal(entry.fingerprint[:], fingerprint[:]) {
			c.counters.mismatches.Add(1)
			shard.mu.Unlock()
			c.maybeLogStats()
			return true
		}
		if entry.freeRepeats >= retransmitCacheMaxFreeRepeats {
			c.counters.chargedRepeats.Add(1)
			shard.mu.Unlock()
			c.maybeLogStats()
			return true
		}
		entry.freeRepeats++
		c.refreshExpiryLocked(shard, key, entry, now)
		c.counters.hits.Add(1)
		shard.mu.Unlock()
		c.maybeLogStats()
		return false
	}

	connKey := retransmitConnectionKey{nodeID: nodeID, connectionID: frame.ConnectionId}
	if shard.nodeCounts[nodeID] >= retransmitCacheNodeMax/retransmitCacheShardCount ||
		shard.connCounts[connKey] >= retransmitCacheConnectionMax/retransmitCacheShardCount {
		c.counters.quotaDrops.Add(1)
		shard.mu.Unlock()
		c.maybeLogStats()
		return true
	}
	if len(shard.entries) >= retransmitCacheMaxEntries/retransmitCacheShardCount {
		if shard.nodeCounts[nodeID] >= retransmitCacheNodeProtected/retransmitCacheShardCount ||
			!c.evictOverProtectedLocked(shard, nodeID) {
			c.counters.quotaDrops.Add(1)
			shard.mu.Unlock()
			c.maybeLogStats()
			return true
		}
	}

	entry := &retransmitCacheEntry{fingerprint: fingerprint}
	shard.entries[key] = entry
	shard.nodeCounts[nodeID]++
	shard.connCounts[connKey]++
	c.counters.entries.Add(1)
	c.counters.misses.Add(1)
	c.refreshExpiryLocked(shard, key, entry, now)
	shard.mu.Unlock()
	c.maybeLogStats()
	return true
}

func (c *globalRetransmitCache) acknowledge(nodeID, connectionID string, messageID uint64, totalFrames uint32, ranges []network.AckRange) {
	if c == nil || nodeID == "" || connectionID == "" || totalFrames == 0 || len(ranges) == 0 {
		return
	}
	messageKey := retransmitMessageKey{
		nodeID:       nodeID,
		connectionID: connectionID,
		messageID:    messageID,
		totalFrames:  totalFrames,
	}
	c.ackMu.Lock()
	next := c.ackProgress[messageKey]
	advanced := next
	for _, ackRange := range ranges {
		if ackRange.Start > ackRange.End || ackRange.End >= totalFrames || ackRange.Start > advanced {
			break
		}
		if ackRange.End >= advanced {
			advanced = ackRange.End + 1
		}
	}
	if advanced == next {
		c.ackMu.Unlock()
		return
	}
	if advanced >= totalFrames {
		delete(c.ackProgress, messageKey)
	} else {
		c.ackProgress[messageKey] = advanced
	}
	c.ackMu.Unlock()

	for seqID := next; seqID < advanced; seqID++ {
		key := retransmitFrameKey{
			nodeID:       nodeID,
			connectionID: connectionID,
			messageID:    messageID,
			seqID:        seqID,
			totalFrames:  totalFrames,
		}
		shard := &c.shards[c.shardIndex(key)]
		shard.mu.Lock()
		if entry := shard.entries[key]; entry != nil {
			c.removeLocked(shard, key, entry)
			c.counters.ackRemovals.Add(1)
		}
		shard.mu.Unlock()
	}
}

func (c *globalRetransmitCache) forgetConnection(nodeID, connectionID string) {
	if c == nil || nodeID == "" || connectionID == "" {
		return
	}
	for shardIndex := range c.shards {
		shard := &c.shards[shardIndex]
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if key.nodeID == nodeID && key.connectionID == connectionID {
				c.removeLocked(shard, key, entry)
			}
		}
		shard.mu.Unlock()
	}
	c.ackMu.Lock()
	for key := range c.ackProgress {
		if key.nodeID == nodeID && key.connectionID == connectionID {
			delete(c.ackProgress, key)
		}
	}
	c.ackMu.Unlock()
}

func (c *globalRetransmitCache) snapshot() retransmitCacheStats {
	return retransmitCacheStats{
		Hits:           c.counters.hits.Load(),
		Misses:         c.counters.misses.Load(),
		Mismatches:     c.counters.mismatches.Load(),
		ChargedRepeats: c.counters.chargedRepeats.Load(),
		QuotaDrops:     c.counters.quotaDrops.Load(),
		Evictions:      c.counters.evictions.Load(),
		Expired:        c.counters.expired.Load(),
		AckRemovals:    c.counters.ackRemovals.Load(),
		FailClosed:     c.counters.failClosed.Load(),
		Entries:        c.counters.entries.Load(),
	}
}

func (c *globalRetransmitCache) fingerprint(key retransmitFrameKey, payload []byte) [16]byte {
	hasher := c.hmacPool.Get().(hash.Hash)
	hasher.Reset()
	var fixed [22]byte
	binary.LittleEndian.PutUint16(fixed[0:2], uint16(len(key.nodeID)))
	binary.LittleEndian.PutUint16(fixed[2:4], uint16(len(key.connectionID)))
	binary.LittleEndian.PutUint64(fixed[4:12], key.messageID)
	binary.LittleEndian.PutUint32(fixed[12:16], key.seqID)
	binary.LittleEndian.PutUint32(fixed[16:20], key.totalFrames)
	binary.LittleEndian.PutUint16(fixed[20:22], uint16(len(payload)))
	_, _ = hasher.Write(fixed[:])
	_, _ = hasher.Write([]byte(key.nodeID))
	_, _ = hasher.Write([]byte(key.connectionID))
	_, _ = hasher.Write(payload)
	var sum [sha256.Size]byte
	hasher.Sum(sum[:0])
	c.hmacPool.Put(hasher)
	var fingerprint [16]byte
	copy(fingerprint[:], sum[:16])
	return fingerprint
}

func (c *globalRetransmitCache) shardIndex(key retransmitFrameKey) uint64 {
	var hasher maphash.Hash
	hasher.SetSeed(c.shardSeed)
	_, _ = hasher.WriteString(key.nodeID)
	_, _ = hasher.WriteString(key.connectionID)
	var fixed [20]byte
	binary.LittleEndian.PutUint64(fixed[0:8], key.messageID)
	binary.LittleEndian.PutUint32(fixed[8:12], key.seqID)
	binary.LittleEndian.PutUint32(fixed[12:16], key.totalFrames)
	_, _ = hasher.Write(fixed[:16])
	return hasher.Sum64() % retransmitCacheShardCount
}

func (c *globalRetransmitCache) refreshExpiryLocked(shard *retransmitCacheShard, key retransmitFrameKey, entry *retransmitCacheEntry, now int64) {
	if entry.expiryItem != nil {
		shard.expiry.Remove(entry.expiryItem)
	}
	entry.expiresAt = now + int64(retransmitCacheTTL)
	entry.expiryItem = shard.expiry.PushBack(retransmitExpiryItem{key: key, expiresAt: entry.expiresAt})
}

func (c *globalRetransmitCache) expireLocked(shard *retransmitCacheShard, now int64) {
	for item := shard.expiry.Front(); item != nil; item = shard.expiry.Front() {
		expiry := item.Value.(retransmitExpiryItem)
		if expiry.expiresAt > now {
			return
		}
		entry := shard.entries[expiry.key]
		if entry != nil && entry.expiresAt <= now {
			c.removeLocked(shard, expiry.key, entry)
			c.counters.expired.Add(1)
		} else {
			shard.expiry.Remove(item)
		}
	}
}

func (c *globalRetransmitCache) evictOverProtectedLocked(shard *retransmitCacheShard, requesterNodeID string) bool {
	for item := shard.expiry.Front(); item != nil; item = item.Next() {
		candidate := item.Value.(retransmitExpiryItem)
		entry := shard.entries[candidate.key]
		if entry == nil || candidate.key.nodeID == requesterNodeID ||
			shard.nodeCounts[candidate.key.nodeID] <= retransmitCacheNodeProtected/retransmitCacheShardCount {
			continue
		}
		c.removeLocked(shard, candidate.key, entry)
		c.counters.evictions.Add(1)
		return true
	}
	return false
}

func (c *globalRetransmitCache) removeLocked(shard *retransmitCacheShard, key retransmitFrameKey, entry *retransmitCacheEntry) {
	delete(shard.entries, key)
	if entry.expiryItem != nil {
		shard.expiry.Remove(entry.expiryItem)
	}
	shard.nodeCounts[key.nodeID]--
	if shard.nodeCounts[key.nodeID] == 0 {
		delete(shard.nodeCounts, key.nodeID)
	}
	connKey := retransmitConnectionKey{nodeID: key.nodeID, connectionID: key.connectionID}
	shard.connCounts[connKey]--
	if shard.connCounts[connKey] == 0 {
		delete(shard.connCounts, connKey)
	}
	c.counters.entries.Add(-1)
}

func (c *globalRetransmitCache) maybeLogStats() {
	now := time.Now().Unix()
	last := c.counters.lastLogUnix.Load()
	if now-last < int64(retransmitCacheLogInterval/time.Second) || !c.counters.lastLogUnix.CompareAndSwap(last, now) {
		return
	}
	stats := c.snapshot()
	logx.Infof("[billing-cache] available=%t entries=%d hit=%d miss=%d mismatch=%d repeat_charged=%d fail_closed=%d quota_drop=%d eviction=%d expired=%d ack_removed=%d",
		c.available,
		stats.Entries, stats.Hits, stats.Misses, stats.Mismatches, stats.ChargedRepeats,
		stats.FailClosed, stats.QuotaDrops, stats.Evictions, stats.Expired, stats.AckRemovals)
}
