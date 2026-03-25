// internal/protocols/s7/memory.go — Stateful S7 Data Block memory map.
//
// This is the core deception mechanism: when an attacker writes to a Data Block
// (e.g. DB1.DBW0 := 0x0100), subsequent reads return that exact value.
// This convinces exploit tools and scanners that they are interacting with a
// real, writable PLC — not a honeypot.
package s7

import (
	"math/rand"
	"sync"
)

// dbKey uniquely identifies a byte range within a Data Block.
type dbKey struct {
	dbNumber   int
	byteOffset int
}

// MemoryMap is a thread-safe map of S7 Data Block memory.
// It is shared across all connections to the same sensor, modelling the
// behaviour of a single PLC with persistent register state.
type MemoryMap struct {
	mu     sync.RWMutex
	blocks map[dbKey][]byte
	// Track which addresses have been written (for forensic reporting)
	writes []WriteRecord
}

type WriteRecord struct {
	DBNumber   int
	ByteOffset int
	Value      []byte
	SessionKey string // "src_ip:src_port"
}

func NewMemoryMap() *MemoryMap {
	return &MemoryMap{
		blocks: make(map[dbKey][]byte),
	}
}

// Write stores a value at the given DB:offset and records the write for
// forensic/sync purposes.
func (m *MemoryMap) Write(dbNumber, byteOffset int, data []byte, sessionKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := dbKey{dbNumber, byteOffset}
	stored := make([]byte, len(data))
	copy(stored, data)
	m.blocks[key] = stored

	m.writes = append(m.writes, WriteRecord{
		DBNumber:   dbNumber,
		ByteOffset: byteOffset,
		Value:      stored,
		SessionKey: sessionKey,
	})
}

// Read returns the value at the given DB:offset.
// If the address has never been written, it returns plausible default bytes
// (deterministic based on address, to appear consistent across multiple reads).
func (m *MemoryMap) Read(dbNumber, byteOffset, length int) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := dbKey{dbNumber, byteOffset}
	if v, ok := m.blocks[key]; ok {
		// Return stored value, padded or truncated to requested length
		result := make([]byte, length)
		copy(result, v)
		return result
	}

	return m.plausibleDefault(dbNumber, byteOffset, length)
}

// plausibleDefault generates deterministic "factory default" bytes for
// addresses that have never been written. The values are seeded from the
// address so repeated reads return consistent data (real PLCs don't return
// random values for unwritten addresses).
func (m *MemoryMap) plausibleDefault(dbNumber, byteOffset, length int) []byte {
	seed := int64(dbNumber*10000 + byteOffset)
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec
	buf := make([]byte, length)

	// Common PLC patterns:
	// - Word (2 bytes): likely 0x0000 or small integer
	// - DWord (4 bytes): likely 0x00000000 or timestamp
	// - Byte: likely 0x00
	// We bias toward zeros for realism
	if rng.Float32() < 0.7 {
		// 70% chance: all zeros (most PLC memory is initialized to 0)
		return buf
	}
	_, _ = rng.Read(buf)
	// Mask upper bits for realism
	for i := range buf {
		buf[i] &= 0x0F
	}
	return buf
}

// DrainWrites returns and clears all pending write records for gRPC sync.
func (m *MemoryMap) DrainWrites() []WriteRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.writes
	m.writes = nil
	return w
}
