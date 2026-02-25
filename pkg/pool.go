package pkg

import (
	"sync"
	"sync/atomic"
)

// BufferPool provides reusable byte buffers to reduce GC pressure
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool with fixed buffer size
func NewBufferPool(bufferSize int) *BufferPool {
	bp := &BufferPool{size: bufferSize}
	bp.pool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, bp.size)
			return buf
		},
	}
	return bp
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

// Put returns a buffer to the pool
// Only returns buffers of correct capacity to prevent pool pollution
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) == bp.size {
		bp.pool.Put(buf[:bp.size])
	}
	// Drop buffers with wrong capacity (they'll be GC'd)
}

// ConnIDGenerator generates unique connection IDs atomically
type ConnIDGenerator struct {
	counter uint32
}

// NewConnIDGenerator creates a new ID generator
func NewConnIDGenerator() *ConnIDGenerator {
	return &ConnIDGenerator{counter: 0}
}

// Next returns the next unique connection ID
func (g *ConnIDGenerator) Next() uint32 {
	id := atomic.AddUint32(&g.counter, 1)
	if id == 0 {
		// Overflow, skip 0 (reserved)
		id = atomic.AddUint32(&g.counter, 1)
	}
	return id
}

// ConnMap is a thread-safe map for tracking connections
type ConnMap struct {
	mu    sync.RWMutex
	items map[uint32]interface{}
}

// NewConnMap creates a new connection map
func NewConnMap() *ConnMap {
	return &ConnMap{
		items: make(map[uint32]interface{}),
	}
}

// Store adds or updates an item
func (cm *ConnMap) Store(id uint32, value interface{}) {
	cm.mu.Lock()
	cm.items[id] = value
	cm.mu.Unlock()
}

// Load retrieves an item
func (cm *ConnMap) Load(id uint32) (interface{}, bool) {
	cm.mu.RLock()
	v, ok := cm.items[id]
	cm.mu.RUnlock()
	return v, ok
}

// Delete removes an item
func (cm *ConnMap) Delete(id uint32) {
	cm.mu.Lock()
	delete(cm.items, id)
	cm.mu.Unlock()
}

// Len returns number of items
func (cm *ConnMap) Len() int {
	cm.mu.RLock()
	n := len(cm.items)
	cm.mu.RUnlock()
	return n
}

// Range iterates over all items (holds lock during iteration)
func (cm *ConnMap) Range(fn func(id uint32, value interface{}) bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for id, v := range cm.items {
		if !fn(id, v) {
			break
		}
	}
}

// Clear removes all items
func (cm *ConnMap) Clear() {
	cm.mu.Lock()
	cm.items = make(map[uint32]interface{})
	cm.mu.Unlock()
}
