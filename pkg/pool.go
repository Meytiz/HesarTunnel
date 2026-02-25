package pkg

import (
	"sync"
	"sync/atomic"
)

type BufferPool struct {
	pool sync.Pool
	size int
}

func NewBufferPool(size int) *BufferPool {
	bp := &BufferPool{size: size}
	bp.pool = sync.Pool{New: func() interface{} { return make([]byte, bp.size) }}
	return bp
}

func (bp *BufferPool) Get() []byte  { return bp.pool.Get().([]byte) }
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) == bp.size {
		bp.pool.Put(buf[:bp.size])
	}
}

type ConnIDGenerator struct{ counter uint32 }

func NewConnIDGenerator() *ConnIDGenerator { return &ConnIDGenerator{} }
func (g *ConnIDGenerator) Next() uint32 {
	for {
		id := atomic.AddUint32(&g.counter, 1)
		if id != 0 {
			return id
		}
	}
}

type ConnMap struct {
	mu    sync.RWMutex
	items map[uint32]interface{}
}

func NewConnMap() *ConnMap { return &ConnMap{items: make(map[uint32]interface{})} }

func (cm *ConnMap) Store(id uint32, v interface{}) {
	cm.mu.Lock()
	cm.items[id] = v
	cm.mu.Unlock()
}

func (cm *ConnMap) Load(id uint32) (interface{}, bool) {
	cm.mu.RLock()
	v, ok := cm.items[id]
	cm.mu.RUnlock()
	return v, ok
}

func (cm *ConnMap) Delete(id uint32) {
	cm.mu.Lock()
	delete(cm.items, id)
	cm.mu.Unlock()
}

func (cm *ConnMap) Range(fn func(uint32, interface{}) bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for id, v := range cm.items {
		if !fn(id, v) {
			break
		}
	}
}

func (cm *ConnMap) Clear() {
	cm.mu.Lock()
	cm.items = make(map[uint32]interface{})
	cm.mu.Unlock()
}
