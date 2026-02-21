package pool

import "sync"

// BufferPool provides reusable byte buffers to minimize GC pressure.
// Critical for high-throughput tunneling: prevents allocation per-packet.
type BufferPool struct {
	pool sync.Pool
	size int
}

func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, size)
				return buf
			},
		},
		size: size,
	}
}

// Get retrieves a buffer from the pool.
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put returns a buffer to the pool.
func (p *BufferPool) Put(buf []byte) {
	if cap(buf) >= p.size {
		p.pool.Put(buf[:p.size])
	}
}

// Size returns the buffer size.
func (p *BufferPool) Size() int {
	return p.size
}
