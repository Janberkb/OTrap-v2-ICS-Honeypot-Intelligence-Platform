// internal/dispatch/dispatcher.go — Thread-safe ring buffer between protocol
// servers and the gRPC EventStream sender.
package dispatch

import (
	"sync"
	"sync/atomic"

	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

// Dispatcher buffers SensorEvents from protocol handlers and provides
// a blocking consumer channel for the gRPC stream goroutine.
type Dispatcher struct {
	ch          chan *sensorv1.SensorEvent
	dropped     atomic.Int64
	sent        atomic.Int64
	mu          sync.Mutex
	subscribers []chan<- *sensorv1.SensorEvent
}

func New(bufferSize int) *Dispatcher {
	return &Dispatcher{
		ch: make(chan *sensorv1.SensorEvent, bufferSize),
	}
}

// Emit sends an event to the buffer. If the buffer is full, the event is
// dropped and the drop counter is incremented (non-blocking design for
// protocol handler goroutines — we must NEVER block a TCP handler).
func (d *Dispatcher) Emit(event *sensorv1.SensorEvent) {
	select {
	case d.ch <- event:
	default:
		// Buffer full — drop and count
		d.dropped.Add(1)
	}
}

// Events returns the read channel for the gRPC stream consumer.
func (d *Dispatcher) Events() <-chan *sensorv1.SensorEvent {
	return d.ch
}

// Stats returns current counters for heartbeat reporting.
func (d *Dispatcher) Stats() (buffered int64, dropped int64, sent int64) {
	return int64(len(d.ch)), d.dropped.Load(), d.sent.Load()
}

// MarkSent increments the sent counter (called by gRPC stream after successful send).
func (d *Dispatcher) MarkSent() {
	d.sent.Add(1)
}
