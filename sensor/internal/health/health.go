// internal/health/health.go — Port status and connection tracking for heartbeats.
package health

import (
	"sync"
	"sync/atomic"

	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

// portState tracks listening and connection state for one port.
type portState struct {
	listening   bool
	activeConns atomic.Int64
	totalConns  atomic.Int64
}

// Tracker maintains per-port health state for heartbeat reporting.
type Tracker struct {
	sensorID string
	mu       sync.RWMutex
	ports    map[int]*portState
}

func NewTracker(sensorID string) *Tracker {
	return &Tracker{
		sensorID: sensorID,
		ports:    make(map[int]*portState),
	}
}

// SetPortStatus marks a port as listening (called when server starts).
func (t *Tracker) SetPortStatus(port int, listening bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ports[port] == nil {
		t.ports[port] = &portState{}
	}
	t.ports[port].listening = listening
}

// IncrConn increments active and total connection counters for a port.
func (t *Tracker) IncrConn(port int) {
	t.mu.RLock()
	ps := t.ports[port]
	t.mu.RUnlock()
	if ps != nil {
		ps.activeConns.Add(1)
		ps.totalConns.Add(1)
	}
}

// DecrConn decrements the active connection counter for a port.
func (t *Tracker) DecrConn(port int) {
	t.mu.RLock()
	ps := t.ports[port]
	t.mu.RUnlock()
	if ps != nil {
		ps.activeConns.Add(-1)
	}
}

// PortStatuses returns the current status of all tracked ports.
func (t *Tracker) PortStatuses() []*sensorv1.PortStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	statuses := make([]*sensorv1.PortStatus, 0, len(t.ports))
	for port, ps := range t.ports {
		statuses = append(statuses, &sensorv1.PortStatus{
			Port:        int32(port),
			Listening:   ps.listening,
			ActiveConns: ps.activeConns.Load(),
			TotalConns:  ps.totalConns.Load(),
		})
	}
	return statuses
}
