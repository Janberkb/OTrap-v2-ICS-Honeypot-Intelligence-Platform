// internal/health/stats.go — Sensor-level statistics for heartbeat.
package health

// SensorStats returns (buffered, dropped, sent) event counters.
// These are fetched from the dispatcher if available; here we return
// placeholder types that grpcclient will populate from the dispatcher directly.
func (t *Tracker) SensorStats() (buffered, dropped, sent int64) {
	// The actual stats come from dispatch.Dispatcher — grpcclient
	// passes them through from the dispatcher's Stats() call.
	// This method exists for interface completeness.
	return 0, 0, 0
}
