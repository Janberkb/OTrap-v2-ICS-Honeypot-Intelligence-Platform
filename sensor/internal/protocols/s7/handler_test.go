// sensor/internal/protocols/s7/handler_test.go
package s7

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/otrap/sensor/internal/config"
	"github.com/otrap/sensor/internal/dispatch"
	"github.com/otrap/sensor/internal/health"
	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

// mockConn is a net.Conn that reads from a buffer and writes to another buffer.
type mockConn struct {
	readBuf  *bytes.Reader
	writeBuf *bytes.Buffer
	addr     *net.TCPAddr
}

func newMockConn(data []byte) *mockConn {
	return &mockConn{
		readBuf:  bytes.NewReader(data),
		writeBuf: &bytes.Buffer{},
		addr:     &net.TCPAddr{IP: net.ParseIP("10.0.0.42"), Port: 54321},
	}
}

func (m *mockConn) Read(b []byte) (int, error)         { return m.readBuf.Read(b) }
func (m *mockConn) Write(b []byte) (int, error)        { return m.writeBuf.Write(b) }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return m.addr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.addr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func makeTPKT(payload []byte) []byte {
	total := uint16(4 + len(payload))
	frame := []byte{0x03, 0x00, byte(total >> 8), byte(total)}
	return append(frame, payload...)
}

// ─── Memory Map tests ──────────────────────────────────────────────────────

func TestMemoryMap_WriteReadback(t *testing.T) {
	m := NewMemoryMap()

	// Write a value to DB1, offset 0
	written := []byte{0x01, 0x00}
	m.Write(1, 0, written, "10.0.0.42:54321")

	// Read it back — must match exactly
	read := m.Read(1, 0, 2)
	if !bytes.Equal(read, written) {
		t.Errorf("stateful memory read-back failed: expected %x got %x", written, read)
	}
}

func TestMemoryMap_DefaultValue_IsConsistent(t *testing.T) {
	m := NewMemoryMap()
	// Unwritten address must return consistent value on repeated reads
	r1 := m.Read(5, 100, 4)
	r2 := m.Read(5, 100, 4)
	if !bytes.Equal(r1, r2) {
		t.Errorf("default value not deterministic: %x vs %x", r1, r2)
	}
}

func TestMemoryMap_WriteOverwrite(t *testing.T) {
	m := NewMemoryMap()
	m.Write(2, 10, []byte{0xAA, 0xBB}, "session1")
	m.Write(2, 10, []byte{0x00, 0x01}, "session1")
	read := m.Read(2, 10, 2)
	if !bytes.Equal(read, []byte{0x00, 0x01}) {
		t.Errorf("overwrite failed: got %x", read)
	}
}

func TestMemoryMap_DrainWrites(t *testing.T) {
	m := NewMemoryMap()
	m.Write(1, 0, []byte{0x01}, "s1")
	m.Write(2, 4, []byte{0x02}, "s1")
	writes := m.DrainWrites()
	if len(writes) != 2 {
		t.Errorf("expected 2 writes, got %d", len(writes))
	}
	// Drain should clear the queue
	writes2 := m.DrainWrites()
	if len(writes2) != 0 {
		t.Errorf("expected 0 after drain, got %d", len(writes2))
	}
}

// ─── COTP Connection test ──────────────────────────────────────────────────

func TestHandler_COTPConnect(t *testing.T) {
	// Build COTP Connection Request
	cotpCR := []byte{
		0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
		0xC0, 0x01, 0x0A,
		0xC1, 0x02, 0x01, 0x00,
		0xC2, 0x02, 0x01, 0x02,
	}
	frame := makeTPKT(cotpCR)

	// Append a follow-up S7 setup comm to trigger state machine
	s7Setup := []byte{
		0x02, 0xF0, 0x80,
		0x32, 0x01, 0x00, 0x00,
		0x00, 0x01,
		0x00, 0x08, 0x00, 0x00,
		0xF0, 0x00,
		0x00, 0x01, 0x00, 0x01, 0x01, 0xE0,
	}
	frame = append(frame, makeTPKT(s7Setup)...)

	conn := newMockConn(frame)
	cfg  := &config.SensorConfig{
		SensorID:   "test-sensor",
		S7Port:     102,
		PLCName:    "TestPLC",
		ModuleType: "6ES7 315-2AG10-0AB0",
		SerialNumber: "S C-TEST00001",
		StatefulS7Memory: true,
	}
	disp := dispatch.New(100)
	mem  := NewMemoryMap()
	h    := &health.Tracker{}

	handler := NewHandler(conn, cfg, disp, mem, h)
	handler.state = stateInit

	// Run connection handling
	done := make(chan struct{})
	go func() {
		defer close(done)
		// We can't call Handle directly since it loops, so test dispatch
		// COTP CR
		err := handler.handleCOTPConnect(frame[:22])
		if err != nil {
			t.Errorf("handleCOTPConnect error: %v", err)
		}
	}()

	<-done

	// Verify COTP CC was written
	resp := conn.writeBuf.Bytes()
	if len(resp) < 6 || resp[5] != 0xD0 {
		t.Errorf("expected COTP CC (0xD0) in response, got: %x", resp[:min(len(resp), 10)])
	}

	// Verify state transitioned
	if handler.state != stateCOTPConnected {
		t.Errorf("expected stateCOTPConnected, got %d", handler.state)
	}
}

// ─── CPU STOP detection test ───────────────────────────────────────────────

func TestHandler_CPUStop_EmitsCriticalEvent(t *testing.T) {
	cfg  := &config.SensorConfig{SensorID: "test", S7Port: 102}
	disp := dispatch.New(100)
	mem  := NewMemoryMap()
	h    := &health.Tracker{}

	conn := newMockConn([]byte{})
	handler := NewHandler(conn, cfg, disp, mem, h)
	handler.state = stateOperational

	// CPU STOP params
	params := []byte{0x29, 0x00, 0x00, 0x00, 0x00, 0x00}
	rawPkt := []byte{0x03, 0x00, 0x00, 0x1D}

	err := handler.handleControl(0x29, params, 5, rawPkt)
	if err != nil {
		// OK — conn is mock with empty reader, will EOF
	}

	// Check event was emitted
	select {
	case ev := <-disp.Events():
		if ev.EventType != sensorv1.EventType_S7_CPU_STOP {
			t.Errorf("expected S7_CPU_STOP, got %v", ev.EventType)
		}
		if ev.Severity != sensorv1.Severity_SEVERITY_CRITICAL {
			t.Errorf("expected CRITICAL, got %v", ev.Severity)
		}
		if ev.Metadata["cpu_stop"] != "true" {
			t.Errorf("expected cpu_stop=true in metadata")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("no event emitted after CPU STOP")
	}
}

// ─── S7 SZL plausible response test ───────────────────────────────────────

func TestBuildSZLResponse_ModuleID(t *testing.T) {
	cfg := &config.SensorConfig{
		PLCName:    "S7-300/ET 200M station_1",
		ModuleType: "6ES7 315-2AG10-0AB0",
		SerialNumber: "S C-C2UR28922012",
	}
	resp := buildSZLResponse(0x0011, cfg)
	if len(resp) == 0 {
		t.Error("SZL response for 0x0011 should not be empty")
	}
	// SZL-ID must be present
	if resp[0] != 0x00 || resp[1] != 0x11 {
		t.Errorf("SZL-ID mismatch in response: %x", resp[:4])
	}
}

// ─── Dispatcher tests ─────────────────────────────────────────────────────

func TestDispatcher_RingBuffer(t *testing.T) {
	d := dispatch.New(3)

	for i := 0; i < 5; i++ {
		d.Emit(&sensorv1.SensorEvent{EventId: string(rune('a' + i))})
	}

	_, dropped, _ := d.Stats()
	if dropped != 2 {
		t.Errorf("expected 2 dropped events (buffer=3, sent=5), got %d", dropped)
	}
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
