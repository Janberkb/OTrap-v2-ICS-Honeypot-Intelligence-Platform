// internal/protocols/s7/server.go — S7comm honeypot TCP listener
package s7

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/otrap/sensor/internal/config"
	"github.com/otrap/sensor/internal/dispatch"
	"github.com/otrap/sensor/internal/health"
)

const (
	maxConnections = 500
	readTimeout    = 120 * time.Second
	writeTimeout   = 10 * time.Second
)

// Server listens on port 102 and spawns a stateful handler per connection.
type Server struct {
	cfg        *config.SensorConfig
	dispatcher *dispatch.Dispatcher
	health     *health.Tracker

	// Shared stateful memory map (one per sensor, shared across all sessions)
	memory *MemoryMap

	// Optional gRPC client for forensic memory sync to Manager
	// Set via SetMemorySyncClient after construction.
	memorySyncClient MemorySyncClient

	// Active connection tracking
	mu      sync.Mutex
	conns   map[string]*Handler
	total   int64
}

func NewServer(cfg *config.SensorConfig, d *dispatch.Dispatcher, h *health.Tracker) *Server {
	return &Server{
		cfg:        cfg,
		dispatcher: d,
		health:     h,
		memory:     NewMemoryMap(),
		conns:      make(map[string]*Handler),
	}
}

// SetMemorySyncClient wires in the gRPC client for forensic DB write recording.
// Call this before ListenAndServe. If not set, memory sync is silently disabled.
func (s *Server) SetMemorySyncClient(client MemorySyncClient) {
	s.memorySyncClient = client
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.S7Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("s7 listen %s: %w", addr, err)
	}
	defer ln.Close()

	s.health.SetPortStatus(s.cfg.S7Port, true)
	slog.Info("S7 honeypot listening", "addr", addr)

	// Start forensic memory sync to Manager (best-effort, non-blocking)
	StartMemorySync(ctx, s.memory, s.cfg.SensorID, s.memorySyncClient, 5*time.Second)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Warn("S7 accept error", "error", err)
				continue
			}
		}

		s.mu.Lock()
		s.total++
		s.mu.Unlock()

		handler := NewHandler(conn, s.cfg, s.dispatcher, s.memory, s.health)
		s.mu.Lock()
		s.conns[conn.RemoteAddr().String()] = handler
		s.mu.Unlock()

		go func() {
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn.RemoteAddr().String())
				s.mu.Unlock()
				s.health.DecrConn(s.cfg.S7Port)
			}()
			s.health.IncrConn(s.cfg.S7Port)
			handler.Handle(ctx)
		}()
	}
}

func (s *Server) ActiveConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}
