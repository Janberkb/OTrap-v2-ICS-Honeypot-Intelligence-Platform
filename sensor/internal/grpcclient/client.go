// internal/grpcclient/client.go — gRPC client for Manager communication.
//
// Manages the long-lived EventStream and periodic Heartbeat RPCs.
// Reconnects automatically with exponential backoff on stream failure.
package grpcclient

import (
	"context"
	"log/slog"
	"math"
	"runtime"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/otrap/sensor/internal/config"
	"github.com/otrap/sensor/internal/dispatch"
	"github.com/otrap/sensor/internal/health"
	"github.com/otrap/sensor/internal/join"
	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

// Client wraps the gRPC connection and provides high-level stream management.
type Client struct {
	managerAddr string
	identity    *join.Identity
	conn        *grpc.ClientConn
	client      sensorv1.SensorServiceClient
}

func New(managerAddr string, identity *join.Identity) (*Client, error) {
	tlsCfg, err := identity.BuildTLSConfig()
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(
		managerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithBlock(),
		grpc.WithTimeout(15*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return &Client{
		managerAddr: managerAddr,
		identity:    identity,
		conn:        conn,
		client:      sensorv1.NewSensorServiceClient(conn),
	}, nil
}

// RunEventStream maintains a long-lived gRPC EventStream.
// On failure, reconnects with exponential backoff (max 60s).
func (c *Client) RunEventStream(ctx context.Context, disp *dispatch.Dispatcher, cfg *config.SensorConfig) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if attempt > 0 {
			backoffSeconds := 1 << uint(attempt)
			delay := time.Duration(math.Min(float64(backoffSeconds), 60)) * time.Second
			slog.Info("EventStream reconnecting", "delay", delay, "attempt", attempt)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}

		slog.Info("EventStream connecting to Manager")
		if err := c.runStream(ctx, disp, cfg); err != nil {
			slog.Warn("EventStream disconnected", "error", err)
			attempt++
		} else {
			attempt = 0
		}
	}
}

func (c *Client) runStream(ctx context.Context, disp *dispatch.Dispatcher, cfg *config.SensorConfig) error {
	// Send sensor-id as metadata so Manager knows identity at stream-open time,
	// even when no events flow (idle sensor with no attack traffic).
	md := metadata.Pairs("sensor-id", cfg.SensorID)
	streamCtx := metadata.NewOutgoingContext(ctx, md)
	stream, err := c.client.EventStream(streamCtx)
	if err != nil {
		return err
	}
	slog.Info("EventStream established")

	// Receive ack/command goroutine
	go func() {
		for {
			cmd, err := stream.Recv()
			if err != nil {
				return
			}
			switch cmd.Command.(type) {
			case *sensorv1.ManagerCommand_Ping:
				slog.Debug("Manager ping received")
			case *sensorv1.ManagerCommand_ConfigUpdate:
				slog.Info("Config update received from Manager")
			case *sensorv1.ManagerCommand_Shutdown:
				slog.Warn("Manager sent shutdown signal")
			}
		}
	}()

	// Send events from dispatcher
	flushInterval := time.Duration(cfg.StreamFlushIntervalMS) * time.Millisecond
	if flushInterval == 0 {
		flushInterval = 500 * time.Millisecond
	}
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return nil

		case ev := <-disp.Events():
			ev.SensorId = cfg.SensorID
			if err := stream.Send(ev); err != nil {
				return err
			}
			disp.MarkSent()

		case <-ticker.C:
			// Flush any remaining buffered events
			for {
				select {
				case ev := <-disp.Events():
					ev.SensorId = cfg.SensorID
					if err := stream.Send(ev); err != nil {
						return err
					}
					disp.MarkSent()
				default:
					goto done
				}
			}
		done:
		}
	}
}

// RunHeartbeat sends periodic heartbeat RPCs to the Manager.
// RunHeartbeat sends periodic heartbeat RPCs to the Manager.
// Accepts the dispatcher so accurate event counters are included.
func (c *Client) RunHeartbeat(ctx context.Context, tracker *health.Tracker, disp *dispatch.Dispatcher, cfg *config.SensorConfig) {
	interval := time.Duration(cfg.HeartbeatIntervalSec) * time.Second
	if interval == 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			buffered, _, sent := disp.Stats()
			req := &sensorv1.HeartbeatRequest{
				SensorId:        cfg.SensorID,
				EventsBuffered:  buffered,
				EventsSentTotal: sent,
				CpuPercent:      getCPUPercent(),
				MemBytesRss:     getMemRSS(),
				PortStatus:      tracker.PortStatuses(),
			}
			timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			resp, err := c.client.Heartbeat(timeoutCtx, req)
			cancel()
			if err != nil {
				slog.Warn("Heartbeat failed", "error", err)
			} else if !resp.Ok {
				slog.Warn("Heartbeat rejected by Manager", "message", resp.Message)
			}
		}
	}
}

// getCPUPercent returns a rough CPU usage estimate (best-effort).
func getCPUPercent() float32 {
	// In production: use gopsutil or /proc/stat
	// For now, return 0 (non-blocking)
	return 0
}

// getMemRSS returns the current process RSS in bytes.
func getMemRSS() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.Sys
}
