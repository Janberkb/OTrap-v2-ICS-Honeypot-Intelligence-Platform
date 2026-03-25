// internal/protocols/s7/memory_sync.go — Drains S7 memory writes and forwards
// them to the Manager via gRPC SyncMemoryWrite RPC for forensic recording.
//
// Design: runs as a background goroutine inside the S7 server.
// Every 5 seconds, drains all pending writes and sends them in a batch.
// On gRPC failure, writes are not re-queued (best-effort forensics).
package s7

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

// MemorySyncClient is the subset of the gRPC client needed for memory sync.
// Using an interface makes the server testable without a real gRPC connection.
type MemorySyncClient interface {
	SyncMemoryWrite(ctx context.Context, req *sensorv1.MemoryWriteRequest) (*sensorv1.MemoryWriteResponse, error)
}

// StartMemorySync launches a goroutine that periodically drains the memory map's
// write records and forwards them to the Manager.
//
// Parameters:
//   ctx         — cancelled on sensor shutdown
//   mem         — shared S7 memory map
//   sensorID    — used in gRPC requests
//   client      — gRPC client (nil = sync disabled, sensor still works without it)
//   interval    — drain interval (default: 5s)
func StartMemorySync(
	ctx context.Context,
	mem *MemoryMap,
	sensorID string,
	client MemorySyncClient,
	interval time.Duration,
) {
	if client == nil {
		slog.Debug("S7 memory sync disabled (no gRPC client provided)")
		return
	}
	if interval == 0 {
		interval = 5 * time.Second
	}

	go runMemorySync(ctx, mem, sensorID, client, interval)
}

func runMemorySync(
	ctx context.Context,
	mem *MemoryMap,
	sensorID string,
	client MemorySyncClient,
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Debug("S7 memory sync goroutine started", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			// On shutdown: drain any remaining writes
			flushWrites(ctx, mem, sensorID, client)
			return

		case <-ticker.C:
			flushWrites(ctx, mem, sensorID, client)
		}
	}
}

// flushWrites drains all pending writes from the memory map and sends them
// to the Manager. Each write is sent as a separate RPC call (could be
// batched in future — Manager deduplicates on (sensor_id, db, offset)).
func flushWrites(
	ctx context.Context,
	mem *MemoryMap,
	sensorID string,
	client MemorySyncClient,
) {
	writes := mem.DrainWrites()
	if len(writes) == 0 {
		return
	}

	slog.Debug("Syncing S7 memory writes to Manager", "count", len(writes))

	for _, w := range writes {
		req := &sensorv1.MemoryWriteRequest{
			SensorId:   sensorID,
			SessionId:  w.SessionKey,
			DbNumber:   int32(w.DBNumber),
			ByteOffset: int32(w.ByteOffset),
			Value:      w.Value,
			WrittenAt:  timestamppb.Now(),
		}

		// Use a short timeout per RPC — don't block the flush loop
		rpcCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		resp, err := client.SyncMemoryWrite(rpcCtx, req)
		cancel()

		if err != nil {
			slog.Warn("S7 memory sync RPC failed",
				"db", w.DBNumber,
				"offset", w.ByteOffset,
				"error", err,
			)
			// Best-effort: don't re-queue, continue with remaining writes
			continue
		}

		if !resp.Ok {
			slog.Warn("Manager rejected memory write sync",
				"db", w.DBNumber,
				"offset", w.ByteOffset,
			)
		}
	}
}
