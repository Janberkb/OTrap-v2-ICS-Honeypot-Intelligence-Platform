// internal/grpcclient/memory_sync.go — SyncMemoryWrite wrapper satisfying
// the s7.MemorySyncClient interface.
package grpcclient

import (
	"context"

	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

// SyncMemoryWrite forwards a single S7 DB write record to the Manager.
// This satisfies the s7.MemorySyncClient interface.
func (c *Client) SyncMemoryWrite(
	ctx context.Context,
	req *sensorv1.MemoryWriteRequest,
) (*sensorv1.MemoryWriteResponse, error) {
	return c.client.SyncMemoryWrite(ctx, req)
}
