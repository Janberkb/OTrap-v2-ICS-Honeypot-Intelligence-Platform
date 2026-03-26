# Maintainer Notes — Proto / Dependency Regeneration

This document is **not** for end users. The repository ships with pre-generated files so that a normal first-time setup requires no extra tooling.

Pre-generated files included:

- `sensor/go.sum`
- `sensor/proto/sensorv1/sensor.pb.go`
- `sensor/proto/sensorv1/sensor_grpc.pb.go`
- `manager/grpc/sensor_pb2.py`
- `manager/grpc/sensor_pb2_grpc.py`
- `ui/package-lock.json`

You only need this document if:

- `proto/sensor.proto` has changed
- Go dependencies have changed and `go.sum` needs updating
- You want to regenerate the gRPC stubs from scratch

---

## Regeneration

```bash
# From repo root
make proto

# Update Go dependency metadata
cd sensor && go mod tidy && go test ./...

# Refresh UI lockfile (if needed)
cd ../ui && npm install --package-lock-only
```

Notes:

- `make proto` installs Go generator binaries on first run.
- `make proto` creates a local helper venv at `.tools/proto-venv` for Python `grpcio-tools`.
- `protoc` must be installed on the host (`sudo apt install -y protobuf-compiler`).

---

## Verification

```bash
ls sensor/proto/sensorv1/
ls manager/grpc/
wc -l sensor/go.sum
cd sensor && go test ./...
```
