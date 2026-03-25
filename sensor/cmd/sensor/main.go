// cmd/sensor/main.go — OTrap Sensor entrypoint
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/otrap/sensor/internal/config"
	"github.com/otrap/sensor/internal/dispatch"
	"github.com/otrap/sensor/internal/grpcclient"
	"github.com/otrap/sensor/internal/health"
	"github.com/otrap/sensor/internal/join"
	"github.com/otrap/sensor/internal/protocols/hmi"
	"github.com/otrap/sensor/internal/protocols/modbus"
	"github.com/otrap/sensor/internal/protocols/s7"
)

var (
	version = "1.0.0"
	commit  = "dev"
)

func main() {
	// ── CLI flags ──────────────────────────────────────────────────────────────
	managerAddr := flag.String("manager", envOr("SENSOR_MANAGER_URL", "manager:9443"), "Manager gRPC address (host:port)")
	joinToken   := flag.String("token", envOr("SENSOR_JOIN_TOKEN", ""), "One-time join token (required on first run)")
	sensorName  := flag.String("name", envOr("SENSOR_NAME", "sensor-01"), "Human-readable sensor name")
	certDir     := flag.String("cert-dir", envOr("SENSOR_CERT_DIR", "/etc/otrap/sensor/certs"), "Directory for encrypted cert storage")
	certPassKey := flag.String("cert-key", envOr("SENSOR_CERT_ENC_KEY", ""), "32-byte hex key for cert encryption at rest")
	logLevel    := flag.String("log-level", envOr("LOG_LEVEL", "info"), "Log level: debug|info|warn|error")
	healthCheck := flag.Bool("health-check", false, "Run container health check and exit")
	flag.Parse()

	if *healthCheck {
		if err := runHealthCheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// ── Logger ─────────────────────────────────────────────────────────────────
	logger := buildLogger(*logLevel)
	slog.SetDefault(logger)

	slog.Info("OTrap Sensor starting",
		"version", version,
		"commit", commit,
		"name", *sensorName,
		"manager", *managerAddr,
	)

	// ── Load or create sensor identity ────────────────────────────────────────
	store, err := join.NewCertStore(*certDir, *certPassKey)
	if err != nil {
		slog.Error("Failed to initialize cert store", "error", err)
		os.Exit(1)
	}

	identity, err := store.Load()
	if err != nil || identity == nil {
		// First run or cert not found — perform join
		if *joinToken == "" {
			slog.Error("No stored identity and no --token provided. Cannot join Manager.")
			os.Exit(1)
		}
		slog.Info("No stored identity found — performing join with Manager")
		joiner := join.NewJoiner(*managerAddr, *joinToken, *sensorName, version)
		identity, err = joiner.Join(context.Background())
		if err != nil {
			slog.Error("Join failed", "error", err)
			os.Exit(1)
		}
		if err := store.Save(identity); err != nil {
			slog.Error("Failed to save identity", "error", err)
			os.Exit(1)
		}
		slog.Info("Join successful", "sensor_id", identity.SensorID)
	} else {
		slog.Info("Loaded existing sensor identity", "sensor_id", identity.SensorID)
	}

	// ── Build config from identity ────────────────────────────────────────────
	cfg := config.FromIdentity(identity)

	// ── Event dispatcher (ring buffer + gRPC stream) ───────────────────────────
	dispatcher := dispatch.New(cfg.EventBufferSize)

	// ── gRPC client (EventStream + Heartbeat) ─────────────────────────────────
	grpcClient, err := grpcclient.New(*managerAddr, identity)
	if err != nil {
		slog.Error("Failed to create gRPC client", "error", err)
		os.Exit(1)
	}

	// ── Health tracker ────────────────────────────────────────────────────────
	healthTracker := health.NewTracker(identity.SensorID)

	// ── Context with cancellation ─────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Start protocol listeners ───────────────────────────────────────────────
	s7Server := s7.NewServer(cfg, dispatcher, healthTracker)
	// Wire forensic memory sync: S7 DB writes → Manager gRPC → Postgres
	s7Server.SetMemorySyncClient(grpcClient)
	go func() {
		if err := s7Server.ListenAndServe(ctx); err != nil {
			slog.Error("S7 server error", "error", err)
		}
	}()

	modbusServer := modbus.NewServer(cfg, dispatcher, healthTracker)
	go func() {
		if err := modbusServer.ListenAndServe(ctx); err != nil {
			slog.Error("Modbus server error", "error", err)
		}
	}()

	hmiServer := hmi.NewServer(cfg, dispatcher, healthTracker)
	go func() {
		if err := hmiServer.ListenAndServe(ctx); err != nil {
			slog.Error("HMI server error", "error", err)
		}
	}()

	// ── Start gRPC stream and heartbeat ───────────────────────────────────────
	go grpcClient.RunEventStream(ctx, dispatcher, cfg)
	go grpcClient.RunHeartbeat(ctx, healthTracker, dispatcher, cfg)

	// ── Wait for shutdown signal ───────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	slog.Info("Shutdown signal received", "signal", sig)
	cancel()

	slog.Info("OTrap Sensor stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func buildLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(fmt.Sprintf("%v", a.Value))
			}
			return a
		},
	}))
}

func runHealthCheck() error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1/health")
	if err != nil {
		return fmt.Errorf("sensor health probe failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sensor health probe returned status %d", resp.StatusCode)
	}

	return nil
}
