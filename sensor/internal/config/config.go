// internal/config/config.go — Sensor runtime configuration
package config

import "github.com/otrap/sensor/internal/join"

// SensorConfig is the runtime configuration for all protocol servers.
// It is derived from the Manager-issued JoinResponse and can be updated
// via ManagerCommand.ConfigUpdate during operation.
type SensorConfig struct {
	SensorID   string
	SensorName string

	// Protocol ports
	S7Port       int
	ModbusPort   int
	HMIHTTPPort  int
	HMIHTTPSPort int
	ENIPPort     int

	// HMI TLS (PEM strings; empty = auto-generate self-signed)
	HMITLSCertPEM string
	HMITLSKeyPEM  string

	// S7 deception identity
	StatefulS7Memory bool
	PLCName          string
	ModuleType       string
	SerialNumber     string
	OrderNumber      string

	// HMI deception identity
	BruteForceThreshold int
	HMIBrandName        string
	HMIPlantName        string

	// Operational
	EventBufferSize       int
	HeartbeatIntervalSec  int
	StreamFlushIntervalMS int
}

// FromIdentity builds a SensorConfig from a join identity, applying
// Manager-provided config overrides and sensible defaults.
func FromIdentity(id *join.Identity) *SensorConfig {
	c := id.Config
	statefulS7Memory := true
	if c != nil {
		statefulS7Memory = c.GetStatefulS7Memory()
	}
	cfg := &SensorConfig{
		SensorID:   id.SensorID,
		SensorName: id.SensorName,

		S7Port:       intOr(int(c.GetS7Port()), 102),
		ModbusPort:   intOr(int(c.GetModbusPort()), 502),
		HMIHTTPPort:  intOr(int(c.GetHmiHttpPort()), 80),
		HMIHTTPSPort: intOr(int(c.GetHmiHttpsPort()), 443),
		ENIPPort:     44818,

		HMITLSCertPEM: c.GetHmiTlsCertPem(),
		HMITLSKeyPEM:  c.GetHmiTlsKeyPem(),

		StatefulS7Memory: statefulS7Memory,
		PLCName:          strOr(c.GetS7PlcName(), "S7-300/ET 200M station_1"),
		ModuleType:       strOr(c.GetS7ModuleType(), "6ES7 315-2AG10-0AB0"),
		SerialNumber:     strOr(c.GetS7SerialNumber(), "S C-C2UR28922012"),

		BruteForceThreshold: intOr(int(c.GetBruteForceThreshold()), 5),
		HMIBrandName:        strOr(c.GetHmiBrandName(), "SIMATIC WinCC"),
		HMIPlantName:        strOr(c.GetHmiPlantName(), "Water Treatment Plant - Unit 3"),

		EventBufferSize:       intOr(int(c.GetEventBufferSize()), 10000),
		HeartbeatIntervalSec:  intOr(int(c.GetHeartbeatIntervalS()), 30),
		StreamFlushIntervalMS: intOr(int(c.GetStreamFlushIntervalMs()), 500),
	}
	return cfg
}

func intOr(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

func strOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
