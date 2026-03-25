// internal/join/join.go — Sensor identity, join flow, and cert storage
package join

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

// Identity is the persistent sensor identity returned by Manager at join time.
type Identity struct {
	SensorID      string
	SensorName    string
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	CACertPEM     []byte
	Config        *sensorv1.SensorConfig
	JoinedAt      time.Time
}

// ─────────────────────────────────────────────────────────────────────────────
// CertStore — AES-256-GCM encrypted JSON file on disk
// ─────────────────────────────────────────────────────────────────────────────

type CertStore struct {
	dir    string
	encKey []byte // 32 bytes
}

func NewCertStore(dir, hexKey string) (*CertStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}
	var key []byte
	if hexKey != "" {
		var err error
		key, err = hex.DecodeString(hexKey)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("cert-key must be 32-byte hex string (64 hex chars)")
		}
	} else {
		// Auto-generate and log once — operator should persist this key
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate cert key: %w", err)
		}
		slog.Warn("No --cert-key provided; generated ephemeral key. Set SENSOR_CERT_ENC_KEY=" + hex.EncodeToString(key) + " to persist identity across restarts.")
	}
	return &CertStore{dir: dir, encKey: key}, nil
}

func (s *CertStore) identityPath() string {
	return filepath.Join(s.dir, "identity.enc")
}

func (s *CertStore) Save(id *Identity) error {
	data, err := json.Marshal(identityDTO{
		SensorID:      id.SensorID,
		SensorName:    id.SensorName,
		ClientCertPEM: string(id.ClientCertPEM),
		ClientKeyPEM:  string(id.ClientKeyPEM),
		CACertPEM:     string(id.CACertPEM),
		Config:        id.Config,
		JoinedAt:      id.JoinedAt,
	})
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}

	ciphertext, err := encryptAESGCM(s.encKey, data)
	if err != nil {
		return fmt.Errorf("encrypt identity: %w", err)
	}

	tmp := s.identityPath() + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	return os.Rename(tmp, s.identityPath())
}

func (s *CertStore) Load() (*Identity, error) {
	raw, err := os.ReadFile(s.identityPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // Not found — first run
	}
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}

	plaintext, err := decryptAESGCM(s.encKey, raw)
	if err != nil {
		return nil, fmt.Errorf("decrypt identity (wrong key?): %w", err)
	}

	var dto identityDTO
	if err := json.Unmarshal(plaintext, &dto); err != nil {
		return nil, fmt.Errorf("unmarshal identity: %w", err)
	}

	return &Identity{
		SensorID:      dto.SensorID,
		SensorName:    dto.SensorName,
		ClientCertPEM: []byte(dto.ClientCertPEM),
		ClientKeyPEM:  []byte(dto.ClientKeyPEM),
		CACertPEM:     []byte(dto.CACertPEM),
		Config:        dto.Config,
		JoinedAt:      dto.JoinedAt,
	}, nil
}

type identityDTO struct {
	SensorID      string                 `json:"sensor_id"`
	SensorName    string                 `json:"sensor_name"`
	ClientCertPEM string                 `json:"client_cert_pem"`
	ClientKeyPEM  string                 `json:"client_key_pem"`
	CACertPEM     string                 `json:"ca_cert_pem"`
	Config        *sensorv1.SensorConfig `json:"config,omitempty"`
	JoinedAt      time.Time              `json:"joined_at"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Joiner — performs the one-time gRPC join handshake
// ─────────────────────────────────────────────────────────────────────────────

type Joiner struct {
	managerAddr string
	token       string
	sensorName  string
	version     string
}

func NewJoiner(managerAddr, token, sensorName, version string) *Joiner {
	return &Joiner{
		managerAddr: managerAddr,
		token:       token,
		sensorName:  sensorName,
		version:     version,
	}
}

func (j *Joiner) Join(ctx context.Context) (*Identity, error) {
	// During join, we cannot yet use mTLS (we don't have a cert yet).
	// We use server-side TLS only, verifying the CA cert that the operator
	// has pre-distributed (or skip verify in dev mode via env flag).
	//
	// In production: SENSOR_MANAGER_CA_CERT_PATH points to the Manager's CA cert.
	// In dev: SENSOR_INSECURE_JOIN=true skips server cert verification.

	tlsCfg := &tls.Config{
		InsecureSkipVerify: os.Getenv("SENSOR_INSECURE_JOIN") == "true", //nolint:gosec
		MinVersion:         tls.VersionTLS13,
	}

	if caPath := os.Getenv("SENSOR_MANAGER_CA_CERT_PATH"); caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read manager CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("parse manager CA cert")
		}
		tlsCfg.RootCAs = pool
		tlsCfg.InsecureSkipVerify = false
	}

	conn, err := grpc.NewClient(j.managerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, friendlyJoinError(j.managerAddr, err)
	}
	defer conn.Close()

	// Apply a 30-second deadline to the Join RPC.
	joinCtx, joinCancel := context.WithTimeout(ctx, 30*time.Second)
	defer joinCancel()

	client := sensorv1.NewSensorServiceClient(conn)

	localIP := "0.0.0.0"
	if ip, err := getOutboundIP(); err == nil {
		localIP = ip
	}

	resp, err := client.Join(joinCtx, &sensorv1.JoinRequest{
		JoinToken:    j.token,
		SensorName:   j.sensorName,
		Version:      j.version,
		Capabilities: []string{"s7", "modbus", "hmi"},
		LocalIp:      localIP,
	})
	if err != nil {
		return nil, friendlyJoinError(j.managerAddr, err)
	}

	if resp.SensorId == "" {
		return nil, fmt.Errorf("manager returned empty sensor_id")
	}

	return &Identity{
		SensorID:      resp.SensorId,
		SensorName:    j.sensorName,
		ClientCertPEM: resp.ClientCertPem,
		ClientKeyPEM:  resp.ClientKeyPem,
		CACertPEM:     resp.CaCertPem,
		Config:        resp.Config,
		JoinedAt:      time.Now().UTC(),
	}, nil
}

func friendlyJoinError(managerAddr string, err error) error {
	if statusErr, ok := status.FromError(err); ok {
		switch statusErr.Code() {
		case codes.Unauthenticated:
			switch statusErr.Message() {
			case "invalid_token":
				return fmt.Errorf("join rejected by Manager: invalid or already-used SENSOR_JOIN_TOKEN")
			case "token_expired":
				return fmt.Errorf("join rejected by Manager: SENSOR_JOIN_TOKEN has expired; generate a new onboarding command")
			default:
				return fmt.Errorf("join rejected by Manager: %s", statusErr.Message())
			}
		case codes.Unavailable:
			return fmt.Errorf("cannot reach Manager at %s. Check SENSOR_MANAGER_URL and outbound TCP/9443 access: %w", managerAddr, err)
		}
	}

	message := err.Error()
	switch {
	case strings.Contains(message, "certificate signed by unknown authority"),
		strings.Contains(message, "tls: failed to verify certificate"),
		strings.Contains(message, "x509:"):
		return fmt.Errorf(
			"Manager TLS verification failed for %s. Set SENSOR_INSECURE_JOIN=true for the first join or provide SENSOR_MANAGER_CA_CERT_PATH: %w",
			managerAddr,
			err,
		)
	case strings.Contains(message, "connection refused"),
		strings.Contains(message, "context deadline exceeded"),
		strings.Contains(message, "i/o timeout"),
		strings.Contains(message, "no route to host"):
		return fmt.Errorf("cannot reach Manager at %s. Check SENSOR_MANAGER_URL and outbound TCP/9443 access: %w", managerAddr, err)
	default:
		return fmt.Errorf("join with Manager at %s failed: %w", managerAddr, err)
	}
}

// BuildTLSConfig builds an mTLS config from the sensor identity.
func (id *Identity) BuildTLSConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(id.ClientCertPEM, id.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client cert/key: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(id.CACertPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	// Extract server CN from CA cert to use as ServerName
	serverName := "otrap-manager"
	if block, _ := pem.Decode(id.CACertPEM); block != nil {
		if caCert, err := x509.ParseCertificate(block.Bytes); err == nil {
			serverName = caCert.Subject.CommonName
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM helpers
// ─────────────────────────────────────────────────────────────────────────────

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Prepend nonce to ciphertext
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func getOutboundIP() (string, error) {
	// UDP dial trick: no packet is sent, but the OS selects the correct
	// outbound interface so LocalAddr() returns the real IP.
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "0.0.0.0", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
