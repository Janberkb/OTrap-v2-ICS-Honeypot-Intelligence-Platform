// internal/protocols/hmi/server.go — Fake HMI web honeypot (HTTP + HTTPS)
package hmi

import (
	"bytes"
	"context"
	"io"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/otrap/sensor/internal/config"
	"github.com/otrap/sensor/internal/dispatch"
	"github.com/otrap/sensor/internal/health"
	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

type Server struct {
	cfg        *config.SensorConfig
	dispatcher *dispatch.Dispatcher
	health     *health.Tracker
	brute      *BruteForceTracker
	classifier *OWASPClassifier
}

func NewServer(cfg *config.SensorConfig, d *dispatch.Dispatcher, h *health.Tracker) *Server {
	return &Server{
		cfg:        cfg,
		dispatcher: d,
		health:     h,
		brute:      NewBruteForceTracker(cfg.BruteForceThreshold),
		classifier: NewOWASPClassifier(),
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	errCh := make(chan error, 2)

	// HTTP
	httpServer := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", s.cfg.HMIHTTPPort),
		Handler:      mux,
		ConnState:    s.connStateHook(s.cfg.HMIHTTPPort),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	s.health.SetPortStatus(s.cfg.HMIHTTPPort, true)

	go func() {
		slog.Info("HMI HTTP honeypot listening", "port", s.cfg.HMIHTTPPort)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("hmi http: %w", err)
		}
	}()

	// HTTPS (self-signed or provided cert)
	tlsCfg, err := s.buildTLSConfig()
	if err != nil {
		slog.Warn("Failed to build HMI TLS config, skipping HTTPS", "error", err)
	} else {
		httpsServer := &http.Server{
			Addr:         fmt.Sprintf("0.0.0.0:%d", s.cfg.HMIHTTPSPort),
			Handler:      mux,
			TLSConfig:    tlsCfg,
			ConnState:    s.connStateHook(s.cfg.HMIHTTPSPort),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
		}
		s.health.SetPortStatus(s.cfg.HMIHTTPSPort, true)

		go func() {
			slog.Info("HMI HTTPS honeypot listening", "port", s.cfg.HMIHTTPSPort)
			if err := httpsServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				errCh <- fmt.Errorf("hmi https: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) connStateHook(port int) func(net.Conn, http.ConnState) {
	return func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			s.health.IncrConn(port)
		case http.StateClosed, http.StateHijacked:
			s.health.DecrConn(port)
		}
	}
}

// handleRequest is the central dispatch for all HMI HTTP traffic.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Internal health check (for manager health polling — always 200)
	if r.URL.Path == "/health" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}

	sourceIP := extractIP(r.RemoteAddr)
	path     := r.URL.Path
	method   := r.Method

	// ── OWASP Classification ──────────────────────────────────────────────────
	classification := s.classifier.Classify(r)

	// ── Route-aware dispatch ──────────────────────────────────────────────────
	switch {
	case isLoginPath(path) && (method == http.MethodPost):
		s.handleLogin(w, r, sourceIP, classification)

	case isLoginPath(path):
		s.handleLoginPage(w, r, sourceIP, classification)

	case isDashboardPath(path):
		s.handleDashboard(w, r, sourceIP, classification)

	default:
		s.handleGeneric(w, r, sourceIP, classification)
	}
}

// handleLogin captures credentials and applies brute-force rabbit hole logic.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, sourceIP string, cls *Classification) {
	_ = r.ParseForm()
	username := r.FormValue("username")
	if username == "" {
		username = r.FormValue("user")
	}
	if username == "" {
		username = r.FormValue("login")
	}
	password := r.FormValue("password")
	if password == "" {
		password = r.FormValue("pass")
	}

	artifacts := []*sensorv1.Artifact{}
	if username != "" {
		artifacts = append(artifacts, &sensorv1.Artifact{
			ArtifactType: "username",
			Value:        []byte(username),
			Encoding:     "utf8",
		})
	}
	if password != "" {
		artifacts = append(artifacts, &sensorv1.Artifact{
			ArtifactType: "password",
			Value:        []byte(password),
			Encoding:     "utf8",
		})
	}

	result := s.brute.Record(sourceIP, username, password)

	if result.Allowed {
		// ── Rabbit hole: deceptive login success ──────────────────────────────
		meta := map[string]string{
			"username":    username,
			"path":        r.URL.Path,
			"first_entry": fmt.Sprintf("%v", result.FirstEntry),
			"brute_force": "true",
		}

		evType := sensorv1.EventType_HMI_LOGIN_SUCCESS
		if result.FirstEntry {
			evType = sensorv1.EventType_HMI_LOGIN_SUCCESS // Rabbit hole opened
		}

		s.emitEvent(evType, sensorv1.Severity_SEVERITY_HIGH,
			fmt.Sprintf("HMI deceptive login granted for '%s' after brute-force (rabbit hole)", username),
			sourceIP, r, artifacts, meta)

		// Redirect to fake dashboard
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    uuid.New().String(),
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   3600,
		})
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Standard failed login
	s.emitEvent(sensorv1.EventType_HMI_LOGIN_ATTEMPT, sensorv1.Severity_SEVERITY_MEDIUM,
		fmt.Sprintf("HMI login attempt: user='%s'", username),
		sourceIP, r, artifacts, map[string]string{
			"username": username,
			"path":     r.URL.Path,
			"attempt":  fmt.Sprintf("%d", s.brute.AttemptCount(sourceIP)),
		})

	// Return realistic "invalid credentials" page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(loginPageHTML(s.cfg, "Invalid username or password.")))
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request, sourceIP string, cls *Classification) {
	s.emitClassifiedEvent(sensorv1.EventType_HMI_ACCESS, cls, sourceIP, r, nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loginPageHTML(s.cfg, "")))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, sourceIP string, cls *Classification) {
	// Only allow if in rabbit hole
	if !s.brute.IsAllowed(sourceIP) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.emitEvent(sensorv1.EventType_HMI_DASHBOARD_ACCESS, sensorv1.Severity_SEVERITY_HIGH,
		"Attacker engaged with fake HMI dashboard (rabbit hole active)",
		sourceIP, r, nil, map[string]string{"rabbit_hole": "active"})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardPageHTML(s.cfg)))
}

func (s *Server) handleGeneric(w http.ResponseWriter, r *http.Request, sourceIP string, cls *Classification) {
	evType, severity := cls.ToEventType()
	s.emitClassifiedEvent(evType, cls, sourceIP, r, nil)

	// Realistic response based on path/classification
	switch {
	case cls.Type == ClassSensitivePath || cls.Type == ClassAdmin:
		w.Header().Set("WWW-Authenticate", `Basic realm="WinCC"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(errorPageHTML(s.cfg, 401, "Unauthorized")))
		_ = severity

	case cls.Type == ClassSQLi || cls.Type == ClassXSS || cls.Type == ClassCmdInj || cls.Type == ClassPathTraversal:
		// Attacker gets a 400 — realistic for a web app that validates input
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(errorPageHTML(s.cfg, 400, "Bad Request")))

	default:
		// Generic 404
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(errorPageHTML(s.cfg, 404, "Page Not Found")))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// OWASP Classifier
// ─────────────────────────────────────────────────────────────────────────────

type ClassType int

const (
	ClassGeneric       ClassType = iota
	ClassLogin
	ClassSQLi
	ClassXSS
	ClassCmdInj
	ClassPathTraversal
	ClassSensitivePath
	ClassAdmin
	ClassScanner
)

type Classification struct {
	Type    ClassType
	Label   string
	Detail  string
	Payload string
}

type OWASPClassifier struct {
	sqliPatterns      []string
	xssPatterns       []string
	cmdInjPatterns    []string
	traversalPatterns []string
	sensitivePaths    []string
	scannerUAs        []string
}

func NewOWASPClassifier() *OWASPClassifier {
	return &OWASPClassifier{
		sqliPatterns: []string{
			"'", "\"", "1=1", "1 =1", "or 1", "union select", "union all",
			"select ", "insert ", "update ", "delete ", "drop table",
			"information_schema", "xp_cmdshell", "exec(", "execute(",
			"sleep(", "waitfor delay", "benchmark(", "load_file(",
			"outfile", "dumpfile", "char(", "concat(", "group_concat(",
			"0x", "0X", "hex(", "unhex(", "md5(", "--", "#", "/*",
		},
		xssPatterns: []string{
			"<script", "</script>", "javascript:", "onerror=", "onload=",
			"onclick=", "onmouseover=", "onfocus=", "alert(", "confirm(",
			"prompt(", "document.cookie", "document.write", "innerHTML",
			"eval(", "fromcharcode", "&#x", "&#", "%3cscript", "%3c/script",
		},
		cmdInjPatterns: []string{
			"; ls", "| ls", "| id", "; id", "; cat", "| cat",
			"&& ls", "|| ls", "`id`", "$(id)", "$(cat", ";wget",
			"|wget", "; curl", "| curl", "| nc ", "; nc ", "bash -i",
			"/bin/sh", "/bin/bash", "cmd.exe", "powershell",
		},
		traversalPatterns: []string{
			"../", "..\\", ".././", "%2e%2e%2f", "%2e%2e/", "..%2f",
			"%252e%252e", "..%5c", "%2e.", "....//", "..;/",
			"/etc/passwd", "/etc/shadow", "/windows/system32",
			"boot.ini", "win.ini", "web.config", ".htaccess",
		},
		sensitivePaths: []string{
			"/admin", "/wp-admin", "/wp-login", "/phpmyadmin", "/pma",
			"/.git", "/.env", "/config", "/backup", "/db", "/database",
			"/api/admin", "/console", "/manager", "/actuator",
			"/metrics", "/.well-known", "/robots.txt", "/sitemap.xml",
			"/server-status", "/server-info",
		},
		scannerUAs: []string{
			"sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei",
			"shodan", "censys", "zmap", "python-requests", "go-http",
			"curl/", "wget/", "scanner", "crawler", "spider",
		},
	}
}

func (c *OWASPClassifier) Classify(r *http.Request) *Classification {
	path    := strings.ToLower(r.URL.Path)
	query   := strings.ToLower(r.URL.RawQuery)
	ua      := strings.ToLower(r.Header.Get("User-Agent"))
	body := ""
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil && len(bodyBytes) > 0 {
			body = strings.ToLower(string(bodyBytes))
			// Restore so downstream handlers (e.g. ParseForm) can still read it
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}
	rawPayload := query
	if rawPayload == "" {
		rawPayload = body
	}
	combined := path + " " + query + " " + body

	// Scanner detection
	for _, pattern := range c.scannerUAs {
		if strings.Contains(ua, pattern) {
			return &Classification{
				Type:    ClassScanner,
				Label:   "scanner_detected",
				Detail:  fmt.Sprintf("Known scanner UA: %s", ua),
				Payload: ua,
			}
		}
	}

	// SQLi
	for _, pattern := range c.sqliPatterns {
		if strings.Contains(combined, pattern) {
			return &Classification{
				Type:    ClassSQLi,
				Label:   "sqli_probe",
				Detail:  fmt.Sprintf("SQL injection pattern detected: '%s'", pattern),
				Payload: rawPayload,
			}
		}
	}

	// XSS
	for _, pattern := range c.xssPatterns {
		if strings.Contains(combined, pattern) {
			return &Classification{
				Type:    ClassXSS,
				Label:   "xss_probe",
				Detail:  fmt.Sprintf("XSS pattern detected: '%s'", pattern),
				Payload: rawPayload,
			}
		}
	}

	// Command injection
	for _, pattern := range c.cmdInjPatterns {
		if strings.Contains(combined, pattern) {
			return &Classification{
				Type:    ClassCmdInj,
				Label:   "command_injection",
				Detail:  fmt.Sprintf("Command injection pattern: '%s'", pattern),
				Payload: rawPayload,
			}
		}
	}

	// Path traversal
	for _, pattern := range c.traversalPatterns {
		if strings.Contains(combined, pattern) {
			return &Classification{
				Type:    ClassPathTraversal,
				Label:   "path_traversal",
				Detail:  fmt.Sprintf("Path traversal pattern: '%s'", pattern),
				Payload: path,
			}
		}
	}

	// Sensitive path
	for _, sp := range c.sensitivePaths {
		if strings.HasPrefix(path, sp) {
			return &Classification{
				Type:   ClassSensitivePath,
				Label:  "sensitive_path",
				Detail: fmt.Sprintf("Sensitive path accessed: %s", path),
				Payload: path,
			}
		}
	}

	return &Classification{Type: ClassGeneric, Label: "hmi_access", Detail: "Generic HMI access"}
}

func (cls *Classification) ToEventType() (sensorv1.EventType, sensorv1.Severity) {
	switch cls.Type {
	case ClassSQLi:
		return sensorv1.EventType_HMI_SQLI_PROBE, sensorv1.Severity_SEVERITY_HIGH
	case ClassXSS:
		return sensorv1.EventType_HMI_XSS_PROBE, sensorv1.Severity_SEVERITY_MEDIUM
	case ClassCmdInj:
		return sensorv1.EventType_HMI_CMD_INJECTION, sensorv1.Severity_SEVERITY_HIGH
	case ClassPathTraversal:
		return sensorv1.EventType_HMI_PATH_TRAVERSAL, sensorv1.Severity_SEVERITY_HIGH
	case ClassSensitivePath, ClassAdmin:
		return sensorv1.EventType_HMI_SENSITIVE_PATH, sensorv1.Severity_SEVERITY_MEDIUM
	case ClassScanner:
		return sensorv1.EventType_HMI_SCANNER_DETECTED, sensorv1.Severity_SEVERITY_LOW
	default:
		return sensorv1.EventType_HMI_ACCESS, sensorv1.Severity_SEVERITY_LOW
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Brute-Force Tracker
// ─────────────────────────────────────────────────────────────────────────────

type LoginResult struct {
	Allowed    bool
	Deceptive  bool
	FirstEntry bool
}

type BruteForceTracker struct {
	mu        sync.Mutex
	attempts  map[string]int
	allowed   map[string]bool
	threshold int
}

func NewBruteForceTracker(threshold int) *BruteForceTracker {
	return &BruteForceTracker{
		attempts:  make(map[string]int),
		allowed:   make(map[string]bool),
		threshold: threshold,
	}
}

func (b *BruteForceTracker) Record(sourceIP, username, password string) LoginResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.attempts[sourceIP]++

	if b.allowed[sourceIP] {
		return LoginResult{Allowed: true, Deceptive: true}
	}

	// Check for special "always allow" credentials (common default creds)
	// that real HMIs often have — adds realism
	alwaysAllow := map[string]string{
		"admin":    "admin",
		"operator": "operator",
		"simatic":  "simatic",
		"wincc":    "wincc",
		"guest":    "guest",
	}
	if expected, ok := alwaysAllow[strings.ToLower(username)]; ok && password == expected {
		b.allowed[sourceIP] = true
		return LoginResult{Allowed: true, Deceptive: true, FirstEntry: true}
	}

	if b.attempts[sourceIP] >= b.threshold {
		b.allowed[sourceIP] = true
		return LoginResult{Allowed: true, Deceptive: true, FirstEntry: true}
	}

	return LoginResult{Allowed: false}
}

func (b *BruteForceTracker) IsAllowed(sourceIP string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allowed[sourceIP]
}

func (b *BruteForceTracker) AttemptCount(sourceIP string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempts[sourceIP]
}

// ─────────────────────────────────────────────────────────────────────────────
// Event emission helpers
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) emitClassifiedEvent(evType sensorv1.EventType, cls *Classification, sourceIP string, r *http.Request, artifacts []*sensorv1.Artifact) {
	_, severity := cls.ToEventType()
	if evType == sensorv1.EventType_HMI_ACCESS {
		severity = sensorv1.Severity_SEVERITY_LOW
	}

	meta := map[string]string{
		"method":         r.Method,
		"path":           r.URL.Path,
		"query":          r.URL.RawQuery,
		"user_agent":     r.Header.Get("User-Agent"),
		"host":           r.Host,
		"classification": cls.Label,
		"detail":         cls.Detail,
	}
	if cls.Payload != "" {
		artifacts = append(artifacts, &sensorv1.Artifact{
			ArtifactType: "http_probe",
			Value:        []byte(cls.Payload),
			Encoding:     "utf8",
		})
	}

	s.emitEvent(evType, severity,
		fmt.Sprintf("[%s] %s %s — %s", cls.Label, r.Method, r.URL.Path, cls.Detail),
		sourceIP, r, artifacts, meta)
}

func (s *Server) emitEvent(evType sensorv1.EventType, severity sensorv1.Severity, summary, sourceIP string, r *http.Request, artifacts []*sensorv1.Artifact, meta map[string]string) {
	addr := r.RemoteAddr
	_, port, _ := net.SplitHostPort(addr)
	srcPort := int32(0)
	fmt.Sscan(port, &srcPort)

	protocol := sensorv1.Protocol_PROTOCOL_HTTP
	if r.TLS != nil {
		protocol = sensorv1.Protocol_PROTOCOL_HTTPS
	}
	dstPort := int32(s.cfg.HMIHTTPPort)
	if r.TLS != nil {
		dstPort = int32(s.cfg.HMIHTTPSPort)
	}

	s.dispatcher.Emit(&sensorv1.SensorEvent{
		SensorId:    s.cfg.SensorID,
		EventId:     uuid.New().String(),
		Timestamp:   timestamppb.Now(),
		SourceIp:    sourceIP,
		SourcePort:  srcPort,
		DstPort:     dstPort,
		Protocol:    protocol,
		EventType:   evType,
		Severity:    severity,
		RawSummary:  summary,
		Metadata:    meta,
		Artifacts:   artifacts,
		SessionHint: fmt.Sprintf("%s:%d:http", sourceIP, srcPort),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS helpers
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	var certPEM, keyPEM []byte

	if s.cfg.HMITLSCertPEM != "" && s.cfg.HMITLSKeyPEM != "" {
		certPEM = []byte(s.cfg.HMITLSCertPEM)
		keyPEM  = []byte(s.cfg.HMITLSKeyPEM)
	} else {
		// Auto-generate self-signed cert
		var err error
		certPEM, keyPEM, err = generateSelfSignedCert(s.cfg.HMIPlantName)
		if err != nil {
			return nil, err
		}
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Prefer server cipher suites for consistency
		PreferServerCipherSuites: true,
	}, nil
}

func generateSelfSignedCert(plantName string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"Siemens AG"},
			OrganizationalUnit: []string{"SIMATIC"},
			CommonName:         plantName,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Route helpers
// ─────────────────────────────────────────────────────────────────────────────

func isLoginPath(path string) bool {
	p := strings.ToLower(path)
	return p == "/" || p == "/login" || p == "/signin" || p == "/auth" || strings.HasPrefix(p, "/login")
}

func isDashboardPath(path string) bool {
	p := strings.ToLower(path)
	return strings.HasPrefix(p, "/dashboard") || strings.HasPrefix(p, "/hmi") || strings.HasPrefix(p, "/scada")
}

func extractIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML Templates
// ─────────────────────────────────────────────────────────────────────────────

func loginPageHTML(cfg *config.SensorConfig, errMsg string) string {
	errBlock := ""
	if errMsg != "" {
		errBlock = fmt.Sprintf(`<div class="error">%s</div>`, errMsg)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s - Login</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: "Segoe UI", Arial, sans-serif; background: #1a1a2e; color: #eee; display: flex; align-items: center; justify-content: center; height: 100vh; }
.container { background: #16213e; border: 1px solid #0f3460; border-radius: 4px; padding: 40px; width: 380px; }
.logo { text-align: center; margin-bottom: 24px; }
.logo img { width: 48px; }
h1 { color: #00a8ff; font-size: 18px; margin-bottom: 4px; }
.subtitle { color: #888; font-size: 12px; margin-bottom: 24px; }
label { display: block; font-size: 12px; color: #aaa; margin-bottom: 4px; }
input { width: 100%%; background: #0d1b2a; border: 1px solid #333; color: #eee; padding: 10px; border-radius: 3px; margin-bottom: 16px; font-size: 14px; }
input:focus { outline: none; border-color: #00a8ff; }
button { width: 100%%; background: #0f3460; color: white; border: none; padding: 12px; border-radius: 3px; cursor: pointer; font-size: 14px; }
button:hover { background: #00a8ff; }
.error { background: #3d1c1c; border: 1px solid #7b2c2c; color: #ff6b6b; padding: 10px; border-radius: 3px; margin-bottom: 16px; font-size: 13px; }
.footer { text-align: center; font-size: 11px; color: #555; margin-top: 24px; }
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <h1>%s</h1>
    <div class="subtitle">%s | Operator Login</div>
  </div>
  %s
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" autocomplete="username" required>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer">%s &copy; Siemens AG. All rights reserved.</div>
</div>
</body>
</html>`, cfg.HMIBrandName, cfg.HMIBrandName, cfg.HMIPlantName, errBlock, cfg.HMIBrandName)
}

func dashboardPageHTML(cfg *config.SensorConfig) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>%s - Dashboard</title>
<meta http-equiv="refresh" content="30">
<style>
body { font-family: "Segoe UI", Arial, sans-serif; background: #1a1a2e; color: #eee; margin: 0; }
.header { background: #0f3460; padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; }
h1 { color: #00a8ff; font-size: 16px; }
.content { padding: 24px; }
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
.card { background: #16213e; border: 1px solid #0f3460; border-radius: 4px; padding: 16px; }
.card-title { font-size: 11px; color: #888; text-transform: uppercase; margin-bottom: 8px; }
.card-value { font-size: 28px; font-weight: bold; color: #00a8ff; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
.tag.running { background: #1a3a1a; color: #4caf50; }
.tag.stopped { background: #3a1a1a; color: #f44336; }
.table { background: #16213e; border: 1px solid #0f3460; border-radius: 4px; width: 100%%; border-collapse: collapse; }
.table th, .table td { padding: 10px 16px; text-align: left; font-size: 13px; border-bottom: 1px solid #0f3460; }
.table th { color: #888; font-size: 11px; text-transform: uppercase; }
.status { font-size: 11px; color: #555; margin-top: 16px; }
</style>
</head>
<body>
<div class="header">
  <h1>%s — %s</h1>
  <span class="tag running">● ONLINE</span>
</div>
<div class="content">
  <div class="cards">
    <div class="card"><div class="card-title">CPU Load</div><div class="card-value">12%%</div></div>
    <div class="card"><div class="card-title">Memory</div><div class="card-value">847 MB</div></div>
    <div class="card"><div class="card-title">PLC Status</div><div class="card-value" style="font-size:16px;padding-top:6px"><span class="tag running">RUN</span></div></div>
    <div class="card"><div class="card-title">Alarms</div><div class="card-value" style="color:#f44336">3</div></div>
  </div>
  <table class="table">
    <thead><tr><th>Tag</th><th>Value</th><th>Unit</th><th>Status</th><th>Timestamp</th></tr></thead>
    <tbody>
      <tr><td>TANK_LVL_01</td><td>73.4</td><td>%%</td><td><span class="tag running">OK</span></td><td>%s</td></tr>
      <tr><td>PUMP_01_RPM</td><td>1450</td><td>rpm</td><td><span class="tag running">OK</span></td><td>%s</td></tr>
      <tr><td>VALVE_02</td><td>OPEN</td><td>—</td><td><span class="tag running">OK</span></td><td>%s</td></tr>
      <tr><td>TEMP_HX_01</td><td>84.2</td><td>°C</td><td><span class="tag stopped">ALARM</span></td><td>%s</td></tr>
      <tr><td>PRESSURE_01</td><td>3.21</td><td>bar</td><td><span class="tag running">OK</span></td><td>%s</td></tr>
    </tbody>
  </table>
  <div class="status">Last refresh: %s | Read-only view</div>
</div>
</body>
</html>`,
		cfg.HMIBrandName, cfg.HMIBrandName, cfg.HMIPlantName,
		time.Now().Format("15:04:05"),
		time.Now().Format("15:04:05"),
		time.Now().Format("15:04:05"),
		time.Now().Add(-5*time.Minute).Format("15:04:05"),
		time.Now().Format("15:04:05"),
		time.Now().Format("2006-01-02 15:04:05 UTC"),
	)
}

func errorPageHTML(cfg *config.SensorConfig, code int, msg string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>%d %s - %s</title>
<style>body{font-family:Arial,sans-serif;background:#1a1a2e;color:#888;display:flex;align-items:center;justify-content:center;height:100vh;}
.box{text-align:center;}.code{font-size:72px;color:#0f3460;font-weight:bold;}.msg{font-size:16px;margin-top:8px;}.brand{font-size:11px;margin-top:24px;color:#444;}</style>
</head><body><div class="box"><div class="code">%d</div><div class="msg">%s</div>
<div class="brand">%s</div></div></body></html>`, code, msg, cfg.HMIBrandName, code, msg, cfg.HMIBrandName)
}
