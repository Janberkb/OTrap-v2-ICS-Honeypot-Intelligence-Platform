// internal/protocols/enip/server.go — EtherNet/IP decoy server (Allen-Bradley / Rockwell)
//
// Emulates a Rockwell Automation 1769-L33ER CompactLogix PLC on TCP 44818.
// Responds to the most common EtherNet/IP encapsulation commands:
//   - ListIdentity   (0x0063) — device scanner probe
//   - ListServices   (0x0004) — service enumeration
//   - RegisterSession (0x0065) — session establishment
//   - UnRegisterSession (0x0066) — session teardown
//   - SendRRData     (0x006F) — CIP explicit messaging (Read/WriteTag, GetAttr…)
//
// All other commands return a generic error response and emit an alert.
package enip

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/otrap/sensor/internal/config"
	"github.com/otrap/sensor/internal/dispatch"
	"github.com/otrap/sensor/internal/health"
	sensorv1 "github.com/otrap/sensor/proto/sensorv1"
)

// EtherNet/IP encapsulation header is always 24 bytes (little-endian fields).
const (
	encapHeaderLen = 24
	readTimeout    = 60 * time.Second
	writeTimeout   = 5 * time.Second

	// EtherNet/IP command codes
	cmdNOP               = 0x0001
	cmdListServices      = 0x0004
	cmdListIdentity      = 0x0063
	cmdListInterfaces    = 0x0064
	cmdRegisterSession   = 0x0065
	cmdUnRegisterSession = 0x0066
	cmdSendRRData        = 0x006F
	cmdSendUnitData      = 0x0070

	// CIP service codes (inside SendRRData payload)
	cipGetAttrAll    = 0x01
	cipGetAttrSingle = 0x0E
	cipSetAttrSingle = 0x10
	cipReadTag       = 0x4C
	cipWriteTag      = 0x4D
	cipReadTagFrag   = 0x4E
	cipWriteTagFrag  = 0x4F

	// Fake session handle issued to clients
	fakeSessionHandle = uint32(0xDEADC0DE)
)

// Fake CompactLogix identity (1769-L33ER/B LOGIX5333ER).
// Passes basic fingerprint checks from nmap, SCAPY, and Metasploit CIP modules.
var (
	productName = []byte("1769-L33ER/B LOGIX5333ER")
	vendorID    = uint16(0x0001) // Rockwell Automation
	deviceType  = uint16(0x000E) // Programmable Logic Controller
	productCode = uint16(0x0059) // CompactLogix L33ER
	revMajor    = byte(20)
	revMinor    = byte(11)
	plcStatus   = uint16(0x0030) // Running
	serialNum   = uint32(0xA1B2C3D4)
)

// Server listens on TCP 44818 and spawns a handler per connection.
type Server struct {
	cfg        *config.SensorConfig
	dispatcher *dispatch.Dispatcher
	health     *health.Tracker
}

func NewServer(cfg *config.SensorConfig, d *dispatch.Dispatcher, h *health.Tracker) *Server {
	return &Server{cfg: cfg, dispatcher: d, health: h}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.ENIPPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("enip listen %s: %w", addr, err)
	}
	defer ln.Close()

	s.health.SetPortStatus(s.cfg.ENIPPort, true)
	slog.Info("EtherNet/IP honeypot listening", "addr", addr)

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Warn("EtherNet/IP accept error", "error", err)
				continue
			}
		}
		s.health.IncrConn(s.cfg.ENIPPort)
		go func() {
			defer s.health.DecrConn(s.cfg.ENIPPort)
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	addr := conn.RemoteAddr().(*net.TCPAddr)
	remoteIP   := addr.IP.String()
	remotePort := addr.Port
	sessionKey := fmt.Sprintf("%s:%d:enip", remoteIP, remotePort)

	// No initial connect event — wait for the first command to see what they do.

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read encapsulation header (24 bytes, always present)
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		header := make([]byte, encapHeaderLen)
		if _, err := io.ReadFull(conn, header); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.emitEvent(sensorv1.EventType_ENIP_SESSION_TIMEOUT, sensorv1.Severity_SEVERITY_NOISE,
					"EtherNet/IP session idle timeout", remoteIP, remotePort, sessionKey, nil, nil)
			}
			return
		}

		cmd    := binary.LittleEndian.Uint16(header[0:2])
		length := binary.LittleEndian.Uint16(header[2:4])
		// session := binary.LittleEndian.Uint32(header[4:8]) // echoed back
		ctx8 := header[12:20] // sender context (8 bytes), echoed back

		// Read payload
		var payload []byte
		if length > 0 {
			if length > 4096 {
				return // Protect against absurd lengths
			}
			payload = make([]byte, length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}

		rawPacket := append(header, payload...)
		resp := s.handleCommand(cmd, payload, ctx8, remoteIP, remotePort, sessionKey, rawPacket)
		if resp != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, err := conn.Write(resp); err != nil {
				return
			}
		}
	}
}

// handleCommand dispatches an EtherNet/IP command and returns the response frame.
func (s *Server) handleCommand(
	cmd uint16, payload, ctx8 []byte,
	remoteIP string, remotePort int, sessionKey string, rawPacket []byte,
) []byte {
	switch cmd {
	case cmdNOP:
		// NOP — no response required, no event
		return nil

	case cmdListIdentity:
		s.emitEvent(sensorv1.EventType_ENIP_LIST_IDENTITY, sensorv1.Severity_SEVERITY_LOW,
			fmt.Sprintf("EtherNet/IP ListIdentity from %s (scanner probe)", remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket, nil)
		return s.buildListIdentityResponse(ctx8)

	case cmdListServices:
		s.emitEvent(sensorv1.EventType_ENIP_LIST_SERVICES, sensorv1.Severity_SEVERITY_LOW,
			fmt.Sprintf("EtherNet/IP ListServices from %s", remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket, nil)
		return s.buildListServicesResponse(ctx8)

	case cmdListInterfaces:
		// Reply with empty item list — no interfaces exposed
		return s.buildEncapHeader(cmdListInterfaces, ctx8, []byte{0x00, 0x00}) // item count = 0

	case cmdRegisterSession:
		s.emitEvent(sensorv1.EventType_ENIP_REGISTER_SESSION, sensorv1.Severity_SEVERITY_MEDIUM,
			fmt.Sprintf("EtherNet/IP RegisterSession from %s", remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket, nil)
		// Respond with assigned session handle and protocol version 1
		data := make([]byte, 4)
		binary.LittleEndian.PutUint16(data[0:], 1) // Protocol version
		binary.LittleEndian.PutUint16(data[2:], 0) // Options flags
		return s.buildEncapHeaderWithSession(cmdRegisterSession, fakeSessionHandle, 0, ctx8, data)

	case cmdUnRegisterSession:
		// No response required for UnRegister
		return nil

	case cmdSendRRData:
		return s.handleSendRRData(payload, ctx8, remoteIP, remotePort, sessionKey, rawPacket)

	default:
		s.emitEvent(sensorv1.EventType_ENIP_UNKNOWN_COMMAND, sensorv1.Severity_SEVERITY_MEDIUM,
			fmt.Sprintf("EtherNet/IP unknown command 0x%04X from %s", cmd, remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket, nil)
		// Return encap error response (status = 0x0001: invalid command)
		return s.buildEncapHeaderWithSession(cmd, 0, 0x0001, ctx8, nil)
	}
}

// handleSendRRData parses the CPF packet and dispatches CIP service codes.
func (s *Server) handleSendRRData(
	payload, ctx8 []byte,
	remoteIP string, remotePort int, sessionKey string, rawPacket []byte,
) []byte {
	// SendRRData payload: Interface Handle (4) + Timeout (2) + CPF item count (2) + items
	if len(payload) < 10 {
		return s.buildEncapHeaderWithSession(cmdSendRRData, fakeSessionHandle, 0x0065, ctx8, nil)
	}

	itemCount := binary.LittleEndian.Uint16(payload[6:8])
	if itemCount < 2 {
		return s.buildEncapHeaderWithSession(cmdSendRRData, fakeSessionHandle, 0x0065, ctx8, nil)
	}

	// Skip Null Address Item (type=0x0000, len=0): 4 bytes
	// Then read Unconnected Data Item (type=0x00B2): type(2)+len(2)+data
	offset := 8
	if offset+4 > len(payload) {
		return nil
	}
	// Skip address item (usually 4 bytes: type=0x0000, length=0x0000)
	offset += 4
	if offset+4 > len(payload) {
		return nil
	}
	// dataItemType := binary.LittleEndian.Uint16(payload[offset:])
	dataItemLen := binary.LittleEndian.Uint16(payload[offset+2:])
	offset += 4
	if offset+int(dataItemLen) > len(payload) {
		return nil
	}
	cipData := payload[offset : offset+int(dataItemLen)]
	if len(cipData) < 1 {
		return nil
	}

	cipService := cipData[0] & 0x7F // mask off response bit

	switch cipService {
	case cipReadTag, cipReadTagFrag:
		s.emitEvent(sensorv1.EventType_ENIP_CIP_READ_TAG, sensorv1.Severity_SEVERITY_MEDIUM,
			fmt.Sprintf("CIP ReadTag from %s — ControlLogix tag read", remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket, nil)
		return s.buildCIPErrorResponse(ctx8, cipService, 0x08) // path segment error — tag not found

	case cipWriteTag, cipWriteTagFrag:
		s.emitEvent(sensorv1.EventType_ENIP_CIP_WRITE_TAG, sensorv1.Severity_SEVERITY_HIGH,
			fmt.Sprintf("CIP WriteTag from %s — ControlLogix tag WRITE attempt", remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket,
			[]*sensorv1.Artifact{{
				ArtifactType: "enip_payload",
				Value:        rawPacket,
				Encoding:     "hex",
			}})
		return s.buildCIPErrorResponse(ctx8, cipService, 0x08)

	case cipGetAttrAll, cipGetAttrSingle:
		s.emitEvent(sensorv1.EventType_ENIP_CIP_GET_ATTR, sensorv1.Severity_SEVERITY_LOW,
			fmt.Sprintf("CIP GetAttribute from %s — device attribute enumeration", remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket, nil)
		return s.buildCIPErrorResponse(ctx8, cipService, 0x08)

	case cipSetAttrSingle:
		s.emitEvent(sensorv1.EventType_ENIP_CIP_SET_ATTR, sensorv1.Severity_SEVERITY_HIGH,
			fmt.Sprintf("CIP SetAttribute from %s — attribute modification attempt", remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket,
			[]*sensorv1.Artifact{{
				ArtifactType: "enip_payload",
				Value:        rawPacket,
				Encoding:     "hex",
			}})
		return s.buildCIPErrorResponse(ctx8, cipService, 0x08)

	default:
		s.emitEvent(sensorv1.EventType_ENIP_SEND_RRDATA, sensorv1.Severity_SEVERITY_MEDIUM,
			fmt.Sprintf("CIP service 0x%02X from %s", cipService, remoteIP),
			remoteIP, remotePort, sessionKey, rawPacket, nil)
		return s.buildCIPErrorResponse(ctx8, cipService, 0x08)
	}
}

// ─── Response builders ─────────────────────────────────────────────────────

// buildEncapHeader builds a standard 24-byte EtherNet/IP encapsulation header.
func (s *Server) buildEncapHeader(cmd uint16, ctx8 []byte, data []byte) []byte {
	return s.buildEncapHeaderWithSession(cmd, 0, 0, ctx8, data)
}

func (s *Server) buildEncapHeaderWithSession(cmd uint16, sessionHandle uint32, status uint32, ctx8 []byte, data []byte) []byte {
	frame := make([]byte, encapHeaderLen+len(data))
	binary.LittleEndian.PutUint16(frame[0:], cmd)
	binary.LittleEndian.PutUint16(frame[2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(frame[4:], sessionHandle)
	binary.LittleEndian.PutUint32(frame[8:], status)
	if len(ctx8) >= 8 {
		copy(frame[12:20], ctx8[:8])
	}
	binary.LittleEndian.PutUint32(frame[20:], 0) // Options = 0
	copy(frame[encapHeaderLen:], data)
	return frame
}

// buildListIdentityResponse builds a ListIdentity response CPF packet.
func (s *Server) buildListIdentityResponse(ctx8 []byte) []byte {
	// Build identity item data
	item := make([]byte, 0, 40)

	// Protocol version (2 LE)
	item = appendU16LE(item, 1)

	// Socket address (16 bytes, big-endian for sin_family and sin_port)
	sockAddr := make([]byte, 16)
	binary.BigEndian.PutUint16(sockAddr[0:], 2)     // AF_INET
	binary.BigEndian.PutUint16(sockAddr[2:], 44818) // port
	// sin_addr and sin_zero all zero
	item = append(item, sockAddr...)

	item = appendU16LE(item, vendorID)
	item = appendU16LE(item, deviceType)
	item = appendU16LE(item, productCode)
	item = append(item, revMajor, revMinor)
	item = appendU16LE(item, plcStatus)
	item = appendU32LE(item, serialNum)
	item = append(item, byte(len(productName)))
	item = append(item, productName...)
	item = append(item, 0xFF) // State: running

	// CPF packet: item count (2) + type (2) + length (2) + item data
	cpf := make([]byte, 0, 6+len(item))
	cpf = appendU16LE(cpf, 1)           // item count
	cpf = appendU16LE(cpf, 0x000C)     // CIP Identity item type
	cpf = appendU16LE(cpf, uint16(len(item)))
	cpf = append(cpf, item...)

	return s.buildEncapHeader(cmdListIdentity, ctx8, cpf)
}

// buildListServicesResponse announces CIP encapsulation support.
func (s *Server) buildListServicesResponse(ctx8 []byte) []byte {
	svcName := [16]byte{}
	copy(svcName[:], "Communications")

	item := make([]byte, 0, 20)
	item = appendU16LE(item, 1)      // Protocol version
	item = appendU16LE(item, 0x00C0) // Capability: CIP encap + class 1 UDP
	item = append(item, svcName[:]...)

	cpf := make([]byte, 0, 6+len(item))
	cpf = appendU16LE(cpf, 1)       // item count
	cpf = appendU16LE(cpf, 0x0100) // CIP Service Port item type
	cpf = appendU16LE(cpf, uint16(len(item)))
	cpf = append(cpf, item...)

	return s.buildEncapHeader(cmdListServices, ctx8, cpf)
}

// buildCIPErrorResponse wraps a CIP error in a SendRRData CPF packet.
func (s *Server) buildCIPErrorResponse(ctx8 []byte, service byte, generalStatus byte) []byte {
	// CIP error response: service | 0x80 (1) + reserved (1) + general status (1) + add'l status size (1)
	cipResp := []byte{service | 0x80, 0x00, generalStatus, 0x00}

	// CPF: interface handle (4) + timeout (2) + item count (2) +
	//      null addr item (4) + data item header (4) + CIP data
	cpf := make([]byte, 0, 16+len(cipResp))
	cpf = appendU32LE(cpf, 0)            // Interface handle
	cpf = appendU16LE(cpf, 0)            // Timeout
	cpf = appendU16LE(cpf, 2)            // Item count
	cpf = appendU16LE(cpf, 0x0000)      // Null address item type
	cpf = appendU16LE(cpf, 0)            // Null address length = 0
	cpf = appendU16LE(cpf, 0x00B2)      // Unconnected data item type
	cpf = appendU16LE(cpf, uint16(len(cipResp)))
	cpf = append(cpf, cipResp...)

	return s.buildEncapHeaderWithSession(cmdSendRRData, fakeSessionHandle, 0, ctx8, cpf)
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func appendU16LE(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendU32LE(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// ─── Event emission ────────────────────────────────────────────────────────

func (s *Server) emitEvent(
	evType sensorv1.EventType, sev sensorv1.Severity, summary string,
	remoteIP string, remotePort int, sessionKey string,
	rawPacket []byte, artifacts []*sensorv1.Artifact,
) {
	meta := map[string]string{
		"vendor":       "Rockwell Automation",
		"product_name": string(productName),
	}
	s.dispatcher.Emit(&sensorv1.SensorEvent{
		SensorId:    s.cfg.SensorID,
		EventId:     uuid.New().String(),
		Timestamp:   timestamppb.Now(),
		SourceIp:    remoteIP,
		SourcePort:  int32(remotePort),
		DstPort:     int32(s.cfg.ENIPPort),
		Protocol:    sensorv1.Protocol_PROTOCOL_ENIP,
		EventType:   evType,
		Severity:    sev,
		RawSummary:  summary,
		RawPayload:  rawPacket,
		Metadata:    meta,
		Artifacts:   artifacts,
		SessionHint: sessionKey,
	})
}
