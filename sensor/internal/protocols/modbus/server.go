// internal/protocols/modbus/server.go — Modbus/TCP decoy server
package modbus

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

// Modbus/TCP frame constants
const (
	mbapHeaderLen = 6     // Transaction ID(2) + Protocol ID(2) + Length(2)
	maxMBAPLen    = 260   // Max Modbus/TCP frame
	readTimeout   = 60 * time.Second
	writeTimeout  = 5 * time.Second
)

// Modbus function codes
const (
	fcReadCoils          = 0x01
	fcReadDiscreteInputs = 0x02
	fcReadHoldingRegs    = 0x03
	fcReadInputRegs      = 0x04
	fcWriteSingleCoil    = 0x05
	fcWriteSingleReg     = 0x06
	fcWriteMultipleCoils = 0x0F
	fcWriteMultipleRegs  = 0x10
	fcReadFileRecord     = 0x14
	fcMaskWriteReg       = 0x16
	fcReadWriteMultiRegs = 0x17
	fcEncapsulatedTransport = 0x2B // MEI — device identification
)

// Modbus exception codes
const (
	exIllegalFunction    = 0x01
	exIllegalDataAddress = 0x02
	exIllegalDataValue   = 0x03
	exServerDeviceFailure = 0x04
)

// Severity mapping per function code
var fcSeverity = map[byte]sensorv1.Severity{
	fcReadCoils:          sensorv1.Severity_SEVERITY_LOW,
	fcReadDiscreteInputs: sensorv1.Severity_SEVERITY_LOW,
	fcReadHoldingRegs:    sensorv1.Severity_SEVERITY_MEDIUM,
	fcReadInputRegs:      sensorv1.Severity_SEVERITY_LOW,
	fcWriteSingleCoil:    sensorv1.Severity_SEVERITY_HIGH,
	fcWriteSingleReg:     sensorv1.Severity_SEVERITY_HIGH,
	fcWriteMultipleCoils: sensorv1.Severity_SEVERITY_HIGH,
	fcWriteMultipleRegs:  sensorv1.Severity_SEVERITY_HIGH,
}

// Server listens on port 502 and spawns a handler per connection.
type Server struct {
	cfg        *config.SensorConfig
	dispatcher *dispatch.Dispatcher
	health     *health.Tracker
}

func NewServer(cfg *config.SensorConfig, d *dispatch.Dispatcher, h *health.Tracker) *Server {
	return &Server{cfg: cfg, dispatcher: d, health: h}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.ModbusPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("modbus listen %s: %w", addr, err)
	}
	defer ln.Close()

	s.health.SetPortStatus(s.cfg.ModbusPort, true)
	slog.Info("Modbus honeypot listening", "addr", addr)

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Warn("Modbus accept error", "error", err)
				continue
			}
		}
		s.health.IncrConn(s.cfg.ModbusPort)
		go func() {
			defer s.health.DecrConn(s.cfg.ModbusPort)
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	addr := conn.RemoteAddr().(*net.TCPAddr)
	remoteIP   := addr.IP.String()
	remotePort := addr.Port
	sessionKey := fmt.Sprintf("%s:%d:modbus", remoteIP, remotePort)

	s.emit(sensorv1.EventType_MODBUS_CONNECT, sensorv1.Severity_SEVERITY_LOW,
		fmt.Sprintf("Modbus/TCP connection from %s", remoteIP),
		remoteIP, remotePort, sessionKey, nil, nil)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read MBAP header (6 bytes)
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		header := make([]byte, mbapHeaderLen)
		if _, err := io.ReadFull(conn, header); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.emit(sensorv1.EventType_MODBUS_SESSION_TIMEOUT, sensorv1.Severity_SEVERITY_NOISE,
					"Modbus session idle timeout", remoteIP, remotePort, sessionKey, nil, nil)
			}
			return
		}

		transactionID := binary.BigEndian.Uint16(header[0:2])
		protocolID    := binary.BigEndian.Uint16(header[2:4])
		length        := binary.BigEndian.Uint16(header[4:6])

		// Validate: protocol ID must be 0 for Modbus
		if protocolID != 0 {
			slog.Debug("Non-Modbus protocol ID on port 502", "protocol_id", protocolID, "remote", remoteIP)
			return
		}

		if length < 2 || int(length) > maxMBAPLen {
			return
		}

		// Read PDU (unit ID + function code + data)
		pdu := make([]byte, length)
		if _, err := io.ReadFull(conn, pdu); err != nil {
			return
		}

		unitID := pdu[0]
		fc     := pdu[1]
		data   := pdu[2:]

		rawPacket := append(header, pdu...)
		response  := s.dispatch(fc, data, transactionID, unitID, remoteIP, remotePort, sessionKey, rawPacket)

		if response != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, err := conn.Write(response); err != nil {
				return
			}
		}
	}
}

// dispatch routes Modbus function codes and returns the response frame.
func (s *Server) dispatch(
	fc byte, data []byte, txID uint16, unitID byte,
	remoteIP string, remotePort int, sessionKey string, rawPacket []byte,
) []byte {
	switch fc {
	case fcReadCoils:
		s.emitFC(fc, sensorv1.EventType_MODBUS_READ_COILS, "Read Coils",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		return s.buildReadBitsResponse(txID, unitID, fc, data, 0x00)

	case fcReadDiscreteInputs:
		s.emitFC(fc, sensorv1.EventType_MODBUS_READ_DISCRETE, "Read Discrete Inputs",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		return s.buildReadBitsResponse(txID, unitID, fc, data, 0xFF)

	case fcReadHoldingRegs:
		s.emitFC(fc, sensorv1.EventType_MODBUS_READ_HOLDING, "Read Holding Registers",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		return s.buildReadRegsResponse(txID, unitID, fc, data)

	case fcReadInputRegs:
		s.emitFC(fc, sensorv1.EventType_MODBUS_READ_INPUT, "Read Input Registers",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		return s.buildReadRegsResponse(txID, unitID, fc, data)

	case fcWriteSingleCoil:
		s.emitFC(fc, sensorv1.EventType_MODBUS_WRITE_SINGLE_COIL, "Write Single Coil — HIGH SEVERITY",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		// Echo back the request (standard Modbus success response)
		return s.buildMBAP(txID, unitID, append([]byte{fc}, data...))

	case fcWriteSingleReg:
		s.emitFC(fc, sensorv1.EventType_MODBUS_WRITE_SINGLE_REG, "Write Single Register — HIGH SEVERITY",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		return s.buildMBAP(txID, unitID, append([]byte{fc}, data...))

	case fcWriteMultipleCoils:
		s.emitFC(fc, sensorv1.EventType_MODBUS_WRITE_MULTIPLE, "Write Multiple Coils — HIGH SEVERITY",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		if len(data) >= 4 {
			return s.buildMBAP(txID, unitID, []byte{fc, data[0], data[1], data[2], data[3]})
		}
		return s.buildException(txID, unitID, fc, exIllegalDataValue)

	case fcWriteMultipleRegs:
		s.emitFC(fc, sensorv1.EventType_MODBUS_WRITE_MULTIPLE, "Write Multiple Registers — MITRE T0836",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		if len(data) >= 4 {
			return s.buildMBAP(txID, unitID, []byte{fc, data[0], data[1], data[2], data[3]})
		}
		return s.buildException(txID, unitID, fc, exIllegalDataValue)

	case fcEncapsulatedTransport:
		// MEI Device Identification — scanner probe
		s.emitFC(fc, sensorv1.EventType_MODBUS_UNKNOWN_FUNCTION, "MEI Device Identification (scanner probe)",
			remoteIP, remotePort, sessionKey, rawPacket, data)
		// Return basic device identification
		mei := []byte{
			fc, 0x0E, 0x01, 0x01, 0x00, // MEI type, read device id, conformity
			0x00, 0x00, 0x00, 0x03,       // more follows, next obj, reserved, obj count
			0x00, 0x0E, // obj id=VendorName, len=14
		}
		mei = append(mei, []byte("Schneider Electric")...)
		return s.buildMBAP(txID, unitID, mei)

	default:
		s.emit(sensorv1.EventType_MODBUS_UNKNOWN_FUNCTION, sensorv1.Severity_SEVERITY_MEDIUM,
			fmt.Sprintf("Unknown Modbus function code: 0x%02X", fc),
			remoteIP, remotePort, sessionKey, rawPacket, nil)
		return s.buildException(txID, unitID, fc, exIllegalFunction)
	}
}

// ─── Response builders ─────────────────────────────────────────────────────

func (s *Server) buildMBAP(txID uint16, unitID byte, pdu []byte) []byte {
	frame := make([]byte, 6+len(pdu))
	binary.BigEndian.PutUint16(frame[0:], txID)
	binary.BigEndian.PutUint16(frame[2:], 0x0000) // Protocol ID = Modbus
	binary.BigEndian.PutUint16(frame[4:], uint16(1+len(pdu)))
	frame[6] = unitID
	copy(frame[7:], pdu)
	return frame
}

func (s *Server) buildException(txID uint16, unitID, fc, exCode byte) []byte {
	return s.buildMBAP(txID, unitID, []byte{fc | 0x80, exCode})
}

func (s *Server) buildReadBitsResponse(txID uint16, unitID, fc byte, data []byte, fillByte byte) []byte {
	count := uint16(0)
	if len(data) >= 4 {
		count = binary.BigEndian.Uint16(data[2:4])
	}
	if count == 0 || count > 2000 {
		return s.buildException(txID, unitID, fc, exIllegalDataAddress)
	}
	byteCount := (count + 7) / 8
	resp := make([]byte, 2+byteCount)
	resp[0] = fc
	resp[1] = byte(byteCount)
	for i := uint16(0); i < byteCount; i++ {
		resp[2+i] = fillByte
	}
	return s.buildMBAP(txID, unitID, resp)
}

func (s *Server) buildReadRegsResponse(txID uint16, unitID, fc byte, data []byte) []byte {
	count := uint16(0)
	if len(data) >= 4 {
		count = binary.BigEndian.Uint16(data[2:4])
	}
	if count == 0 || count > 125 {
		return s.buildException(txID, unitID, fc, exIllegalDataAddress)
	}
	// Return plausible register values (deterministic based on address)
	startAddr := uint16(0)
	if len(data) >= 2 {
		startAddr = binary.BigEndian.Uint16(data[0:2])
	}
	byteCount := count * 2
	resp := make([]byte, 2+byteCount)
	resp[0] = fc
	resp[1] = byte(byteCount)
	for i := uint16(0); i < count; i++ {
		// Plausible factory-default register values
		val := plausibleRegValue(startAddr + i)
		binary.BigEndian.PutUint16(resp[2+i*2:], val)
	}
	return s.buildMBAP(txID, unitID, resp)
}

// plausibleRegValue returns a deterministic plausible register value.
func plausibleRegValue(addr uint16) uint16 {
	switch {
	case addr < 10:
		return 0x0000 // Status registers: OFF/0
	case addr < 100:
		return 0x0001 // Control registers: 1 (enabled)
	case addr < 1000:
		// Process values: simulate temperatures, pressures in realistic ranges
		base := uint16(100 + (addr%50)*3) // e.g. 100–250 (temperature-like)
		return base
	default:
		return 0x0000
	}
}

// ─── Event emission helpers ────────────────────────────────────────────────

func (s *Server) emitFC(
	fc byte, evType sensorv1.EventType, summary string,
	remoteIP string, remotePort int, sessionKey string,
	rawPacket, data []byte,
) {
	sev := fcSeverity[fc]
	if sev == sensorv1.Severity_SEVERITY_NOISE {
		sev = sensorv1.Severity_SEVERITY_LOW
	}
	meta := map[string]string{"function_code": fmt.Sprintf("0x%02X", fc)}
	if len(data) >= 4 {
		meta["start_address"] = fmt.Sprintf("%d", binary.BigEndian.Uint16(data[0:2]))
		meta["quantity"]      = fmt.Sprintf("%d", binary.BigEndian.Uint16(data[2:4]))
	}
	var artifacts []*sensorv1.Artifact
	if sev >= sensorv1.Severity_SEVERITY_HIGH {
		artifacts = []*sensorv1.Artifact{{
			ArtifactType: "modbus_payload",
			Value:        rawPacket,
			Encoding:     "hex",
		}}
	}
	s.dispatcher.Emit(&sensorv1.SensorEvent{
		SensorId:    s.cfg.SensorID,
		EventId:     uuid.New().String(),
		Timestamp:   timestamppb.Now(),
		SourceIp:    remoteIP,
		SourcePort:  int32(remotePort),
		DstPort:     int32(s.cfg.ModbusPort),
		Protocol:    sensorv1.Protocol_PROTOCOL_MODBUS,
		EventType:   evType,
		Severity:    sev,
		RawSummary:  summary,
		RawPayload:  rawPacket,
		Metadata:    meta,
		Artifacts:   artifacts,
		SessionHint: sessionKey,
	})
}

func (s *Server) emit(
	evType sensorv1.EventType, sev sensorv1.Severity, summary string,
	remoteIP string, remotePort int, sessionKey string,
	rawPacket []byte, artifacts []*sensorv1.Artifact,
) {
	s.dispatcher.Emit(&sensorv1.SensorEvent{
		SensorId:    s.cfg.SensorID,
		EventId:     uuid.New().String(),
		Timestamp:   timestamppb.Now(),
		SourceIp:    remoteIP,
		SourcePort:  int32(remotePort),
		DstPort:     int32(s.cfg.ModbusPort),
		Protocol:    sensorv1.Protocol_PROTOCOL_MODBUS,
		EventType:   evType,
		Severity:    sev,
		RawSummary:  summary,
		RawPayload:  rawPacket,
		Artifacts:   artifacts,
		SessionHint: sessionKey,
	})
}
