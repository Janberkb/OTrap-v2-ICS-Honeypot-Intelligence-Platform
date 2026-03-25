// internal/protocols/s7/handler.go — Stateful S7comm connection handler.
//
// Implements TPKT/COTP/S7comm framing for Siemens S7-300/400 emulation.
// State machine: TCP → COTP_CR → COTP_CC → S7_SETUP → S7_OPERATIONS
package s7

import (
	"context"
	"encoding/binary"
	"encoding/hex"
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

// S7 state machine states
type connState int

const (
	stateInit         connState = iota
	stateCOTPConnected           // COTP CC sent
	stateS7Setup                 // Setup Comm ack sent
	stateOperational             // Full S7 operations
)

// TPKT constants
const (
	tpktVersion  = 0x03
	tpktMinLen   = 4
	maxTPKTLen   = 8192
	maxReadSize  = 4096
)

// COTP PDU types
const (
	cotpCR = 0xE0 // Connection Request
	cotpCC = 0xD0 // Connection Confirm
	cotpDT = 0xF0 // Data Transfer
	cotpER = 0x70 // Error
)

// S7 function codes (rosctr + function combinations)
const (
	s7FuncSetupComm   = 0xF0
	s7FuncReadVar     = 0x04
	s7FuncWriteVar    = 0x05
	s7FuncRequestDownload = 0x1A
	s7FuncDownloadBlock   = 0x1B
	s7FuncEndDownload     = 0x1C
	s7FuncUploadBlock     = 0x1D
	s7FuncEndUpload       = 0x1F
	s7FuncDeleteBlock     = 0x28
	s7FuncControl         = 0x28
	s7FuncUserData        = 0x00
)

// S7 control function sub-functions (for CPU STOP detection)
const (
	s7CpuStopSubfunc   = 0x29
	s7CpuStartSubfunc  = 0x00
)

// S7 ROSCTR values
const (
	s7RosctrJob      = 0x01
	s7RosctrAck      = 0x02
	s7RosctrAckData  = 0x03
	s7RosctrUserData = 0x07
)

// Handler manages a single S7 TCP connection.
type Handler struct {
	conn       net.Conn
	cfg        *config.SensorConfig
	dispatcher *dispatch.Dispatcher
	memory     *MemoryMap
	health     *health.Tracker

	state      connState
	sessionKey string
	remoteIP   string
	remotePort int
	startTime  time.Time
}

func NewHandler(conn net.Conn, cfg *config.SensorConfig, d *dispatch.Dispatcher, m *MemoryMap, h *health.Tracker) *Handler {
	addr := conn.RemoteAddr().(*net.TCPAddr)
	return &Handler{
		conn:       conn,
		cfg:        cfg,
		dispatcher: d,
		memory:     m,
		health:     h,
		state:      stateInit,
		sessionKey: fmt.Sprintf("%s:%d:s7", addr.IP.String(), addr.Port),
		remoteIP:   addr.IP.String(),
		remotePort: addr.Port,
		startTime:  time.Now(),
	}
}

func (h *Handler) Handle(ctx context.Context) {
	defer h.conn.Close()

	slog.Debug("S7 connection accepted", "remote", h.conn.RemoteAddr())
	h.emitEvent(sensorv1.EventType_S7_COTP_CONNECT, sensorv1.Severity_SEVERITY_LOW,
		"S7/COTP connection attempt", nil, nil)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline
		_ = h.conn.SetReadDeadline(time.Now().Add(readTimeout))

		// Read TPKT header (4 bytes)
		tpktHeader := make([]byte, tpktMinLen)
		if _, err := io.ReadFull(h.conn, tpktHeader); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				h.emitEvent(sensorv1.EventType_S7_SESSION_TIMEOUT, sensorv1.Severity_SEVERITY_NOISE,
					"S7 session idle timeout", nil, nil)
			}
			return
		}

		// Validate TPKT version
		if tpktHeader[0] != tpktVersion {
			// Non-TPKT traffic on port 102 — scanner or raw TCP probe
			raw := make([]byte, maxReadSize)
			n, _ := h.conn.Read(raw)
			payload := append(tpktHeader, raw[:n]...)
			h.emitEvent(sensorv1.EventType_S7_NON_TPKT_TRAFFIC, sensorv1.Severity_SEVERITY_LOW,
				fmt.Sprintf("Non-TPKT traffic (first byte: 0x%02X)", tpktHeader[0]),
				payload, nil)
			return
		}

		// Parse TPKT length
		tpktLen := int(binary.BigEndian.Uint16(tpktHeader[2:4]))
		if tpktLen < tpktMinLen || tpktLen > maxTPKTLen {
			h.emitEvent(sensorv1.EventType_S7_MALFORMED_TPKT, sensorv1.Severity_SEVERITY_LOW,
				fmt.Sprintf("Malformed TPKT length: %d", tpktLen), tpktHeader, nil)
			return
		}

		// Read COTP + S7 payload
		payload := make([]byte, tpktLen-tpktMinLen)
		if len(payload) > 0 {
			if _, err := io.ReadFull(h.conn, payload); err != nil {
				h.emitEvent(sensorv1.EventType_S7_PARTIAL_PACKET, sensorv1.Severity_SEVERITY_LOW,
					"Partial packet read", tpktHeader, nil)
				return
			}
		}

		fullPacket := append(tpktHeader, payload...)
		if err := h.dispatchCOTP(payload, fullPacket); err != nil {
			slog.Debug("S7 dispatch error", "error", err, "remote", h.remoteIP)
			return
		}
	}
}

// dispatchCOTP parses the COTP layer and routes to S7 handler.
func (h *Handler) dispatchCOTP(payload, rawPacket []byte) error {
	if len(payload) < 3 {
		h.emitEvent(sensorv1.EventType_S7_MALFORMED_TPKT, sensorv1.Severity_SEVERITY_LOW,
			"COTP payload too short", rawPacket, nil)
		return fmt.Errorf("cotp payload too short")
	}

	cotpLen  := int(payload[0])
	cotpType := payload[1]

	switch cotpType {
	case cotpCR:
		// Connection Request → send Connection Confirm
		return h.handleCOTPConnect(rawPacket)

	case cotpDT:
		// Data Transfer — route to S7
		if len(payload) < cotpLen+2 {
			h.emitEvent(sensorv1.EventType_S7_PARTIAL_PACKET, sensorv1.Severity_SEVERITY_LOW,
				"COTP DT payload truncated", rawPacket, nil)
			return fmt.Errorf("cotp dt payload truncated")
		}
		s7Data := payload[cotpLen+1:]
		return h.dispatchS7(s7Data, rawPacket)

	default:
		h.emitEvent(sensorv1.EventType_S7_INVALID_COTP_TYPE, sensorv1.Severity_SEVERITY_LOW,
			fmt.Sprintf("Unknown COTP type: 0x%02X", cotpType), rawPacket, nil)
		return nil // Don't close — continue reading
	}
}

// handleCOTPConnect sends a COTP Connection Confirm.
func (h *Handler) handleCOTPConnect(rawPacket []byte) error {
	if h.state != stateInit {
		return nil // Duplicate CR — ignore
	}

	// COTP CC response (minimal, matching real S7-315 behavior)
	// TPKT header + COTP CC
	cc := []byte{
		0x03, 0x00, 0x00, 0x16, // TPKT: version=3, len=22
		0x11,                   // COTP: length=17
		0xD0,                   // COTP: CC
		0x00, 0x01,             // dst-ref
		0x00, 0x01,             // src-ref
		0x00,                   // class/option=0
		// Parameters (src-tsap, dst-tsap, tpdu-size)
		0xC0, 0x01, 0x0A,       // tpdu-size: 0x0A = 1024 bytes
		0xC1, 0x02, 0x01, 0x00, // src-tsap
		0xC2, 0x02, 0x01, 0x02, // dst-tsap
	}

	_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := h.conn.Write(cc); err != nil {
		return fmt.Errorf("write COTP CC: %w", err)
	}

	h.state = stateCOTPConnected
	return nil
}

// dispatchS7 routes S7 PDUs based on ROSCTR and function code.
func (h *Handler) dispatchS7(s7Data, rawPacket []byte) error {
	if len(s7Data) < 10 {
		return nil // Too short for S7 header
	}

	// S7 header: ID(2) ROSCTR(1) Reserved(2) PDU-ref(2) Params-len(2) Data-len(2)
	if s7Data[0] != 0x32 {
		// Not S7 protocol magic
		h.emitEvent(sensorv1.EventType_S7_MALFORMED_TPKT, sensorv1.Severity_SEVERITY_LOW,
			"Invalid S7 protocol ID", rawPacket, nil)
		return nil
	}

	rosctr  := s7Data[1]
	pduRef  := binary.BigEndian.Uint16(s7Data[4:6])
	paramLen := binary.BigEndian.Uint16(s7Data[6:8])

	var params []byte
	if int(10+paramLen) <= len(s7Data) {
		params = s7Data[10 : 10+paramLen]
	}

	switch rosctr {
	case s7RosctrJob:
		if len(params) == 0 {
			return nil
		}
		return h.handleS7Job(params[0], params, pduRef, rawPacket, s7Data)

	case s7RosctrUserData:
		var data []byte
		dataLen := binary.BigEndian.Uint16(s7Data[8:10])
		dataStart := 10 + int(paramLen)
		if dataStart <= len(s7Data) {
			dataEnd := dataStart + int(dataLen)
			if dataEnd > len(s7Data) {
				dataEnd = len(s7Data)
			}
			data = s7Data[dataStart:dataEnd]
		}
		return h.handleS7UserData(params, data, pduRef, rawPacket)

	default:
		h.emitEvent(sensorv1.EventType_S7_UNKNOWN_FUNCTION, sensorv1.Severity_SEVERITY_MEDIUM,
			fmt.Sprintf("Unknown S7 ROSCTR: 0x%02X", rosctr), rawPacket, nil)
		return nil
	}
}

// handleS7Job handles S7 Job PDUs (read, write, setup, control).
func (h *Handler) handleS7Job(funcCode byte, params []byte, pduRef uint16, rawPacket, s7Data []byte) error {
	switch funcCode {
	case s7FuncSetupComm:
		return h.handleSetupComm(pduRef)

	case s7FuncReadVar:
		return h.handleReadVar(params, pduRef, rawPacket)

	case s7FuncWriteVar:
		return h.handleWriteVar(params, s7Data, pduRef, rawPacket)

	case s7FuncControl:
		// Control functions: CPU STOP, CPU START, etc.
		if len(params) >= 2 {
			return h.handleControl(params[1], params, pduRef, rawPacket)
		}

	case s7CpuStopSubfunc:
		// Some tooling sends CPU STOP as the top-level function code (0x29)
		// instead of wrapping it in the generic control function (0x28).
		return h.handleControl(s7CpuStopSubfunc, params, pduRef, rawPacket)

	case s7FuncRequestDownload, s7FuncDownloadBlock, s7FuncEndDownload:
		h.emitEvent(sensorv1.EventType_S7_DOWNLOAD_BLOCK, sensorv1.Severity_SEVERITY_CRITICAL,
			fmt.Sprintf("S7 block download function: 0x%02X", funcCode),
			rawPacket,
			[]*sensorv1.Artifact{{
				ArtifactType: "s7_payload",
				Value:        rawPacket,
				Encoding:     "hex",
			}})
		return h.sendS7Ack(pduRef, nil)

	case s7FuncUploadBlock, s7FuncEndUpload:
		h.emitEvent(sensorv1.EventType_S7_UPLOAD_BLOCK, sensorv1.Severity_SEVERITY_HIGH,
			"S7 block upload attempt", rawPacket, nil)
		return h.sendS7Ack(pduRef, nil)

	default:
		h.emitEvent(sensorv1.EventType_S7_UNKNOWN_FUNCTION, sensorv1.Severity_SEVERITY_MEDIUM,
			fmt.Sprintf("Unknown S7 function code: 0x%02X", funcCode), rawPacket, nil)
		return h.sendS7Error(pduRef, 0x85, 0x01) // Function not supported
	}
	return nil
}

// handleSetupComm sends Setup Communication acknowledgment.
// This is the critical handshake that convinces tools the target is a real S7 PLC.
func (h *Handler) handleSetupComm(pduRef uint16) error {
	if h.state >= stateS7Setup {
		return nil
	}

	h.emitEvent(sensorv1.EventType_S7_SETUP_COMM, sensorv1.Severity_SEVERITY_LOW,
		"S7 Setup Communication", nil, nil)

	// S7 Setup Communication Acknowledgment
	// Emulates: maxAmQCalling=1, maxAmQCalled=1, maxPDULength=480 (S7-315 default)
	ack := h.buildTPKT([]byte{
		0x02,       // COTP: LEN
		cotpDT,     // COTP: DT
		0x80,       // COTP: EOT=1
		// S7 Ack-Data header
		0x32,       // S7 ID
		0x03,       // ROSCTR: Ack-Data
		0x00, 0x00, // Reserved
		byte(pduRef >> 8), byte(pduRef), // PDU ref (echo)
		0x00, 0x08, // Params-len: 8
		0x00, 0x00, // Data-len: 0
		0x00, 0x00, // Error class + code (no error)
		// Setup Comm params
		s7FuncSetupComm,
		0x00,       // Reserved
		0x00, 0x01, // maxAmQCalling: 1
		0x00, 0x01, // maxAmQCalled:  1
		0x01, 0xE0, // maxPDULength:  480
	})

	_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := h.conn.Write(ack); err != nil {
		return fmt.Errorf("write setup comm ack: %w", err)
	}

	h.state = stateOperational
	return nil
}

// handleReadVar responds to S7 read variable requests.
// Returns data from the stateful memory map.
func (h *Handler) handleReadVar(params []byte, pduRef uint16, rawPacket []byte) error {
	h.emitEvent(sensorv1.EventType_S7_READ_VAR, sensorv1.Severity_SEVERITY_MEDIUM,
		"S7 Read Variable request", rawPacket, nil)

	// Parse item count from params
	if len(params) < 2 {
		return h.sendS7Error(pduRef, 0x85, 0x01)
	}

	itemCount := int(params[1])
	var readData []byte
	readData = append(readData, 0x32, 0x03, 0x00, 0x00) // S7 ID, Ack-Data
	readData = append(readData, byte(pduRef>>8), byte(pduRef))

	// Build response items
	var items []byte
	for i := 0; i < itemCount; i++ {
		itemOffset := 2 + i*12
		if itemOffset+12 > len(params) {
			break
		}
		item := params[itemOffset : itemOffset+12]
		
		// Parse item: spec(1) len(1) syntax(1) transport(1) count(2) db(2) area(1) addr(3)
		if len(item) >= 12 {
			dbNumber   := int(binary.BigEndian.Uint16(item[6:8]))
			byteOffset := int(binary.BigEndian.Uint32([]byte{0, item[9], item[10], item[11]}) >> 3)
			byteCount  := int(binary.BigEndian.Uint16(item[4:6]))

			value := h.memory.Read(dbNumber, byteOffset, byteCount)
			// Item response: return-code(1) transport-size(1) data-len(2) data
			items = append(items, 0xFF, 0x04) // Return OK, transport=BYTE
			items = append(items, byte(byteCount>>8), byte(byteCount))
			items = append(items, value...)
		}
	}

	paramLen := uint16(2) // itemCount + reserved
	dataLen  := uint16(len(items))
	response := h.buildTPKT([]byte{
		0x02, cotpDT, 0x80,
		0x32, 0x03, 0x00, 0x00,
		byte(pduRef >> 8), byte(pduRef),
		byte(paramLen >> 8), byte(paramLen),
		byte(dataLen >> 8), byte(dataLen),
		0x00, 0x00, // No error
		0x04, byte(itemCount),
	})
	response = append(response, items...)

	_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := h.conn.Write(response)
	return err
}

// handleWriteVar processes S7 write variable requests.
// Stores to stateful memory map and records as CRITICAL-tier evidence.
func (h *Handler) handleWriteVar(params, s7Data []byte, pduRef uint16, rawPacket []byte) error {
	// Extract DB number and value for artifact capture
	var dbNumber, byteOffset int
	var writtenValue []byte

	if len(params) >= 14 {
		dbNumber   = int(binary.BigEndian.Uint16(params[8:10]))
		byteOffset = int(binary.BigEndian.Uint32([]byte{0, params[11], params[12], params[13]}) >> 3)
		
		// Extract write data from s7Data section
		paramsLen := int(binary.BigEndian.Uint16(s7Data[6:8]))
		if 10+paramsLen+4 <= len(s7Data) {
			dataSection := s7Data[10+paramsLen:]
			if len(dataSection) >= 4 {
				dataLen := int(binary.BigEndian.Uint16(dataSection[2:4]))
				if 4+dataLen <= len(dataSection) {
					writtenValue = dataSection[4 : 4+dataLen]
					if h.cfg.StatefulS7Memory {
						h.memory.Write(dbNumber, byteOffset, writtenValue, h.sessionKey)
					}
				}
			}
		}
	}

	artifacts := []*sensorv1.Artifact{{
		ArtifactType: "s7_write_payload",
		Value:        rawPacket,
		Encoding:     "hex",
	}}

	meta := map[string]string{
		"db_number":   fmt.Sprintf("%d", dbNumber),
		"byte_offset": fmt.Sprintf("%d", byteOffset),
		"value_hex":   hex.EncodeToString(writtenValue),
	}

	h.emitEventWithMeta(sensorv1.EventType_S7_WRITE_VAR, sensorv1.Severity_SEVERITY_HIGH,
		fmt.Sprintf("S7 Write to DB%d.DBB%d = %s", dbNumber, byteOffset, hex.EncodeToString(writtenValue)),
		rawPacket, artifacts, meta)

	// Send write acknowledgment (plausible success)
	ack := h.buildTPKT([]byte{
		0x02, cotpDT, 0x80,
		0x32, 0x03, 0x00, 0x00,
		byte(pduRef >> 8), byte(pduRef),
		0x00, 0x02, // params-len=2
		0x00, 0x01, // data-len=1
		0x00, 0x00, // no error
		0x05, 0x01, // function=WriteVar, item-count=1
		0xFF,       // item return code: success
	})

	_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := h.conn.Write(ack)
	return err
}

// handleControl handles S7 control functions, specifically CPU STOP.
// *** CRITICAL DECEPTION PATH ***
func (h *Handler) handleControl(subFunc byte, params []byte, pduRef uint16, rawPacket []byte) error {
	switch subFunc {
	case s7CpuStopSubfunc:
		// ── CPU STOP DETECTED ─────────────────────────────────────────────────
		// This is the primary attack target. We:
		// 1. Emit a CRITICAL severity event
		// 2. Return a plausible ACK (MUST NOT return error/RST — that would reveal us as honeypot)
		h.emitEventWithMeta(
			sensorv1.EventType_S7_CPU_STOP,
			sensorv1.Severity_SEVERITY_CRITICAL,
			"*** S7 CPU STOP exploit detected — plausible ACK returned ***",
			rawPacket,
			[]*sensorv1.Artifact{{
				ArtifactType: "s7_cpu_stop_payload",
				Value:        rawPacket,
				Encoding:     "hex",
			}},
			map[string]string{
				"mitre_technique": "T0816",
				"mitre_tactic":    "Inhibit Response Function",
				"cpu_stop":        "true",
			},
		)

		// Plausible CPU STOP acknowledgment (what a real S7-315 returns)
		ack := h.buildTPKT([]byte{
			0x02, cotpDT, 0x80,
			0x32, 0x03, 0x00, 0x00,
			byte(pduRef >> 8), byte(pduRef),
			0x00, 0x02, // params-len=2
			0x00, 0x00, // data-len=0
			0x00, 0x00, // no error
			0x29, 0x00, // Control ACK
		})

		_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err := h.conn.Write(ack)
		return err

	default:
		h.emitEvent(sensorv1.EventType_S7_UNKNOWN_FUNCTION, sensorv1.Severity_SEVERITY_MEDIUM,
			fmt.Sprintf("S7 control sub-function: 0x%02X", subFunc), rawPacket, nil)
		return h.sendS7Ack(pduRef, nil)
	}
}

// handleS7UserData handles SZL (System Status List) reads and other UserData PDUs.
func (h *Handler) handleS7UserData(params, data []byte, pduRef uint16, rawPacket []byte) error {
	if len(params) < 4 {
		return nil
	}

	// Check if this is an SZL request
	funcGroup := (params[3] >> 4) & 0x0F
	if funcGroup == 0x04 || (len(params) >= 6 && params[4] == 0x11 && (params[5]>>4) == 0x04) {
		return h.handleSZLRead(params, data, pduRef, rawPacket)
	}

	h.emitEvent(sensorv1.EventType_S7_UNKNOWN_FUNCTION, sensorv1.Severity_SEVERITY_MEDIUM,
		"S7 UserData PDU (non-SZL)", rawPacket, nil)
	return nil
}

// handleSZLRead emulates Siemens SZL (System Status List) responses.
// SZL reads are the primary device discovery mechanism for tools like s7scan.
func (h *Handler) handleSZLRead(params, data []byte, pduRef uint16, rawPacket []byte) error {
	// Extract SZL-ID from request
	szlID := uint16(0x0011)
	szlIndex := uint16(0)
	if len(data) >= 4 {
		szlID = binary.BigEndian.Uint16(data[0:2])
		szlIndex = binary.BigEndian.Uint16(data[2:4])
	} else if len(data) >= 3 {
		szlID = binary.BigEndian.Uint16(data[0:2])
		szlIndex = uint16(data[2]) << 8
	} else if len(params) >= 8 {
		szlID = binary.BigEndian.Uint16(params[4:6])
		szlIndex = binary.BigEndian.Uint16(params[6:8])
	}

	h.emitEventWithMeta(
		sensorv1.EventType_S7_SZL_READ,
		sensorv1.Severity_SEVERITY_MEDIUM,
		fmt.Sprintf("S7 SZL Read request: SZL-ID=0x%04X Index=0x%04X (device discovery)", szlID, szlIndex),
		rawPacket,
		nil,
		map[string]string{
			"szl_id":    fmt.Sprintf("0x%04X", szlID),
			"szl_index": fmt.Sprintf("0x%04X", szlIndex),
			"mitre_technique": "T0888",
			"mitre_tactic":    "Discovery",
		},
	)

	// Return plausible SZL response based on SZL-ID
	szlData := buildSZLResponse(szlID, h.cfg)

	// Build UserData response
	paramsResp := []byte{
		0x00, 0x01, 0x12, byte(8 + len(szlData)),
		0x84,             // type=response, function=SZL read
		0x04,             // function group
		0x00, 0x01,       // sequence
		0xFF, 0x09,       // return code OK, transport=OCTET_STRING
		byte(len(szlData) >> 8), byte(len(szlData)),
	}
	paramsResp = append(paramsResp, szlData...)

	paramLen := uint16(len(paramsResp))
	response := h.buildTPKT(append([]byte{
		0x02, cotpDT, 0x80,
		0x32, 0x07, 0x00, 0x00, // ROSCTR=UserData
		byte(pduRef >> 8), byte(pduRef),
		byte(paramLen >> 8), byte(paramLen),
		0x00, 0x00, // data-len=0
	}, paramsResp...))

	_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := h.conn.Write(response)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// SZL Data Builder
// ─────────────────────────────────────────────────────────────────────────────

// buildSZLResponse returns realistic SZL data for common SZL IDs.
func buildSZLResponse(szlID uint16, cfg *config.SensorConfig) []byte {
	switch szlID {
	case 0x0011: // Module identification
		// SZL-ID=0x0011: CPU identification
		// Order number, PLC name, serial number
		name   := padRight(cfg.PLCName, 24)
		serial := padRight(cfg.SerialNumber, 24)
		order  := padRight(cfg.ModuleType, 20)
		data   := []byte{0x00, 0x11, 0x00, 0x1C, 0x00, 0x03} // SZL-ID, SZL-IDX, LEN, COUNT
		data    = append(data, []byte(order)...)
		data    = append(data, 0x00, 0x00)
		data    = append(data, []byte(name)...)
		data    = append(data, []byte(serial)...)
		return data

	case 0x001C: // Component identification
		data := []byte{0x00, 0x1C, 0x00, 0x0A, 0x00, 0x01}
		data  = append(data, []byte(padRight(cfg.PLCName, 24))...)
		return data

	case 0x0131: // Communication capabilities
		return []byte{
			0x01, 0x31, 0x00, 0x0A, 0x00, 0x01,
			0x00, 0x14, // max connections
			0x01,       // reserved
			0x08, 0x00, // max PDU S7
		}

	default:
		// Generic empty SZL response (no data)
		return []byte{byte(szlID >> 8), byte(szlID), 0x00, 0x02, 0x00, 0x00}
	}
}

func padRight(s string, n int) string {
	for len(s) < n {
		s += "\x00"
	}
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────────────
// Frame builders
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) buildTPKT(payload []byte) []byte {
	totalLen := uint16(tpktMinLen + len(payload))
	frame := []byte{tpktVersion, 0x00, byte(totalLen >> 8), byte(totalLen)}
	return append(frame, payload...)
}

func (h *Handler) sendS7Ack(pduRef uint16, data []byte) error {
	ack := h.buildTPKT([]byte{
		0x02, cotpDT, 0x80,
		0x32, 0x03, 0x00, 0x00,
		byte(pduRef >> 8), byte(pduRef),
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := h.conn.Write(ack)
	return err
}

func (h *Handler) sendS7Error(pduRef uint16, errClass, errCode byte) error {
	errResp := h.buildTPKT([]byte{
		0x02, cotpDT, 0x80,
		0x32, 0x02, 0x00, 0x00,
		byte(pduRef >> 8), byte(pduRef),
		0x00, 0x00, 0x00, 0x00,
		errClass, errCode,
	})
	_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := h.conn.Write(errResp)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Event helpers
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) emitEvent(evType sensorv1.EventType, severity sensorv1.Severity, summary string, rawPayload []byte, artifacts []*sensorv1.Artifact) {
	h.emitEventWithMeta(evType, severity, summary, rawPayload, artifacts, nil)
}

func (h *Handler) emitEventWithMeta(evType sensorv1.EventType, severity sensorv1.Severity, summary string, rawPayload []byte, artifacts []*sensorv1.Artifact, meta map[string]string) {
	if meta == nil {
		meta = make(map[string]string)
	}
	meta["state"] = fmt.Sprintf("%d", h.state)

	var payloadBytes []byte
	if len(rawPayload) > maxReadSize {
		payloadBytes = rawPayload[:maxReadSize]
	} else {
		payloadBytes = rawPayload
	}

	h.dispatcher.Emit(&sensorv1.SensorEvent{
		SensorId:   h.cfg.SensorID,
		EventId:    uuid.New().String(),
		Timestamp:  timestamppb.Now(),
		SourceIp:   h.remoteIP,
		SourcePort: int32(h.remotePort),
		DstPort:    int32(h.cfg.S7Port),
		Protocol:   sensorv1.Protocol_PROTOCOL_S7,
		EventType:  evType,
		Severity:   severity,
		RawSummary: summary,
		RawPayload: payloadBytes,
		Metadata:   meta,
		Artifacts:  artifacts,
		SessionHint: h.sessionKey,
	})
}
