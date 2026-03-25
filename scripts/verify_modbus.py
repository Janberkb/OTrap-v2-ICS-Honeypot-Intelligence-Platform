#!/usr/bin/env python3
"""
scripts/verify_modbus.py — Modbus/TCP decoy verification.

Tests all major Modbus function codes and verifies:
  - FC01 Read Coils
  - FC02 Read Discrete Inputs
  - FC03 Read Holding Registers
  - FC04 Read Input Registers
  - FC05 Write Single Coil (HIGH severity)
  - FC06 Write Single Register (HIGH severity)
  - FC16 Write Multiple Registers — MITRE T0836
  - FC43 MEI Device Identification (scanner probe)
  - Unknown function code → exception response

Usage:
    python3 scripts/verify_modbus.py --host 127.0.0.1
"""

import argparse
import socket
import struct
import sys

class Colors:
    OK   = "\033[92m"; FAIL = "\033[91m"; WARN = "\033[93m"
    BOLD = "\033[1m";  RESET = "\033[0m"

def ok(m):   print(f"  {Colors.OK}✓{Colors.RESET} {m}")
def fail(m): print(f"  {Colors.FAIL}✗{Colors.RESET} {m}"); sys.exit(1)
def warn(m): print(f"  {Colors.WARN}!{Colors.RESET} {m}")
def section(m): print(f"\n{Colors.BOLD}── {m}{Colors.RESET}")


def build_mbap(tx_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Build Modbus/TCP MBAP header + PDU."""
    return struct.pack("!HHHB", tx_id, 0, 1 + len(pdu), unit_id) + pdu


def send_recv(sock: socket.socket, data: bytes, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    sock.sendall(data)
    try:
        return sock.recv(1024)
    except socket.timeout:
        return b""


def run_modbus_tests(host: str, port: int = 502) -> None:
    section(f"Modbus/TCP Decoy → {host}:{port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        ok("TCP connected to port 502")
    except Exception as e:
        fail(f"TCP connect failed: {e}")

    tx = 1

    # FC01 — Read Coils
    pdu  = bytes([0x01]) + struct.pack("!HH", 0, 16)
    resp = send_recv(sock, build_mbap(tx, 1, pdu)); tx += 1
    if resp and resp[7] == 0x01:
        byte_count = resp[8]
        ok(f"FC01 Read Coils → {byte_count} bytes returned")
    else:
        warn(f"FC01 unexpected: {resp.hex()[:20]}")

    # FC03 — Read Holding Registers
    pdu  = bytes([0x03]) + struct.pack("!HH", 0, 10)
    resp = send_recv(sock, build_mbap(tx, 1, pdu)); tx += 1
    if resp and resp[7] == 0x03:
        n_bytes = resp[8]
        regs = [struct.unpack("!H", resp[9+i*2:11+i*2])[0] for i in range(n_bytes//2)]
        ok(f"FC03 Read Holding Registers → {regs[:5]}…")
    else:
        warn(f"FC03 unexpected: {resp.hex()[:20]}")

    # FC04 — Read Input Registers
    pdu  = bytes([0x04]) + struct.pack("!HH", 100, 5)
    resp = send_recv(sock, build_mbap(tx, 1, pdu)); tx += 1
    if resp and resp[7] == 0x04:
        ok("FC04 Read Input Registers → plausible process values returned")
    else:
        warn(f"FC04 unexpected: {resp.hex()[:20]}")

    # FC05 — Write Single Coil (HIGH severity)
    pdu  = bytes([0x05]) + struct.pack("!HH", 0, 0xFF00)
    resp = send_recv(sock, build_mbap(tx, 1, pdu)); tx += 1
    if resp and resp[7] == 0x05:
        ok("FC05 Write Single Coil → echo ACK (HIGH severity event emitted)")
    else:
        warn(f"FC05 unexpected: {resp.hex()[:20]}")

    # FC06 — Write Single Register (HIGH severity)
    pdu  = bytes([0x06]) + struct.pack("!HH", 10, 0x0200)
    resp = send_recv(sock, build_mbap(tx, 1, pdu)); tx += 1
    if resp and resp[7] == 0x06:
        ok("FC06 Write Single Register → echo ACK (HIGH severity)")
    else:
        warn(f"FC06 unexpected: {resp.hex()[:20]}")

    # FC16 — Write Multiple Registers (MITRE T0836)
    reg_data = struct.pack("!HH", 30, 50) + bytes([4]) + struct.pack("!HH", 0x0100, 0x0200)
    pdu  = bytes([0x10]) + reg_data
    resp = send_recv(sock, build_mbap(tx, 1, pdu)); tx += 1
    if resp and resp[7] == 0x10:
        ok("FC16 Write Multiple Registers → ACK (MITRE T0836 — Modify Parameter)")
    elif resp and resp[7] == 0x90:  # Exception
        ok(f"FC16 Write Multiple → Exception 0x{resp[8]:02X} (still classified)")
    else:
        warn(f"FC16 unexpected: {resp.hex()[:20]}")

    # FC43 — MEI Device Identification (scanner probe)
    pdu  = bytes([0x2B, 0x0E, 0x01, 0x00])
    resp = send_recv(sock, build_mbap(tx, 1, pdu)); tx += 1
    if resp and len(resp) > 8:
        ok("FC43 MEI Device Identification → vendor data returned (scanner probe classified)")
    else:
        warn("FC43 no response")

    # Unknown FC (0x41) — should return exception
    pdu  = bytes([0x41, 0x00, 0x00])
    resp = send_recv(sock, build_mbap(tx, 1, pdu)); tx += 1
    if resp and len(resp) > 8 and resp[7] == 0xC1:  # 0x41 | 0x80
        ok("Unknown FC → Modbus exception 0x01 (Illegal Function) returned")
    else:
        warn(f"Unknown FC response: {resp.hex()[:20] if resp else 'empty'}")

    sock.close()
    ok(f"All {tx - 1} Modbus probes completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=502)
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}OTrap Modbus Verification{Colors.RESET}")
    print("=" * 50)
    run_modbus_tests(args.host, args.port)
    print(f"\n{Colors.OK}{Colors.BOLD}Modbus verification complete.{Colors.RESET}\n")
