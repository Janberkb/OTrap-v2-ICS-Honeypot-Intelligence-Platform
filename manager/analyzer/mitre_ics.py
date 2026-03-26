"""
manager/analyzer/mitre_ics.py — MITRE ATT&CK for ICS technique mappings.

Reference: https://attack.mitre.org/matrices/ics/
Each entry maps an OTrap event_type to a MITRE ICS technique.
"""

MITRE_ICS_MAPPING: dict[str, dict[str, str]] = {
    # ── S7 / ICS Protocol Events ──────────────────────────────────────────────
    "S7_COTP_CONNECT": {
        "technique_id":   "T0883",
        "technique_name": "Internet Accessible Device",
        "tactic":         "Initial Access",
        "description":    "Adversary connected to an internet-accessible ICS device.",
    },
    "S7_SZL_READ": {
        "technique_id":   "T0888",
        "technique_name": "Remote System Information Discovery",
        "tactic":         "Discovery",
        "description":    "SZL read used to discover PLC identification and configuration.",
    },
    "S7_SETUP_COMM": {
        "technique_id":   "T0885",
        "technique_name": "Commonly Used Port",
        "tactic":         "Command and Control",
        "description":    "Use of standard S7comm port (102/TCP) for C2 communication.",
    },
    "S7_READ_VAR": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "Reading PLC variables to monitor industrial process state.",
    },
    "S7_WRITE_VAR": {
        "technique_id":   "T0836",
        "technique_name": "Modify Parameter",
        "tactic":         "Impair Process Control",
        "description":    "Writing to PLC Data Block to manipulate process parameters.",
    },
    "S7_CPU_STOP": {
        "technique_id":   "T0816",
        "technique_name": "Device Restart/Shutdown",
        "tactic":         "Inhibit Response Function",
        "description":    "Unauthorized CPU STOP command sent to Siemens S7 PLC. "
                          "This is the signature technique of Stage 2 ICS attacks (Stuxnet, CRASHOVERRIDE).",
    },
    "S7_DOWNLOAD_BLOCK": {
        "technique_id":   "T0843",
        "technique_name": "Program Download",
        "tactic":         "Lateral Movement",
        "description":    "Adversary downloading modified control logic to PLC.",
    },
    "S7_DELETE_BLOCK": {
        "technique_id":   "T0809",
        "technique_name": "Data Destruction",
        "tactic":         "Inhibit Response Function",
        "description":    "Deletion of PLC program blocks.",
    },
    "S7_UPLOAD_BLOCK": {
        "technique_id":   "T0845",
        "technique_name": "Program Upload",
        "tactic":         "Collection",
        "description":    "Exfiltrating PLC control program for analysis.",
    },
    "S7_MALFORMED_TPKT": {
        "technique_id":   "T0856",
        "technique_name": "Spoof Reporting Message",
        "tactic":         "Evasion",
        "description":    "Malformed TPKT frames may indicate fuzzing or evasion attempts.",
    },
    "S7_NON_TPKT_TRAFFIC": {
        "technique_id":   "T0888",
        "technique_name": "Remote System Information Discovery",
        "tactic":         "Discovery",
        "description":    "Non-TPKT traffic on S7 port suggests port scanner or probe.",
    },

    # ── Modbus Events ─────────────────────────────────────────────────────────
    "MODBUS_WRITE_SINGLE_REG": {
        "technique_id":   "T0836",
        "technique_name": "Modify Parameter",
        "tactic":         "Impair Process Control",
        "description":    "Writing a single Modbus register to alter process control values.",
    },
    "MODBUS_WRITE_MULTIPLE": {
        "technique_id":   "T0836",
        "technique_name": "Modify Parameter",
        "tactic":         "Impair Process Control",
        "description":    "Bulk Modbus register write — high-impact parameter manipulation.",
    },
    "MODBUS_READ_HOLDING": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "Reading Modbus holding registers to observe process state.",
    },
    "MODBUS_READ_COILS": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "Reading Modbus coil states.",
    },
    "MODBUS_CONNECT": {
        "technique_id":   "T0883",
        "technique_name": "Internet Accessible Device",
        "tactic":         "Initial Access",
        "description":    "Connection to Modbus/TCP device.",
    },
    "MODBUS_SCANNER_DETECTED": {
        "technique_id":   "T0846",
        "technique_name": "Remote System Discovery",
        "tactic":         "Discovery",
        "description":    "MEI Device Identification (fc=0x2B) — automated scanner probe for device fingerprinting.",
    },

    # ── HMI / Web Events ──────────────────────────────────────────────────────
    "HMI_LOGIN_ATTEMPT": {
        "technique_id":   "T0866",
        "technique_name": "Exploitation of Remote Services",
        "tactic":         "Initial Access",
        "description":    "Credential brute-force against HMI web login.",
    },
    "HMI_LOGIN_SUCCESS": {
        "technique_id":   "T0866",
        "technique_name": "Exploitation of Remote Services",
        "tactic":         "Initial Access",
        "description":    "Attacker successfully authenticated to HMI (deceptive: rabbit hole active).",
    },
    "HMI_SQLI_PROBE": {
        "technique_id":   "T0817",
        "technique_name": "Drive-by Compromise",
        "tactic":         "Initial Access",
        "description":    "SQL injection probe against HMI web interface.",
    },
    "HMI_XSS_PROBE": {
        "technique_id":   "T0817",
        "technique_name": "Drive-by Compromise",
        "tactic":         "Initial Access",
        "description":    "Cross-site scripting probe against HMI.",
    },
    "HMI_CMD_INJECTION": {
        "technique_id":   "T0862",
        "technique_name": "Supply Chain Compromise",
        "tactic":         "Initial Access",
        "description":    "Command injection attempt against HMI web application.",
    },
    "HMI_PATH_TRAVERSAL": {
        "technique_id":   "T0817",
        "technique_name": "Drive-by Compromise",
        "tactic":         "Initial Access",
        "description":    "Path traversal probe attempting file read from HMI server.",
    },
    "HMI_SENSITIVE_PATH": {
        "technique_id":   "T0888",
        "technique_name": "Remote System Information Discovery",
        "tactic":         "Discovery",
        "description":    "Probe of sensitive admin/config paths on HMI web server.",
    },
    "HMI_DASHBOARD_ACCESS": {
        "technique_id":   "T0824",
        "technique_name": "I/O Module Discovery",
        "tactic":         "Discovery",
        "description":    "Attacker accessing deceptive HMI dashboard (rabbit hole engaged).",
    },
}
