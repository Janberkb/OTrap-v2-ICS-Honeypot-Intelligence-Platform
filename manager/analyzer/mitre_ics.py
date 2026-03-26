"""
manager/analyzer/mitre_ics.py — MITRE ATT&CK for ICS technique mappings.

Reference: https://attack.mitre.org/matrices/ics/
Each entry maps an OTrap event_type to a primary MITRE ICS technique.
Optional `additional_techniques` list carries secondary technique mappings
so that high-value events can surface multiple relevant techniques.

Total coverage: 48 primary + 15 secondary = 63 technique-event pairs.
"""

MITRE_ICS_MAPPING: dict[str, dict] = {
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
        "additional_techniques": [
            {
                "technique_id":   "T0882",
                "technique_name": "Theft of Operational Information",
                "tactic":         "Collection",
                "description":    "SZL enumeration harvests PLC identity, firmware version, and module layout — operational data usable for targeted attack planning.",
            },
        ],
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
        "additional_techniques": [
            {
                "technique_id":   "T0814",
                "technique_name": "Denial of Control",
                "tactic":         "Inhibit Response Function",
                "description":    "Writing incorrect values to control registers denies operators the ability to command the physical process.",
            },
        ],
    },
    "S7_CPU_STOP": {
        "technique_id":   "T0816",
        "technique_name": "Device Restart/Shutdown",
        "tactic":         "Inhibit Response Function",
        "description":    "Unauthorized CPU STOP command sent to Siemens S7 PLC. "
                          "This is the signature technique of Stage 2 ICS attacks (Stuxnet, CRASHOVERRIDE).",
        "additional_techniques": [
            {
                "technique_id":   "T0814",
                "technique_name": "Denial of Control",
                "tactic":         "Inhibit Response Function",
                "description":    "CPU STOP removes operator ability to control the physical process, achieving Denial of Control.",
            },
            {
                "technique_id":   "T0879",
                "technique_name": "Damage to Property",
                "tactic":         "Impact",
                "description":    "Abrupt PLC shutdown can damage physical equipment dependent on continuous PLC control (motors, valves, pumps).",
            },
        ],
    },
    "S7_CPU_START": {
        "technique_id":   "T0834",
        "technique_name": "Native API",
        "tactic":         "Execution",
        "description":    "CPU START command issued via native S7comm API — adversary may restart PLC after uploading modified logic.",
        "additional_techniques": [
            {
                "technique_id":   "T0858",
                "technique_name": "Lateral Tool Transfer",
                "tactic":         "Lateral Movement",
                "description":    "CPU START following a Download Block sequence activates newly transferred malicious control logic.",
            },
        ],
    },
    "S7_DOWNLOAD_BLOCK": {
        "technique_id":   "T0843",
        "technique_name": "Program Download",
        "tactic":         "Lateral Movement",
        "description":    "Adversary downloading modified control logic to PLC.",
        "additional_techniques": [
            {
                "technique_id":   "T0839",
                "technique_name": "Module Firmware",
                "tactic":         "Persistence",
                "description":    "Downloading a malicious OB/FC/DB block achieves persistence — the logic survives PLC power cycles.",
            },
        ],
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
        "additional_techniques": [
            {
                "technique_id":   "T0830",
                "technique_name": "Man in the Middle",
                "tactic":         "Collection",
                "description":    "Malformed TPKT can be injected by a MITM adversary manipulating S7 traffic between engineering workstation and PLC.",
            },
        ],
    },
    "S7_NON_TPKT_TRAFFIC": {
        "technique_id":   "T0888",
        "technique_name": "Remote System Information Discovery",
        "tactic":         "Discovery",
        "description":    "Non-TPKT traffic on S7 port suggests port scanner or probe.",
    },
    "S7_UNKNOWN_FUNCTION": {
        "technique_id":   "T0834",
        "technique_name": "Native API",
        "tactic":         "Execution",
        "description":    "Undocumented or proprietary S7 function code invoked — may indicate exploit development or fuzzing of S7 service.",
    },
    "S7_SESSION_TIMEOUT": {
        "technique_id":   "T0813",
        "technique_name": "Denial of View",
        "tactic":         "Inhibit Response Function",
        "description":    "S7 session terminated abnormally — repeated timeouts may indicate connection disruption or resource exhaustion against the honeypot.",
    },
    "S7_PARTIAL_PACKET": {
        "technique_id":   "T0856",
        "technique_name": "Spoof Reporting Message",
        "tactic":         "Evasion",
        "description":    "Incomplete TPKT frame — may indicate fragmentation-based evasion or protocol fuzzing.",
    },
    "S7_INVALID_COTP_TYPE": {
        "technique_id":   "T0849",
        "technique_name": "Masquerading",
        "tactic":         "Evasion",
        "description":    "Invalid COTP PDU type — attacker may be spoofing connection setup to evade protocol-aware IDS/IPS.",
        "additional_techniques": [
            {
                "technique_id":   "T0830",
                "technique_name": "Man in the Middle",
                "tactic":         "Collection",
                "description":    "Malformed COTP may originate from an ARP-poisoning MITM position injecting tampered packets.",
            },
        ],
    },

    # ── Modbus Events ─────────────────────────────────────────────────────────
    "MODBUS_CONNECT": {
        "technique_id":   "T0883",
        "technique_name": "Internet Accessible Device",
        "tactic":         "Initial Access",
        "description":    "Connection to Modbus/TCP device.",
    },
    "MODBUS_READ_COILS": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "Reading Modbus coil states.",
    },
    "MODBUS_READ_DISCRETE": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "Reading Modbus discrete input states — monitoring digital sensor readings from the field.",
    },
    "MODBUS_READ_HOLDING": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "Reading Modbus holding registers to observe process state.",
    },
    "MODBUS_READ_INPUT": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "Reading Modbus input registers — analog sensor values from the physical process.",
    },
    "MODBUS_WRITE_SINGLE_COIL": {
        "technique_id":   "T0855",
        "technique_name": "Unauthorized Command Message",
        "tactic":         "Impair Process Control",
        "description":    "Writing a single Modbus coil — sending an unauthorized on/off command to a physical actuator (relay, valve, motor).",
        "additional_techniques": [
            {
                "technique_id":   "T0814",
                "technique_name": "Denial of Control",
                "tactic":         "Inhibit Response Function",
                "description":    "Unauthorized coil write can override operator commands and deny control of physical process outputs.",
            },
        ],
    },
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
        "additional_techniques": [
            {
                "technique_id":   "T0814",
                "technique_name": "Denial of Control",
                "tactic":         "Inhibit Response Function",
                "description":    "Bulk register write can overwrite setpoints and limits, denying operators effective control of the process.",
            },
        ],
    },
    "MODBUS_UNKNOWN_FUNCTION": {
        "technique_id":   "T0834",
        "technique_name": "Native API",
        "tactic":         "Execution",
        "description":    "Non-standard Modbus function code — may indicate vendor-specific extensions or exploit attempts against the Modbus stack.",
    },
    "MODBUS_EXCEPTION_RESPONSE": {
        "technique_id":   "T0856",
        "technique_name": "Spoof Reporting Message",
        "tactic":         "Evasion",
        "description":    "Modbus exception response elicited — attacker probing boundary conditions, or exception spoofed by a MITM actor.",
    },
    "MODBUS_SESSION_TIMEOUT": {
        "technique_id":   "T0813",
        "technique_name": "Denial of View",
        "tactic":         "Inhibit Response Function",
        "description":    "Modbus session timed out — repeated events may indicate connection flooding or resource exhaustion.",
    },
    "MODBUS_SCANNER_DETECTED": {
        "technique_id":   "T0846",
        "technique_name": "Remote System Discovery",
        "tactic":         "Discovery",
        "description":    "MEI Device Identification (fc=0x2B) — automated scanner probe for device fingerprinting.",
    },

    # ── HMI / Web Events ──────────────────────────────────────────────────────
    "HMI_ACCESS": {
        "technique_id":   "T0883",
        "technique_name": "Internet Accessible Device",
        "tactic":         "Initial Access",
        "description":    "Generic HTTP request to the HMI web interface — initial reconnaissance of the exposed web panel.",
    },
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
        "additional_techniques": [
            {
                "technique_id":   "T0822",
                "technique_name": "External Remote Services",
                "tactic":         "Initial Access",
                "description":    "Successful HMI login via external network — attacker gained access through an exposed remote service.",
            },
        ],
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
    "HMI_SCANNER_DETECTED": {
        "technique_id":   "T0849",
        "technique_name": "Masquerading",
        "tactic":         "Evasion",
        "description":    "Automated scanner detected via User-Agent or request pattern — tool masquerading as a legitimate browser.",
    },
    "HMI_DASHBOARD_ACCESS": {
        "technique_id":   "T0824",
        "technique_name": "I/O Module Discovery",
        "tactic":         "Discovery",
        "description":    "Attacker accessing deceptive HMI dashboard (rabbit hole engaged).",
    },

    # ── EtherNet/IP (Allen-Bradley / Rockwell) Events ─────────────────────────
    "ENIP_LIST_IDENTITY": {
        "technique_id":   "T0846",
        "technique_name": "Remote System Discovery",
        "tactic":         "Discovery",
        "description":    "EtherNet/IP ListIdentity request — automated scanner probe for Rockwell/Allen-Bradley PLCs.",
    },
    "ENIP_LIST_SERVICES": {
        "technique_id":   "T0846",
        "technique_name": "Remote System Discovery",
        "tactic":         "Discovery",
        "description":    "EtherNet/IP ListServices request — enumerating supported encapsulation services.",
    },
    "ENIP_REGISTER_SESSION": {
        "technique_id":   "T0883",
        "technique_name": "Internet Accessible Device",
        "tactic":         "Initial Access",
        "description":    "EtherNet/IP RegisterSession — adversary establishing an active CIP session with the PLC.",
    },
    "ENIP_SEND_RRDATA": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "EtherNet/IP SendRRData — unconnected explicit messaging, used to send CIP service requests.",
    },
    "ENIP_CIP_READ_TAG": {
        "technique_id":   "T0801",
        "technique_name": "Monitor Process State",
        "tactic":         "Collection",
        "description":    "CIP ReadTag service — reading ControlLogix tag values to monitor industrial process state.",
    },
    "ENIP_CIP_WRITE_TAG": {
        "technique_id":   "T0836",
        "technique_name": "Modify Parameter",
        "tactic":         "Impair Process Control",
        "description":    "CIP WriteTag service — writing to ControlLogix tags to manipulate process control parameters.",
        "additional_techniques": [
            {
                "technique_id":   "T0814",
                "technique_name": "Denial of Control",
                "tactic":         "Inhibit Response Function",
                "description":    "Writing incorrect values to CIP tags can deny operators the ability to control actuators and setpoints.",
            },
            {
                "technique_id":   "T0879",
                "technique_name": "Damage to Property",
                "tactic":         "Impact",
                "description":    "Malicious tag writes can force physical equipment beyond safe operating limits, causing physical damage.",
            },
        ],
    },
    "ENIP_CIP_GET_ATTR": {
        "technique_id":   "T0888",
        "technique_name": "Remote System Information Discovery",
        "tactic":         "Discovery",
        "description":    "CIP GetAttributeAll — enumerating PLC object attributes for device profiling.",
    },
    "ENIP_CIP_SET_ATTR": {
        "technique_id":   "T0836",
        "technique_name": "Modify Parameter",
        "tactic":         "Impair Process Control",
        "description":    "CIP SetAttributeSingle — modifying PLC object attributes to alter device behavior.",
        "additional_techniques": [
            {
                "technique_id":   "T0814",
                "technique_name": "Denial of Control",
                "tactic":         "Inhibit Response Function",
                "description":    "Modifying PLC configuration attributes can disable safety interlocks and deny control.",
            },
        ],
    },
    "ENIP_UNKNOWN_COMMAND": {
        "technique_id":   "T0856",
        "technique_name": "Spoof Reporting Message",
        "tactic":         "Evasion",
        "description":    "Unknown or malformed EtherNet/IP command — may indicate fuzzing, evasion, or novel exploit.",
    },
    "ENIP_SESSION_TIMEOUT": {
        "technique_id":   "T0813",
        "technique_name": "Denial of View",
        "tactic":         "Inhibit Response Function",
        "description":    "EtherNet/IP session terminated abnormally — may indicate scan tool disconnection or session flooding.",
    },
}
