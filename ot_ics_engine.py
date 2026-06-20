"""
ot_ics_engine.py — PenteIA V4.0
OT/ICS/SCADA attack scenarios for Brazilian energy, oil & gas, water, manufacturing sectors.
MITRE ATT&CK for ICS framework techniques.
"""

ICS_TECHNIQUES = [
    {
        "id": "ICS-T0817",
        "name": "Drive-by Compromise (OT Network)",
        "mitre_ics": "T0817",
        "tactic": "INITIAL_ACCESS",
        "severity": "critical",
        "sector": ["energy", "manufacturing", "water"],
        "description": "Engineer workstation compromise installs dropper targeting ICS software (Ignition, WinCC, FactoryTalk).",
        "real_world": "TRITON/TRISIS — targeted safety instrumented systems at Saudi petrochemical plant 2017",
        "kill_chain": [
            {"step": 1, "action": "Compromise engineering workstation via spear-phishing or watering hole"},
            {"step": 2, "action": "Install dropper that scans for OT software (Wonderware, Ignition, WinCC)"},
            {"step": 3, "action": "Pivot from IT to OT via historian server or remote access terminal"},
            {"step": 4, "action": "Deploy ICS-specific payload targeting PLC/RTU/SIS"},
        ],
        "detection": ["Monitor engineering workstations for anomalous outbound connections", "IDS on IT-OT boundary"],
        "mitigations": ["Air gap or strict IT-OT separation", "Application allowlisting on engineering workstations", "Regular patching of ICS HMI software"],
        "affected_systems": ["Siemens WinCC", "Rockwell FactoryTalk", "Inductive Automation Ignition", "Wonderware"],
        "cvss_ics": 9.8,
    },
    {
        "id": "ICS-T0855",
        "name": "Unauthorized Command Message (Modbus/DNP3)",
        "mitre_ics": "T0855",
        "tactic": "IMPACT",
        "severity": "critical",
        "sector": ["energy", "water", "oil_gas"],
        "description": "Send unauthorized Modbus or DNP3 commands to PLC/RTU to open/close valves, trip breakers, or alter setpoints.",
        "real_world": "Ukraine power grid attacks 2015/2016 — BlackEnergy used unauthorized SCADA commands to cut power to 230,000 customers",
        "kill_chain": [
            {"step": 1, "action": "Gain access to OT network (IT-OT pivot or direct)"},
            {"step": 2, "action": "Enumerate Modbus devices: nmap -sU -p 502 <ot-subnet>"},
            {"step": 3, "action": "Identify target device function codes via passive sniffing"},
            {"step": 4, "action": "Send rogue Modbus write: coil/register modification to open valve or trip breaker"},
            {"step": 5, "action": "Physical impact: equipment damage, production halt, safety incident"},
        ],
        "detection": ["Modbus/DNP3 deep packet inspection", "Alert on write commands from non-HMI IPs"],
        "mitigations": ["Modbus firewall (allowlist source IPs)", "OPC-UA with security mode", "Unidirectional gateways (data diode)"],
        "affected_systems": ["Any Modbus/DNP3 device: PLCs, RTUs, smart meters"],
        "cvss_ics": 10.0,
    },
    {
        "id": "ICS-T0812",
        "name": "Default Credentials on ICS Devices",
        "mitre_ics": "T0812",
        "tactic": "INITIAL_ACCESS",
        "severity": "critical",
        "sector": ["energy", "manufacturing", "water", "oil_gas"],
        "description": "OT devices (PLCs, RTUs, HMIs) often deployed with default credentials never changed.",
        "real_world": "Oldsmar Water Treatment 2021 — attacker used remote access (TeamViewer) to increase NaOH level 111x",
        "kill_chain": [
            {"step": 1, "action": "Enumerate OT devices on network: Shodan, nmap, Claroty passive scan"},
            {"step": 2, "action": "Try default credentials: admin/admin, guest/guest, 1234/1234, root/root"},
            {"step": 3, "action": "Log into HMI web interface or engineering software"},
            {"step": 4, "action": "Modify PLC program, setpoints, or process parameters"},
        ],
        "detection": ["Monitor logins to OT devices", "Alert on first-time logins or new source IPs"],
        "mitigations": ["Change all default passwords before deployment", "MFA on remote access to OT", "Inventory all OT devices"],
        "affected_systems": ["Siemens SIMATIC", "Allen-Bradley PLCs", "Schneider Electric Modicon", "GE iFIX"],
        "cvss_ics": 10.0,
    },
    {
        "id": "ICS-T0836",
        "name": "Modify Parameter (Setpoint Manipulation)",
        "mitre_ics": "T0836",
        "tactic": "IMPACT",
        "severity": "critical",
        "sector": ["energy", "water", "oil_gas", "manufacturing"],
        "description": "Attacker with OT access modifies process setpoints (temperature, pressure, flow rate) causing unsafe conditions.",
        "real_world": "TRITON malware targeted Safety Instrumented Systems to disable safety shutdowns before causing explosion",
        "kill_chain": [
            {"step": 1, "action": "Gain HMI or engineering workstation access"},
            {"step": 2, "action": "Identify critical process variables (temperature, pressure, chemical dosing)"},
            {"step": 3, "action": "Modify setpoints gradually to avoid alarm (slow-burn attack)"},
            {"step": 4, "action": "Disable safety overrides via Safety Instrumented System (SIS) compromise"},
        ],
        "detection": ["Process historian: statistical deviation from baseline", "SIS alarm suppression detection", "OT SIEM (Claroty, Dragos)"],
        "mitigations": ["Safety Instrumented System (SIS) independent of DCS", "Setpoint change audit log"],
        "affected_systems": ["DCS (Distributed Control System)", "SIS (Safety Instrumented System)", "PLC ladder logic"],
        "cvss_ics": 10.0,
    },
    {
        "id": "ICS-T0869",
        "name": "OPC-UA Exploitation",
        "mitre_ics": "T0869",
        "tactic": "LATERAL_MOVEMENT",
        "severity": "high",
        "sector": ["manufacturing", "energy"],
        "description": "OPC-UA (OT standard protocol) exploited for lateral movement between ICS components when improperly configured.",
        "real_world": "Multiple cases of unauthenticated OPC-UA servers exposed in industrial networks",
        "kill_chain": [
            {"step": 1, "action": "Identify OPC-UA servers (port 4840) on OT network"},
            {"step": 2, "action": "Exploit unauthenticated or weakly authenticated OPC-UA endpoints"},
            {"step": 3, "action": "Browse OPC-UA node tree to discover all process variables"},
            {"step": 4, "action": "Write to OPC-UA nodes to modify process values"},
        ],
        "detection": ["OPC-UA anomaly detection", "Alert on new OPC-UA clients connecting"],
        "mitigations": ["OPC-UA security mode: SignAndEncrypt", "Certificate-based authentication", "Allowlist OPC-UA clients"],
        "affected_systems": ["OPC-UA servers in any DCS/SCADA"],
        "cvss_ics": 8.5,
    },
]

BR_ICS_CONTEXT = {
    "energy": {
        "label": "Setor Elétrico Brasileiro",
        "regulation": "ONS, ANEEL, Res. 1000/2021",
        "context": "Brasil tem 170GW de capacidade instalada. Ataques ao SCADA de distribuidoras impactam milhões.",
    },
    "oil_gas": {
        "label": "Petróleo & Gás",
        "regulation": "ANP, ABNT NBR IEC 62443",
        "context": "Plataformas offshore com sistemas OT conectados via satélite — vetor de ataque remoto.",
    },
    "water": {
        "label": "Saneamento Básico",
        "regulation": "ANA, Marco Legal do Saneamento (Lei 14.026/2020)",
        "context": "Oldsmar-style attack: acesso remoto a sistema de tratamento de água.",
    },
    "manufacturing": {
        "label": "Indústria 4.0",
        "regulation": "ABNT NBR IEC 62443",
        "context": "Fábricas conectadas via Ethernet industrial são alvo crescente de ransomware OT.",
    },
}

SECTORS = list(BR_ICS_CONTEXT.keys())


def list_techniques(sector=None):
    if sector:
        return [t for t in ICS_TECHNIQUES if sector in t.get("sector", [])]
    return ICS_TECHNIQUES


def get_technique(tid):
    return next((t for t in ICS_TECHNIQUES if t["id"] == tid), None)


def simulate_technique(tid, target, sector="energy"):
    t = get_technique(tid)
    if not t:
        raise ValueError(f"Technique {tid} not found")
    return {
        "technique_id": tid,
        "name": t["name"],
        "tactic": t["tactic"],
        "severity": t["severity"],
        "target": target,
        "sector": sector,
        "status": "simulated",
        "kill_chain": t["kill_chain"],
        "real_world_example": t.get("real_world", ""),
        "br_context": BR_ICS_CONTEXT.get(sector, {}),
        "findings": [f"[SIMULADO] {t['name']} contra {target}", f"Impacto: {t['description']}"],
    }


def get_sector_risk(sector):
    techs = list_techniques(sector)
    return {
        "sector": sector,
        "br_context": BR_ICS_CONTEXT.get(sector, {}),
        "applicable_techniques": len(techs),
        "critical_techniques": sum(1 for t in techs if t["severity"] == "critical"),
        "techniques": techs,
    }
