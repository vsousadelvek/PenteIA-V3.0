"""Regras Wazuh combinadas: Sentinel + PenteIA BAS.

Fonte base: sec365-Org/Sentinel/src/export/wazuh.py (rule specs de produção).
Combinadas com mapeamento MITRE do PenteIA para enriquecer com técnicas BAS.
Usa stdlib xml.etree — sem dependências externas.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

# Mapeamento rule_id → (technique, tactic) — catálogo do Sentinel
MITRE_CATALOG: dict[str, tuple[str, str]] = {
    "brute_force_ssh":             ("T1110.001", "Credential Access"),
    "password_spraying":           ("T1110.003", "Credential Access"),
    "ssh_pivot_internal":          ("T1021.004", "Lateral Movement"),
    "sudo_failed_repeated":        ("T1548.003", "Privilege Escalation"),
    "port_scan_paloalto":          ("T1046",     "Discovery"),
    "palo_alto_threat":            ("T1190",     "Initial Access"),
    "palo_alto_rdp_bruteforce":    ("T1110.001", "Credential Access"),
    "palo_alto_smb_lateral":       ("T1021.002", "Lateral Movement"),
    "palo_alto_exploit":           ("T1203",     "Execution"),
    "toolkit_reverse_shell":       ("T1059.004", "Execution"),
    "toolkit_log4j":               ("T1203",     "Execution"),
    "toolkit_ransomware_enc":      ("T1486",     "Impact"),
    "suspicious_service_start":    ("T1543.002", "Persistence"),
    "port_scan_kernel":            ("T1046",     "Discovery"),
    "malware_detected":            ("T1204.002", "Execution"),
    "http_sql_injection":          ("T1190",     "Initial Access"),
    "http_xss":                    ("T1059.007", "Execution"),
    "ssh_failed_root":             ("T1110.001", "Credential Access"),
    "privilege_escalation_failed": ("T1548",     "Privilege Escalation"),
    "credential_dumping":          ("T1003",     "Credential Access"),
    "powershell_encoded_command":  ("T1059.001", "Execution"),
    "powershell_download_iex":     ("T1059.001", "Execution"),
    "windows_lolbas_abuse":        ("T1218",     "Defense Evasion"),
    "dns_exfil_suspect":           ("T1071.004", "Command and Control"),
    "tor_exit_node_seen":          ("T1090.003", "Command and Control"),
    "login_from_new_country":      ("T1078",     "Initial Access"),
    "impossible_travel":           ("T1078",     "Initial Access"),
    "shadow_copy_deletion":        ("T1490",     "Impact"),
    "ransomware_mass_modification": ("T1486",    "Impact"),
    "windows_event_log_cleared":   ("T1070.001", "Defense Evasion"),
    "security_service_stopped":    ("T1562.001", "Defense Evasion"),
    "powershell_bypass":           ("T1059.001", "Execution"),
    "suspicious_c2_connection":    ("T1071",     "Command and Control"),
    "rdp_success_after_failures":  ("T1078",     "Initial Access"),
    "confirmed_ransomware_chain":  ("T1486",     "Impact"),
}

SEVERITY_TO_LEVEL = {"critical": 14, "high": 12, "medium": 8, "low": 5}

# Regras de produção do Sentinel
SENTINEL_RULE_SPECS: list[dict] = [
    {"id": 100100, "rule_id": "brute_force_ssh",       "severity": "high",     "match": "^Failed (?:password|none) for",                         "description": "SSH brute force detectado",           "frequency": 5,  "timeframe": 300},
    {"id": 100101, "rule_id": "password_spraying",     "severity": "high",     "match": "^Failed (?:password|none) for",                         "description": "Password spraying detectado",          "frequency": 5,  "timeframe": 600},
    {"id": 100102, "rule_id": "ssh_pivot_internal",    "severity": "high",     "match": "^Accepted (?:password|publickey) for",                  "description": "SSH aceito de IP privado (pivo interno)"},
    {"id": 100103, "rule_id": "ssh_failed_root",       "severity": "medium",   "match": "Failed (?:password|none) for (?:invalid user )?root",   "description": "Tentativa SSH contra root"},
    {"id": 100104, "rule_id": "sudo_failed_repeated",  "severity": "medium",   "match": r"\d+ incorrect password attempts",                      "description": "sudo: tentativas falhadas repetidas"},
    {"id": 100105, "rule_id": "toolkit_reverse_shell", "severity": "critical", "match": r"nc\s+[-\w]*e\b.*?/bin/(?:sh|bash)|bash\s+-i\s+>&\s*/dev/tcp/", "description": "Reverse shell detectada"},
    {"id": 100106, "rule_id": "toolkit_log4j",         "severity": "critical", "match": "JNDI-Injection-Exploit|log4j-payload-generator|jndi:(?:ldap|rmi)", "description": "Toolkit Log4Shell/JNDI"},
    {"id": 100107, "rule_id": "toolkit_ransomware_enc","severity": "critical", "match": r"openssl\s+enc\s+-(?:aes|des)|RansomwareBehavior",        "description": "Ransomware: criptografia em massa"},
    {"id": 100108, "rule_id": "suspicious_service_start","severity": "high",   "match": r"suspicious_process\.service",                          "description": "Serviço com nome suspeito ativado"},
    {"id": 100109, "rule_id": "port_scan_kernel",      "severity": "medium",   "match": "Possible port scan detected from",                      "description": "Port scan detectado (iptables)"},
    {"id": 100110, "rule_id": "palo_alto_threat",      "severity": "high",     "match": r"threat_name=\S+",                                      "description": "Palo Alto: threat_name presente"},
    {"id": 100112, "rule_id": "malware_detected",      "severity": "critical", "match": r"Malware detected:",                                    "description": "Antivirus reportou malware"},
    {"id": 100113, "rule_id": "http_sql_injection",    "severity": "high",     "match": r"'\s*OR\s+'|UNION\s+SELECT",                            "description": "SQL injection em logs HTTP"},
    {"id": 100114, "rule_id": "http_xss",              "severity": "medium",   "match": r"<script",                                              "description": "XSS em logs HTTP"},
    {"id": 100115, "rule_id": "privilege_escalation_failed","severity": "high","match": "failed_privilege_escalation",                           "description": "Escalação de privilégio falhada"},
    {"id": 100116, "rule_id": "powershell_encoded_command","severity": "high", "match": r"powershell.*-[Ee]ncode[Dd]Command",                     "description": "PowerShell com comando codificado"},
    {"id": 100117, "rule_id": "windows_lolbas_abuse",  "severity": "high",     "match": r"mshta\.exe|regsvr32\.exe|certutil\.exe.*-urlcache",    "description": "LOLBAS: abuso de binário Windows"},
    {"id": 100118, "rule_id": "shadow_copy_deletion",  "severity": "critical", "match": r"vssadmin.*delete|wmic.*shadowcopy.*delete",            "description": "Shadow copies deletadas (ransomware)"},
    {"id": 100119, "rule_id": "windows_event_log_cleared","severity": "high",  "match": "Security Audit log cleared|wevtutil.*cl",               "description": "Log de eventos Windows limpo"},
    {"id": 100120, "rule_id": "dns_exfil_suspect",     "severity": "high",     "match": r"[a-zA-Z0-9+/]{30,}\.[a-z]{2,}",                       "description": "DNS exfiltration suspeita (payload base64)"},
    {"id": 100121, "rule_id": "credential_dumping",    "severity": "critical", "match": r"procdump.*lsass|mimikatz|sekurlsa::logonpasswords",    "description": "Despejo de credenciais detectado"},
    {"id": 100122, "rule_id": "suspicious_c2_connection","severity": "critical","match": r"beacon_interval|cobalt.?strike|empire.*stager",        "description": "Comunicação C2 suspeita"},
    {"id": 100123, "rule_id": "impossible_travel",     "severity": "high",     "match": r"impossible_travel_detected|login.*country.*changed",   "description": "Viagem impossível (login de dois países)"},
]


def _indent(elem: ET.Element, level: int = 0) -> None:
    indent = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = indent + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = indent
        for child in elem:
            _indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = indent
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = indent


def _build_sentinel_rule(spec: dict) -> ET.Element:
    technique, tactic = MITRE_CATALOG.get(spec["rule_id"], ("T0000", "Unknown"))
    attrs = {"id": str(spec["id"]), "level": str(SEVERITY_TO_LEVEL.get(spec["severity"], 8))}
    if spec.get("frequency"):
        attrs["frequency"] = str(spec["frequency"])
    if spec.get("timeframe"):
        attrs["timeframe"] = str(spec["timeframe"])
    rule = ET.Element("rule", **attrs)

    match = ET.SubElement(rule, "match", type="pcre2")
    match.text = spec["match"]

    desc = ET.SubElement(rule, "description")
    desc.text = spec["description"]

    group = ET.SubElement(rule, "group")
    safe_tech = technique.replace(".", "_")
    group.text = f"sentinel_penteia,{spec['rule_id']},mitre_{safe_tech},"

    mitre_el = ET.SubElement(rule, "mitre")
    ET.SubElement(mitre_el, "id").text = technique
    ET.SubElement(mitre_el, "tactic").text = tactic
    return rule


def _build_bas_rule(rule_id_num: int, technique_id: str, name: str,
                    severity: str, tactic: str, cvss: float) -> ET.Element:
    level = SEVERITY_TO_LEVEL.get(severity.lower(), 8)
    rule = ET.Element("rule", id=str(rule_id_num), level=str(level))

    desc = ET.SubElement(rule, "description")
    desc.text = f"PenteIA BAS: {name} detectado (CVSS {cvss})"

    field = ET.SubElement(rule, "field", name="mitre.id")
    field.text = technique_id

    group = ET.SubElement(rule, "group")
    safe_tech = technique_id.replace(".", "_")
    safe_tactic = tactic.lower().replace(" ", "_").replace("&", "and")
    group.text = f"penteia_bas,mitre,{safe_tactic},{safe_tech},"

    mitre_el = ET.SubElement(rule, "mitre")
    ET.SubElement(mitre_el, "id").text = technique_id
    ET.SubElement(mitre_el, "tactic").text = tactic
    return rule


def generate_sentinel_rules() -> str:
    """Gera regras Wazuh do catálogo Sentinel (produção)."""
    root = ET.Element("group", name="sentinel_threat_hunting,")
    for spec in SENTINEL_RULE_SPECS:
        root.append(_build_sentinel_rule(spec))
    _indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def generate_bas_rules(techniques: list[dict], start_id: int = 200000) -> str:
    """Gera regras Wazuh a partir das técnicas encontradas pelo BAS.

    Args:
        techniques: lista de dicts com keys: id, name, severity, tactic, cvss
        start_id: ID Wazuh inicial para as regras (default: 200000)
    """
    root = ET.Element("group", name="penteia_bas,")
    seen = set()
    rule_id = start_id
    for t in techniques:
        tid = t.get("id", "")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        root.append(_build_bas_rule(
            rule_id_num=rule_id,
            technique_id=tid,
            name=t.get("name", tid),
            severity=t.get("severity", "medium"),
            tactic=t.get("tactic", "Unknown"),
            cvss=float(t.get("cvss", 0)),
        ))
        rule_id += 1
    _indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def generate_combined(techniques: list[dict] | None = None) -> str:
    """Gera arquivo combinado: regras Sentinel + BAS em um único XML."""
    root = ET.Element("group", name="penteia_combined,")

    # Seção 1: regras Sentinel
    comment = ET.Comment(" === SENTINEL THREAT HUNTING RULES (produção) === ")
    root.append(comment)
    for spec in SENTINEL_RULE_SPECS:
        root.append(_build_sentinel_rule(spec))

    # Seção 2: regras BAS
    if techniques:
        bas_comment = ET.Comment(" === PENTEIA BAS DISCOVERED TECHNIQUES === ")
        root.append(bas_comment)
        seen = set()
        rule_id = 200000
        for t in techniques:
            tid = t.get("id", "")
            if not tid or tid in seen:
                continue
            seen.add(tid)
            root.append(_build_bas_rule(
                rule_id_num=rule_id,
                technique_id=tid,
                name=t.get("name", tid),
                severity=t.get("severity", "medium"),
                tactic=t.get("tactic", "Unknown"),
                cvss=float(t.get("cvss", 0)),
            ))
            rule_id += 1

    _indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
