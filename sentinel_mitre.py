"""Catálogo MITRE ATT&CK por rule_id.

Estrutura: rule_id → (technique, tactic).
- `technique` é T<NNN>[.NNN] OU None quando a regra é tática-genérica
  (ex.: detectores de ML que sinalizam comportamento anômalo sem mapear
  para uma técnica específica). DAT-015: TA<NNNN> são IDs de tactic, não
  podem aparecer como technique — usar None.
- `tactic` é o nome legível canônico (ex.: "Credential Access").
"""
from __future__ import annotations

CATALOG: dict[str, tuple[str | None, str]] = {
    "brute_force_ssh": ("T1110.001", "Credential Access"),
    "password_spraying": ("T1110.003", "Credential Access"),
    "ssh_pivot_internal": ("T1021.004", "Lateral Movement"),
    "sudo_failed_repeated": ("T1548.003", "Privilege Escalation"),
    "port_scan_paloalto": ("T1046", "Discovery"),
    "palo_alto_threat": ("T1190", "Initial Access"),
    "palo_alto_rdp_bruteforce": ("T1110.001", "Credential Access"),
    "palo_alto_smb_lateral": ("T1021.002", "Lateral Movement"),
    "palo_alto_exploit": ("T1203", "Execution"),
    "toolkit_reverse_shell": ("T1059.004", "Execution"),
    "toolkit_log4j": ("T1203", "Execution"),
    "toolkit_ransomware_enc": ("T1486", "Impact"),
    "suspicious_service_start": ("T1543.002", "Persistence"),
    "port_scan_kernel": ("T1046", "Discovery"),
    "malware_detected": ("T1204.002", "Execution"),
    "http_sql_injection": ("T1190", "Initial Access"),
    "http_xss": ("T1059.007", "Execution"),
    "ssh_failed_root": ("T1110.001", "Credential Access"),
    "privilege_escalation_failed": ("T1548", "Privilege Escalation"),
    # ML detectors: tactic apenas, technique None (DAT-015)
    "ml_isolation_forest": (None, "Discovery"),
    "ml_rare_template": (None, "Discovery"),
    "ml_volume_burst": (None, "Discovery"),
    "ml_behavior_cluster": (None, "Discovery"),
    "ml_rare_combination": (None, "Discovery"),
    "palo_alto_blocked_high_risk": ("T1190", "Initial Access"),
    "palo_alto_malware_app_blocked": ("T1071.001", "Command and Control"),
    "blocklisted_ip_observed": ("T1071.001", "Command and Control"),
    "credential_dumping": ("T1003", "Credential Access"),
    "powershell_encoded_command": ("T1059.001", "Execution"),
    "powershell_download_iex": ("T1059.001", "Execution"),
    "windows_lolbas_abuse": ("T1218", "Defense Evasion"),
    "dns_exfil_suspect": ("T1071.004", "Command and Control"),
    "tor_exit_node_seen": ("T1090.003", "Command and Control"),
    "login_from_new_country": ("T1078", "Initial Access"),
    "impossible_travel": ("T1078", "Initial Access"),
    # KV semantic detectors
    "shadow_copy_deletion": ("T1490", "Impact"),
    "ransomware_mass_modification": ("T1486", "Impact"),
    "ransomware_file_rename": ("T1486", "Impact"),
    "ransom_note_created": ("T1486", "Impact"),
    "windows_event_log_cleared": ("T1070.001", "Defense Evasion"),
    "security_service_stopped": ("T1562.001", "Defense Evasion"),
    "powershell_bypass": ("T1059.001", "Execution"),
    "suspicious_c2_connection": ("T1071", "Command and Control"),
    "rdp_success_after_failures": ("T1078", "Initial Access"),
    # Chain correlation detectors
    "confirmed_ransomware_chain": ("T1486", "Impact"),
}


# Universo canônico de táticas — usado para popular heatmap com 0-counts (UI-020).
ALL_TACTICS: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)


# Catálogo dinâmico para regras customizadas — alimentado por
# `apply_custom_catalog()` quando custom_rules são carregadas/refrescadas.
_CUSTOM_CATALOG: dict[str, tuple[str | None, str]] = {}


def apply_custom_catalog(entries: dict[str, tuple[str | None, str]]) -> None:
    """Sobrescreve cache de mappings MITRE para custom rules."""
    global _CUSTOM_CATALOG
    _CUSTOM_CATALOG = dict(entries)


def lookup(rule_id: str) -> tuple[str | None, str]:
    if rule_id in CATALOG:
        return CATALOG[rule_id]
    if rule_id in _CUSTOM_CATALOG:
        return _CUSTOM_CATALOG[rule_id]
    return (None, "-")

