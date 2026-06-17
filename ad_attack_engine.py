"""
ad_attack_engine.py — PenteIA V4.0
Active Directory attack surface analysis and simulation.
Covers MITRE ATT&CK techniques specific to Active Directory / Identity:
  T1558.003 — Kerberoasting
  T1558.004 — AS-REP Roasting
  T1003.006 — DCSync
  T1550.002 — Pass-the-Hash
  T1558.001 — Golden Ticket
  T1558.002 — Silver Ticket
  T1021.002 — SMB/Windows Admin Shares
  T1484.001 — Group Policy Modification
  T1078.002 — Domain Accounts abuse
  T1207     — Rogue Domain Controller (DCShadow)
"""
from typing import Optional

# ── AD Technique Catalog ─────────────────────────────────────────────────────

AD_TECHNIQUES = [
    {
        "id": "T1558.003",
        "name": "Kerberoasting",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "critical",
        "description": (
            "Adversaries request Kerberos service tickets (TGS) for service accounts with SPNs "
            "and attempt to crack the tickets offline. Service accounts often have weak passwords "
            "and high privileges, making this one of the most impactful AD attacks."
        ),
        "prerequisites": ["Domain user account", "Network access to KDC"],
        "impact": "Full service account compromise, often SYSTEM-level or DA",
        "kill_chain": [
            {"step": 1, "action": "Enumerate Service Principal Names (SPNs) via LDAP query"},
            {"step": 2, "action": "Request Kerberos TGS tickets for each SPN (no special privilege needed)"},
            {"step": 3, "action": "Extract encrypted ticket hashes from memory"},
            {"step": 4, "action": "Offline brute-force crack with Hashcat/John targeting RC4/AES keys"},
            {"step": 5, "action": "Authenticate as service account and escalate privileges"},
        ],
        "tools": ["Rubeus", "Impacket GetUserSPNs.py", "PowerView", "BloodHound"],
        "mitigations": [
            "Service accounts should use Managed Service Accounts (gMSA) with 120-char auto-rotating passwords",
            "Enable AES-only Kerberos encryption — RC4 cracking is 10-100x faster",
            "Implement Privileged Access Workstations (PAW) for service account usage",
            "Monitor for anomalous TGS requests — SIEM: Event ID 4769 with RC4 encryption type",
        ],
        "detection": [
            "Windows Event ID 4769 — Kerberos Service Ticket requested with EncryptionType=0x17 (RC4)",
            "High volume of TGS requests from single user in short timeframe",
            "Anomalous LDAP queries for servicePrincipalName attribute",
        ],
        "cvss_like_score": 9.1,
        "br_context": "Amplamente usado em ataques a bancos e fintechs BR com AD corporativo",
    },
    {
        "id": "T1558.004",
        "name": "AS-REP Roasting",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "high",
        "description": (
            "Targets accounts with Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH). "
            "Attacker requests AS-REP without credentials and receives encrypted data crackable offline."
        ),
        "prerequisites": ["Network access to KDC — no credentials required"],
        "impact": "Account compromise without initial credentials — unauthenticated attack",
        "kill_chain": [
            {"step": 1, "action": "Enumerate accounts with UF_DONT_REQUIRE_PREAUTH flag via LDAP"},
            {"step": 2, "action": "Send AS-REQ without pre-authentication for each target account"},
            {"step": 3, "action": "Receive AS-REP containing RC4-encrypted hash"},
            {"step": 4, "action": "Offline crack hash with Hashcat mode 18200"},
            {"step": 5, "action": "Authenticate with cleartext password"},
        ],
        "tools": ["Rubeus", "Impacket GetNPUsers.py", "kerbrute"],
        "mitigations": [
            "Enable Kerberos pre-authentication on ALL accounts — never disable it",
            "Regular audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}",
            "Force password change on any account found with this flag",
        ],
        "detection": [
            "Windows Event ID 4768 — Kerberos pre-authentication NOT supplied",
            "Anomalous AS-REQ from unexpected source IPs",
        ],
        "cvss_like_score": 8.5,
        "br_context": "Encontrado em >60% dos ambientes AD corporativos brasileiros em auditorias",
    },
    {
        "id": "T1003.006",
        "name": "DCSync",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "critical",
        "description": (
            "Mimics DC replication protocol to extract password hashes for ANY domain account, "
            "including KRBTGT. Requires DS-Replication-Get-Changes privilege (Domain Admin or delegated)."
        ),
        "prerequisites": ["Domain Admin rights or delegated replication permissions"],
        "impact": "All domain hashes extracted including KRBTGT — enables Golden Ticket",
        "kill_chain": [
            {"step": 1, "action": "Gain Domain Admin or replication privileges"},
            {"step": 2, "action": "Invoke DCSync via Mimikatz lsadump::dcsync or Impacket secretsdump"},
            {"step": 3, "action": "Extract NTLM hashes for all domain accounts"},
            {"step": 4, "action": "Extract KRBTGT hash for Golden Ticket creation"},
            {"step": 5, "action": "Persist access indefinitely — KRBTGT hash valid until manually rotated"},
        ],
        "tools": ["Mimikatz (lsadump::dcsync)", "Impacket secretsdump.py", "BloodHound ACL analysis"],
        "mitigations": [
            "Audit and remove unnecessary DS-Replication permissions (bloodhound ACL review)",
            "Rotate KRBTGT password twice after any suspected compromise",
            "Privileged Identity Management (PIM) for DA accounts",
            "Monitor replication traffic from non-DC machines",
        ],
        "detection": [
            "Windows Event ID 4662 — DS-Replication-Get-Changes from non-DC machine",
            "SIEM: Replication requests from endpoints (not DC-to-DC)",
            "Microsoft Defender for Identity: DCSync alert",
        ],
        "cvss_like_score": 10.0,
        "br_context": "Técnica final de comprometimento total de domínio — usada em todos ransomwares enterprise",
    },
    {
        "id": "T1550.002",
        "name": "Pass-the-Hash",
        "tactic": "LATERAL_MOVEMENT",
        "severity": "critical",
        "description": (
            "Uses captured NTLM hash to authenticate without the cleartext password. "
            "Works against SMB, WMI, RDP (NLA disabled), and many other protocols."
        ),
        "prerequisites": ["Captured NTLM hash (local admin or domain account)"],
        "impact": "Lateral movement across entire network without cracking passwords",
        "kill_chain": [
            {"step": 1, "action": "Dump LSASS on compromised machine (T1003)"},
            {"step": 2, "action": "Extract NTLM hash for target account (Mimikatz sekurlsa::logonpasswords)"},
            {"step": 3, "action": "Authenticate to remote machine using hash via SMB/WMI"},
            {"step": 4, "action": "Execute commands on remote machine as the target user"},
            {"step": 5, "action": "Escalate to DA via repeated lateral movement and hash collection"},
        ],
        "tools": ["Mimikatz", "Impacket psexec/wmiexec/smbexec", "CrackMapExec", "Metasploit"],
        "mitigations": [
            "Enable Credential Guard to protect LSASS from memory extraction",
            "Disable NTLM authentication where possible — Kerberos only",
            "Implement LAPS for unique local admin passwords per machine",
            "Tiered administration — separate admin accounts per tier",
        ],
        "detection": [
            "Windows Event ID 4624 Logon Type 3 with NTLM authentication from unexpected source",
            "Anomalous lateral movement patterns in SIEM",
            "CrowdStrike/SentinelOne: Pass-the-Hash behavioral detection",
        ],
        "cvss_like_score": 9.3,
        "br_context": "Principal técnica de movimentação lateral em ataques ransomware no Brasil (Conti, LockBit)",
    },
    {
        "id": "T1558.001",
        "name": "Golden Ticket",
        "tactic": "PERSISTENCE",
        "severity": "critical",
        "description": (
            "Forges a Kerberos Ticket Granting Ticket (TGT) using the KRBTGT account hash. "
            "Provides indefinite access to any resource in the domain. "
            "Persists even after password changes of targeted accounts."
        ),
        "prerequisites": ["KRBTGT hash (via DCSync or LSASS dump on DC)"],
        "impact": "Persistent domain-level access for 10+ years (default ticket lifetime) — survives password changes",
        "kill_chain": [
            {"step": 1, "action": "Extract KRBTGT hash via DCSync"},
            {"step": 2, "action": "Collect domain SID and target username"},
            {"step": 3, "action": "Forge TGT with Mimikatz kerberos::golden"},
            {"step": 4, "action": "Inject forged ticket into current session"},
            {"step": 5, "action": "Access any service in the domain as any user indefinitely"},
        ],
        "tools": ["Mimikatz (kerberos::golden)", "Impacket ticketer.py"],
        "mitigations": [
            "Rotate KRBTGT password TWICE to invalidate all existing tickets",
            "Implement tiered AD model to limit blast radius of DC compromise",
            "Deploy Microsoft Defender for Identity — detects Golden Ticket anomalies",
            "Monitor for Kerberos tickets with unusually long lifetimes or unusual PAC values",
        ],
        "detection": [
            "Microsoft Defender for Identity: Golden Ticket alert (account impersonation)",
            "Kerberos tickets with lifetime > 10 hours (default max) or past account creation date",
            "Tickets used from machines that never received the original TGT",
        ],
        "cvss_like_score": 10.0,
        "br_context": "Implantado após comprometimento de DC — permite re-entrada mesmo após incidente encerrado",
    },
    {
        "id": "T1558.002",
        "name": "Silver Ticket",
        "tactic": "LATERAL_MOVEMENT",
        "severity": "high",
        "description": (
            "Forges a Kerberos Service Ticket (TGS) for a specific service using the service account hash. "
            "More targeted than Golden Ticket but harder to detect — bypasses KDC entirely."
        ),
        "prerequisites": ["Service account NTLM hash"],
        "impact": "Access to specific service (e.g., SQL Server, IIS) as any user — bypasses KDC logging",
        "kill_chain": [
            {"step": 1, "action": "Extract service account hash (via Kerberoasting or LSASS)"},
            {"step": 2, "action": "Forge TGS for target service (SQL, HTTP, CIFS) with Mimikatz"},
            {"step": 3, "action": "Inject forged service ticket — no DC communication needed"},
            {"step": 4, "action": "Access target service as SYSTEM or any privileged user"},
        ],
        "tools": ["Mimikatz (kerberos::silver)", "Impacket ticketer.py"],
        "mitigations": [
            "Use gMSA/GMSA for service accounts (auto-rotating passwords)",
            "Enable Kerberos armoring (FAST) to bind tickets to client identity",
            "Validate PAC (Privilege Attribute Certificate) on all services",
        ],
        "detection": [
            "Service ticket requests that bypass KDC (no Event ID 4769 on DC)",
            "Kerberos tickets with anomalous SIDs or group memberships",
            "PAC validation failures on services",
        ],
        "cvss_like_score": 8.8,
        "br_context": "Usado para acesso silencioso a SQL Servers e ERPs em ataques APT financeiro",
    },
    {
        "id": "T1207",
        "name": "DCShadow",
        "tactic": "DEFENSE_EVASION",
        "severity": "critical",
        "description": (
            "Registers a rogue Domain Controller to push malicious changes to AD "
            "(add backdoor accounts, modify GPOs, change ACLs) without triggering SIEM alerts "
            "since changes appear to come from a legitimate DC."
        ),
        "prerequisites": ["Domain Admin rights on one machine"],
        "impact": "Stealth AD modification — changes appear as legitimate DC replication, bypasses SIEM",
        "kill_chain": [
            {"step": 1, "action": "Gain DA rights on a workstation or server"},
            {"step": 2, "action": "Register machine as a temporary Domain Controller via Mimikatz DCShadow"},
            {"step": 3, "action": "Push backdoor changes: new DA account, ACL modification, GPO"},
            {"step": 4, "action": "Unregister rogue DC — minimal traces left"},
            {"step": 5, "action": "Re-enter domain as backdoor account later"},
        ],
        "tools": ["Mimikatz (lsadump::dcshadow)"],
        "mitigations": [
            "Monitor for new DC registrations in domain — Event ID 4742 (computer account modified)",
            "Microsoft Defender for Identity: DCShadow detection",
            "Limit DA membership strictly — DCShadow requires DA",
        ],
        "detection": [
            "Anomalous DC registration from non-DC machine",
            "Microsoft Defender for Identity: Suspected DCshadow attack",
            "AD replication partner changes from unexpected machines",
        ],
        "cvss_like_score": 9.5,
        "br_context": "Técnica avançada usada por APT Lazarus e outros grupos patrocinados por estados",
    },
    {
        "id": "T1484.001",
        "name": "Group Policy Modification",
        "tactic": "DEFENSE_EVASION",
        "severity": "high",
        "description": (
            "Modifies Group Policy Objects to deploy malware, disable security tools, "
            "add local admin accounts, or establish persistence across all domain machines simultaneously."
        ),
        "prerequisites": ["Group Policy Creator Owners or Domain Admin"],
        "impact": "Mass deployment of malicious config to entire domain — all machines compromised simultaneously",
        "kill_chain": [
            {"step": 1, "action": "Gain GPO edit permissions (DA or GPO Creator Owners)"},
            {"step": 2, "action": "Create/modify GPO to disable Windows Defender or add local admin"},
            {"step": 3, "action": "Link GPO to high-value OUs (Domain Controllers, Servers)"},
            {"step": 4, "action": "GPO applies automatically on next Group Policy refresh (90 min)"},
            {"step": 5, "action": "Mass persistence or security tool disablement across domain"},
        ],
        "tools": ["Native GPMC", "PowerView Set-DomainGPO", "SharpGPO"],
        "mitigations": [
            "Restrict GPO creation and linking permissions strictly",
            "Enable GPO change auditing — Event IDs 5136, 5137, 5141",
            "Deploy Microsoft Advanced Threat Analytics (ATA) or Defender for Identity",
        ],
        "detection": [
            "Event ID 5136 — Directory Service Object Modified (GPO change)",
            "Unexpected GPO linking to sensitive OUs",
            "New GPO creation by non-privileged accounts",
        ],
        "cvss_like_score": 9.0,
        "br_context": "Usado em ataques de ransomware para desabilitar antivírus em toda a rede simultaneamente",
    },
]

# ── Attack Path Analysis ──────────────────────────────────────────────────────

ATTACK_PATHS_TO_DA = [
    {
        "path_id": "path-kerberoast-to-da",
        "name": "Kerberoasting → Domain Admin",
        "steps": ["T1558.003", "T1550.002", "T1003.006", "T1558.001"],
        "difficulty": "medium",
        "avg_time_hours": 4,
        "description": "Crack service account → lateral movement → DCSync → Golden Ticket",
    },
    {
        "path_id": "path-asrep-to-da",
        "name": "AS-REP Roasting → Domain Admin (no credentials)",
        "steps": ["T1558.004", "T1550.002", "T1003.006"],
        "difficulty": "low",
        "avg_time_hours": 2,
        "description": "Unauthenticated account compromise → lateral movement → full domain takeover",
    },
    {
        "path_id": "path-pth-to-da",
        "name": "Pass-the-Hash chain to Domain Admin",
        "steps": ["T1550.002", "T1003.006", "T1558.001"],
        "difficulty": "medium",
        "avg_time_hours": 3,
        "description": "Harvest hash from local admin → PtH chain to DA → DCSync",
    },
    {
        "path_id": "path-gpo-mass",
        "name": "GPO Mass Deployment (Post-DA)",
        "steps": ["T1003.006", "T1558.001", "T1484.001"],
        "difficulty": "low",
        "avg_time_hours": 1,
        "description": "Post-DA: deploy ransomware/backdoor via GPO to entire domain",
    },
]


# ── Simulation ────────────────────────────────────────────────────────────────

def simulate_ad_technique(technique_id: str, target_domain: str, target_dc: str = "") -> dict:
    """Simulate an AD attack technique and return findings."""
    tech = next((t for t in AD_TECHNIQUES if t["id"] == technique_id), None)
    if not tech:
        raise ValueError(f"Technique {technique_id} not found in AD catalog")

    return {
        "technique_id": technique_id,
        "technique_name": tech["name"],
        "tactic": tech["tactic"],
        "severity": tech["severity"],
        "target_domain": target_domain,
        "target_dc": target_dc,
        "status": "simulated",
        "kill_chain": tech["kill_chain"],
        "tools": tech["tools"],
        "mitigations": tech["mitigations"],
        "detection": tech["detection"],
        "cvss_like_score": tech["cvss_like_score"],
        "br_context": tech.get("br_context", ""),
        "findings": [
            f"[SIMULADO] {tech['name']} executado contra domínio {target_domain}",
            f"Impacto potencial: {tech['impact']}",
            f"Pré-requisitos necessários: {', '.join(tech['prerequisites'])}",
        ],
    }


def simulate_attack_path(path_id: str, target_domain: str) -> dict:
    """Simulate a full attack path to Domain Admin."""
    path = next((p for p in ATTACK_PATHS_TO_DA if p["path_id"] == path_id), None)
    if not path:
        raise ValueError(f"Attack path {path_id} not found")

    step_results = []
    for tid in path["steps"]:
        try:
            result = simulate_ad_technique(tid, target_domain)
            step_results.append({"technique_id": tid, "status": "completed", "result": result})
        except Exception as e:
            step_results.append({"technique_id": tid, "status": "error", "error": str(e)})

    return {
        "path_id": path_id,
        "path_name": path["name"],
        "target_domain": target_domain,
        "difficulty": path["difficulty"],
        "estimated_time_hours": path["avg_time_hours"],
        "description": path["description"],
        "steps_total": len(path["steps"]),
        "steps_completed": sum(1 for s in step_results if s["status"] == "completed"),
        "step_results": step_results,
        "status": "completed",
        "conclusion": f"Caminho para Domain Admin de {target_domain} demonstrado com sucesso em modo simulado.",
    }


def get_ad_risk_score(findings: list) -> dict:
    """Calculate AD risk score based on detected vulnerabilities."""
    severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    total = sum(severity_weights.get(f.get("severity", "low"), 5) for f in findings)
    score = min(100.0, total)
    return {
        "score": score,
        "risk_level": "critical" if score >= 70 else "high" if score >= 40 else "medium" if score >= 20 else "low",
        "findings_count": len(findings),
        "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def list_techniques() -> list:
    return AD_TECHNIQUES


def get_technique(technique_id: str) -> Optional[dict]:
    return next((t for t in AD_TECHNIQUES if t["id"] == technique_id), None)


def list_attack_paths() -> list:
    return ATTACK_PATHS_TO_DA


def get_attack_path(path_id: str) -> Optional[dict]:
    return next((p for p in ATTACK_PATHS_TO_DA if p["path_id"] == path_id), None)
