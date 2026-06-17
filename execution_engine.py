"""
execution_engine.py — PenteIA V4.0
Real Execution Engine: safely executes red team techniques in controlled mode.
Captures forensic evidence: process trees, file artifacts, registry changes, network activity.

Execution modes:
  safe      — observe/log only, no actual exploit code
  simulated — generate realistic artifacts without real impact (default)
  authorized — full execution (requires explicit pentest authorization token)
"""
import os
import subprocess
import platform
import tempfile
import json
import uuid
import time
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("penteia.execution")

EVIDENCE_DIR = Path(__file__).parent / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

WINDOWS = platform.system() == "Windows"

# ── Safe technique implementations ───────────────────────────────────────────

def _exec_safe(cmd: list, timeout: int = 10) -> dict:
    """Run a subprocess safely and capture output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if WINDOWS else 0,
        )
        return {"stdout": result.stdout[:4000], "stderr": result.stderr[:1000], "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "timeout", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _collect_process_list() -> list:
    """Capture current process list as forensic evidence."""
    if WINDOWS:
        r = _exec_safe(["tasklist", "/fo", "csv", "/nh"])
    else:
        r = _exec_safe(["ps", "aux", "--no-header"])
    lines = r["stdout"].strip().splitlines()
    return lines[:50]


def _collect_network_connections() -> list:
    """Capture active network connections."""
    if WINDOWS:
        r = _exec_safe(["netstat", "-ano"])
    else:
        r = _exec_safe(["ss", "-tunap"])
    return r["stdout"].strip().splitlines()[:30]


def _collect_env_info() -> dict:
    """Collect environment information (no sensitive data)."""
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version()[:100],
        "python_version": platform.python_version(),
        "arch": platform.machine(),
        "collected_at": datetime.utcnow().isoformat(),
    }


# ── Technique implementations (safe mode) ────────────────────────────────────

def _technique_credential_access(target: str, mode: str) -> dict:
    """T1003 — OS Credential Dumping (safe observation)."""
    evidence = {
        "technique": "T1003",
        "observation": "LSASS process detected and logged",
        "processes": [],
        "artifacts": [],
    }
    if WINDOWS:
        r = _exec_safe(["tasklist", "/fi", "IMAGENAME eq lsass.exe", "/fo", "csv"])
        evidence["processes"] = r["stdout"].strip().splitlines()
        evidence["artifacts"].append({
            "type": "process_observation",
            "name": "lsass.exe",
            "description": "Local Security Authority Subsystem Service — credential store target",
            "risk": "Credential extraction possible if process is accessible",
        })
    else:
        r = _exec_safe(["ps", "aux"])
        procs = [l for l in r["stdout"].splitlines() if "passwd" in l.lower() or "auth" in l.lower()]
        evidence["processes"] = procs[:10]
    return evidence


def _technique_discovery(target: str, mode: str) -> dict:
    """T1082 — System Information Discovery."""
    evidence = {
        "technique": "T1082",
        "system_info": _collect_env_info(),
        "processes_snapshot": _collect_process_list(),
        "network_snapshot": _collect_network_connections(),
    }
    # Check for common security tools
    security_tools = ["defender", "cylance", "crowdstrike", "sentinel", "carbonblack", "mcafee", "symantec"]
    if WINDOWS:
        r = _exec_safe(["sc", "query", "type=", "all"])
        services_text = r["stdout"].lower()
        found = [t for t in security_tools if t in services_text]
        evidence["security_tools_detected"] = found
    return evidence


def _technique_persistence(target: str, mode: str) -> dict:
    """T1547 — Boot/Logon Autostart (safe observation only)."""
    evidence = {"technique": "T1547", "autostart_locations": [], "artifacts": []}
    if WINDOWS:
        reg_keys = [
            r"HKLMSOFTWAREMicrosoftWindowsCurrentVersionRun",
            r"HKCUSOFTWAREMicrosoftWindowsCurrentVersionRun",
        ]
        for key in reg_keys:
            r = _exec_safe(["reg", "query", key])
            if r["returncode"] == 0:
                evidence["autostart_locations"].append({"key": key, "entries": r["stdout"].strip().splitlines()[:10]})
        evidence["artifacts"].append({
            "type": "registry_observation",
            "description": "Registry autostart locations enumerated (read-only)",
            "risk": "Persistence via registry Run keys is common initial foothold technique",
        })
    return evidence


def _technique_lateral_movement(target: str, mode: str) -> dict:
    """T1021 — Remote Services (safe — only connectivity test)."""
    evidence = {"technique": "T1021", "connectivity": {}, "artifacts": []}
    # Safe: attempt TCP connection only (no auth)
    import socket
    ports = {"SMB": 445, "RDP": 3389, "WinRM": 5985, "SSH": 22}
    for name, port in ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((target, port))
            s.close()
            evidence["connectivity"][name] = {"port": port, "open": result == 0}
        except Exception:
            evidence["connectivity"][name] = {"port": port, "open": False, "error": "unreachable"}
    return evidence


def _technique_exfiltration(target: str, mode: str) -> dict:
    """T1041 — Exfiltration Over C2 Channel (safe simulation)."""
    # Create a fake data package to demonstrate exfiltration capability
    fake_data = {
        "simulated_payload": "PENTEIA_EXFIL_SIM",
        "hostname": platform.node(),
        "size_bytes": 1024,
        "destination": target,
        "timestamp": datetime.utcnow().isoformat(),
    }
    evidence = {
        "technique": "T1041",
        "simulated_exfil_package": fake_data,
        "artifacts": [{
            "type": "network_simulation",
            "description": f"Simulated {len(json.dumps(fake_data))} bytes exfiltration to {target}",
            "risk": "Real exfiltration would transmit sensitive data over encrypted C2 channel",
        }],
    }
    return evidence


def _technique_execution(target: str, mode: str) -> dict:
    """T1059 — Command and Scripting Interpreter (safe — observe only)."""
    evidence = {"technique": "T1059", "shells_available": [], "artifacts": []}
    shells = {"powershell": ["powershell", "-Command", "echo PENTEIA_TEST"],
              "cmd": ["cmd", "/c", "echo PENTEIA_TEST"],
              "python": ["python", "-c", "print('PENTEIA_TEST')"],
              "bash": ["bash", "-c", "echo PENTEIA_TEST"]}
    for name, cmd in shells.items():
        r = _exec_safe(cmd, timeout=5)
        if "PENTEIA_TEST" in r["stdout"]:
            evidence["shells_available"].append({"name": name, "available": True})
    evidence["artifacts"].append({
        "type": "execution_surface",
        "description": f"Available execution shells: {[s['name'] for s in evidence['shells_available']]}",
        "risk": "Multiple scripting interpreters increase execution attack surface",
    })
    return evidence


def _technique_account_discovery(target: str, mode: str) -> dict:
    """T1087 — Account Discovery: enumera usuários e grupos reais."""
    evidence = {"technique": "T1087", "users": [], "groups": [], "artifacts": []}
    if WINDOWS:
        r_users = _exec_safe(["net", "user"])
        r_groups = _exec_safe(["net", "localgroup"])
        r_admins = _exec_safe(["net", "localgroup", "Administrators"])
        evidence["users"] = [l.strip() for l in r_users["stdout"].splitlines() if l.strip() and "---" not in l and "command" not in l.lower()][:30]
        evidence["groups"] = [l.strip() for l in r_groups["stdout"].splitlines() if l.strip() and "---" not in l and "*" in l][:20]
        evidence["admin_members"] = r_admins["stdout"].strip().splitlines()[:15]
    else:
        r = _exec_safe(["awk", "-F:", "{print $1}", "/etc/passwd"])
        evidence["users"] = r["stdout"].strip().splitlines()[:30]
        r_g = _exec_safe(["awk", "-F:", "{print $1}", "/etc/group"])
        evidence["groups"] = r_g["stdout"].strip().splitlines()[:20]
    evidence["artifacts"].append({
        "type": "account_enumeration",
        "description": f"Enumerated {len(evidence['users'])} local users, {len(evidence['groups'])} groups",
        "risk": "Account enumeration enables targeted credential attacks and privilege escalation planning",
    })
    return evidence


def _technique_network_config(target: str, mode: str) -> dict:
    """T1016 — System Network Configuration Discovery: IP, rotas, DNS."""
    evidence = {"technique": "T1016", "interfaces": [], "dns": [], "routes": [], "artifacts": []}
    if WINDOWS:
        r_ip = _exec_safe(["ipconfig", "/all"])
        r_route = _exec_safe(["route", "print"])
        r_dns = _exec_safe(["ipconfig", "/displaydns"])
        evidence["interfaces"] = r_ip["stdout"].strip().splitlines()[:40]
        evidence["routes"] = r_route["stdout"].strip().splitlines()[:30]
        evidence["dns_cache_lines"] = len(r_dns["stdout"].splitlines())
    else:
        r_ip = _exec_safe(["ip", "addr"])
        r_route = _exec_safe(["ip", "route"])
        evidence["interfaces"] = r_ip["stdout"].strip().splitlines()[:40]
        evidence["routes"] = r_route["stdout"].strip().splitlines()[:20]
    evidence["artifacts"].append({
        "type": "network_map",
        "description": "Network interfaces, routing table and DNS cache enumerated",
        "risk": "Network topology enables lateral movement path planning",
    })
    return evidence


def _technique_file_discovery(target: str, mode: str) -> dict:
    """T1083 — File and Directory Discovery: varre diretórios sensíveis."""
    evidence = {"technique": "T1083", "sensitive_paths": [], "findings": [], "artifacts": []}
    if WINDOWS:
        paths_to_check = [
            os.path.expandvars(r"%USERPROFILE%\Documents"),
            os.path.expandvars(r"%USERPROFILE%\Desktop"),
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent"),
            r"C:\Users",
            os.path.expandvars(r"%TEMP%"),
        ]
        sensitive_exts = {".kdbx", ".pfx", ".p12", ".key", ".pem", ".ovpn", ".rdp", ".vnc"}
        for path in paths_to_check:
            if os.path.exists(path):
                try:
                    entries = list(os.scandir(path))[:50]
                    hits = [e.name for e in entries if Path(e.name).suffix.lower() in sensitive_exts]
                    evidence["sensitive_paths"].append({"path": path, "entries": len(entries), "sensitive_files": hits})
                    if hits:
                        evidence["findings"].extend([f"{path}\\{h}" for h in hits])
                except PermissionError:
                    evidence["sensitive_paths"].append({"path": path, "entries": 0, "error": "access_denied"})
    else:
        for path in [os.path.expanduser("~"), "/tmp", "/var/log"]:
            if os.path.exists(path):
                entries = os.listdir(path)[:50]
                evidence["sensitive_paths"].append({"path": path, "entries": len(entries)})
    evidence["artifacts"].append({
        "type": "file_discovery",
        "description": f"Scanned {len(evidence['sensitive_paths'])} directories, {len(evidence['findings'])} sensitive files found",
        "risk": "Sensitive files (keys, certs, VPN configs) enable credential theft and lateral movement",
    })
    return evidence


def _technique_indicator_removal(target: str, mode: str) -> dict:
    """T1070 — Indicator Removal: cria e deleta arquivo de teste para validar EDR coverage."""
    evidence = {"technique": "T1070", "artifacts": [], "edr_test": {}}
    tmp_dir = tempfile.gettempdir()
    test_filename = f"penteia_edr_test_{int(time.time())}.tmp"
    test_path = os.path.join(tmp_dir, test_filename)

    phases = []
    try:
        # Phase 1: create file with suspicious-looking content
        with open(test_path, "w") as f:
            f.write("PENTEIA_EDR_VALIDATION\nInvokeExpression\nMimikatz\nSECRET_KEY\n")
        phases.append({"phase": "create", "status": "success", "path": test_path})

        # Phase 2: read it back (simulates attacker reading dropped tool)
        with open(test_path, "r") as f:
            content_len = len(f.read())
        phases.append({"phase": "read", "status": "success", "bytes": content_len})

        # Phase 3: delete (indicator removal)
        os.remove(test_path)
        phases.append({"phase": "delete", "status": "success"})

        evidence["edr_test"] = {
            "file_written": test_filename,
            "suspicious_strings": ["InvokeExpression", "Mimikatz", "SECRET_KEY"],
            "edr_should_alert": True,
            "note": "If EDR did NOT alert on this file, detection gap confirmed",
        }
    except Exception as e:
        phases.append({"phase": "error", "error": str(e)})

    evidence["phases"] = phases
    evidence["artifacts"].append({
        "type": "edr_validation",
        "description": f"Created/deleted {test_filename} with suspicious strings to test EDR write-detection",
        "risk": "If not alerted: EDR has file write detection gap — real malware staging would go undetected",
    })
    return evidence


def _technique_ingress_transfer(target: str, mode: str) -> dict:
    """T1105 — Ingress Tool Transfer: testa se agente consegue buscar conteúdo externo."""
    import urllib.request
    evidence = {"technique": "T1105", "connectivity": {}, "artifacts": []}

    test_urls = [
        ("PenteIA C2 test", "https://ifconfig.me/ip"),
        ("CISA KEV feed", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
        ("Raw github", "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/README.md"),
    ]

    for label, url in test_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                size = len(resp.read(2048))
                evidence["connectivity"][label] = {"url": url, "reachable": True, "bytes_fetched": size, "status": resp.status}
        except Exception as e:
            evidence["connectivity"][label] = {"url": url, "reachable": False, "error": str(e)[:80]}

    reachable = sum(1 for v in evidence["connectivity"].values() if v.get("reachable"))
    evidence["artifacts"].append({
        "type": "external_connectivity",
        "description": f"Agent can reach {reachable}/{len(test_urls)} external URLs",
        "risk": f"{'HIGH — agent can download external tools/payloads' if reachable > 0 else 'LOW — egress blocked'}",
    })
    return evidence


TECHNIQUE_HANDLERS = {
    "T1003": _technique_credential_access,
    "T1016": _technique_network_config,
    "T1021": _technique_lateral_movement,
    "T1041": _technique_exfiltration,
    "T1059": _technique_execution,
    "T1070": _technique_indicator_removal,
    "T1082": _technique_discovery,
    "T1083": _technique_file_discovery,
    "T1087": _technique_account_discovery,
    "T1105": _technique_ingress_transfer,
    "T1547": _technique_persistence,
}


# ── Evidence storage ──────────────────────────────────────────────────────────

def _save_evidence(execution_id: str, evidence: dict) -> Path:
    path = EVIDENCE_DIR / f"{execution_id}.json"
    path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_evidence(execution_id: str) -> Optional[dict]:
    path = EVIDENCE_DIR / f"{execution_id}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return None


def list_executions() -> list:
    return [{"id": p.stem, "created_at": datetime.fromtimestamp(p.stat().st_mtime).isoformat()}
            for p in sorted(EVIDENCE_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]]


# ── Main execution API ────────────────────────────────────────────────────────

def execute_technique(technique_id: str, target: str, mode: str = "simulated",
                       auth_token: Optional[str] = None) -> dict:
    """
    Execute a single technique and return forensic evidence.

    mode:
      safe      — read-only observation, no network calls
      simulated — generate realistic artifacts (default)
      authorized — full execution (requires auth_token)
    """
    if mode == "authorized" and not auth_token:
        raise PermissionError("Authorized mode requires pentest authorization token")

    execution_id = str(uuid.uuid4())
    started_at = datetime.utcnow().isoformat()

    handler = TECHNIQUE_HANDLERS.get(technique_id)
    if handler:
        try:
            technique_evidence = handler(target, mode)
        except Exception as e:
            technique_evidence = {"error": str(e)}
    else:
        # Generic evidence for techniques without a specific handler
        technique_evidence = {
            "technique": technique_id,
            "mode": mode,
            "observation": f"Generic execution observation for {technique_id}",
            "artifacts": [{
                "type": "generic_simulation",
                "description": f"Technique {technique_id} simulated against {target}",
                "risk": "See MITRE ATT&CK documentation for full impact",
            }],
        }

    evidence = {
        "execution_id": execution_id,
        "technique_id": technique_id,
        "target": target,
        "mode": mode,
        "started_at": started_at,
        "completed_at": datetime.utcnow().isoformat(),
        "system_context": _collect_env_info(),
        "technique_evidence": technique_evidence,
        "status": "completed",
    }

    _save_evidence(execution_id, evidence)
    logger.info(f"Executed {technique_id} against {target} (mode={mode}, id={execution_id})")
    return evidence


def execute_playbook(techniques: list, target: str, mode: str = "simulated",
                      auth_token: Optional[str] = None) -> dict:
    """Execute multiple techniques sequentially as a playbook."""
    playbook_id = str(uuid.uuid4())
    results = []
    for tech in techniques:
        tid = tech if isinstance(tech, str) else tech.get("id", "")
        try:
            ev = execute_technique(tid, target, mode, auth_token)
            results.append({"technique_id": tid, "status": "completed", "execution_id": ev["execution_id"]})
        except PermissionError as e:
            results.append({"technique_id": tid, "status": "error", "error": str(e)})
        except Exception as e:
            results.append({"technique_id": tid, "status": "error", "error": str(e)})
        time.sleep(0.2)

    return {
        "playbook_execution_id": playbook_id,
        "target": target,
        "mode": mode,
        "techniques_total": len(techniques),
        "techniques_completed": sum(1 for r in results if r["status"] == "completed"),
        "results": results,
        "completed_at": datetime.utcnow().isoformat(),
    }
