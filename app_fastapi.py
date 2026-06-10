#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PenteIA v4.0 - FastAPI Web Dashboard
Modern, fast REST API for red team operations
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import json
import os
from pathlib import Path

# Import PenteIA modules
from penteia_v4_orchestrator import PenteIAv4Orchestrator
from c2_framework import C2Controller
from bas_engine import BASPlaybookRunner, Playbook
from automated_reporting import JinjaReportGenerator, ReportExporter
from memory_evasion import SleepObfuscator
from edr_evasion_core import SandboxDetector
from ddos_testing import DDoSTestingEngine, DDoSConfig, DDoSMethod
from recon import resolver_dominio, scan_portas, extrair_host

# ============================================================================
# FastAPI App Setup
# ============================================================================

app = FastAPI(
    title="PenteIA v4.0",
    description="Advanced Red Team Platform",
    version="4.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files & Templates - use absolute path
base_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(base_dir, "static")
templates_dir = os.path.join(base_dir, "templates")

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# ============================================================================
# Models
# ============================================================================

class DDoSStartRequest(BaseModel):
    target_host: str
    target_port: int = 80
    method: str = "http_flood"
    duration: int = 60
    pps: int = 100
    threads: int = 4
    test_name: Optional[str] = None

class C2BeaconRequest(BaseModel):
    profile: str
    listener_host: str
    listener_port: int
    protocol: str = "https"

class BASRequest(BaseModel):
    playbook: str
    target: str
    intensity: str = "medium"

# ============================================================================
# Global State
# ============================================================================

orchestrator = PenteIAv4Orchestrator()
c2_controller = C2Controller()
bas_runner = BASPlaybookRunner()
ddos_engine = DDoSTestingEngine()

operation_logs = []

def log_operation(module: str, action: str, details: str = ""):
    """Log operations for audit trail"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'module': module,
        'action': action,
        'details': details
    }
    operation_logs.append(log_entry)
    print(f"[{module}] {action}: {details}")

# ============================================================================
# Health & Status Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Serve main dashboard"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/health")
async def health():
    """Health check"""
    return {
        "status": "online",
        "version": "4.0",
        "versao": "4.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/status")
async def system_status():
    """System status"""
    return {
        "status": "operational",
        "modules": {
            "orchestrator": "ready",
            "c2": "ready",
            "bas": "ready",
            "ddos": "ready",
            "evasion": "ready"
        },
        "active_operations": len(operation_logs),
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# DDoS Testing Endpoints
# ============================================================================

@app.get("/api/ddos/methods")
async def get_ddos_methods():
    """List available DDoS methods"""
    return {
        'methods': [
            {
                'id': 'syn_flood',
                'name': 'SYN Flood',
                'layer': 'Layer 4 (TCP)',
                'description': 'Floods target with SYN packets'
            },
            {
                'id': 'udp_flood',
                'name': 'UDP Flood',
                'layer': 'Layer 4 (UDP)',
                'description': 'Floods target with UDP packets'
            },
            {
                'id': 'http_flood',
                'name': 'HTTP Flood',
                'layer': 'Layer 7 (Application)',
                'description': 'Floods target with HTTP requests'
            },
            {
                'id': 'slowloris',
                'name': 'Slowloris',
                'layer': 'Layer 7 (Application)',
                'description': 'Keeps connections open to exhaust resources'
            },
            {
                'id': 'dns_amplification',
                'name': 'DNS Amplification',
                'layer': 'Layer 3 (Network)',
                'description': 'Amplifies traffic via DNS servers'
            }
        ],
        'timestamp': datetime.now().isoformat()
    }

@app.post("/api/ddos/start")
async def start_ddos_test(request: DDoSStartRequest):
    """Start a DDoS test"""
    target_host = request.target_host

    if not _validate_ddos_authorization(target_host):
        log_operation('DDoS', 'UNAUTHORIZED', f'Target: {target_host}')
        raise HTTPException(
            status_code=403,
            detail="Target not authorized. Only localhost and private IPs allowed."
        )

    try:
        config = DDoSConfig(
            target_host=target_host,
            target_port=request.target_port,
            method=DDoSMethod(request.method),
            duration_seconds=request.duration,
            threads=request.threads,
            packets_per_second=request.pps,
            authorized=True,
            test_name=request.test_name or f'{request.method} test'
        )

        if request.method == 'syn_flood':
            result = ddos_engine.start_syn_flood(config)
        elif request.method == 'udp_flood':
            result = ddos_engine.start_udp_flood(config)
        elif request.method == 'http_flood':
            result = ddos_engine.start_http_flood(config)
        elif request.method == 'slowloris':
            result = ddos_engine.start_slowloris(config)
        elif request.method == 'dns_amplification':
            result = ddos_engine.start_dns_amplification(config)
        else:
            raise HTTPException(status_code=400, detail="Unknown method")

        log_operation('DDoS', 'Test started', result.get("test_id"))
        return result

    except Exception as e:
        log_operation('ERROR', 'DDoS test failed', str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ddos/stop/{test_id}")
async def stop_ddos_test(test_id: str):
    """Stop active DDoS test"""
    try:
        result = ddos_engine.stop_test(test_id)
        log_operation('DDoS', 'Test stopped', test_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ddos/status/{test_id}")
async def get_ddos_status(test_id: str):
    """Get DDoS test status"""
    try:
        status = ddos_engine.get_test_status(test_id)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ddos/active")
async def get_active_ddos_tests():
    """List active DDoS tests"""
    tests = ddos_engine.list_active_tests()
    return {
        'tests': tests,
        'total': len(tests),
        'timestamp': datetime.now().isoformat()
    }

@app.get("/api/ddos/results")
async def get_ddos_results():
    """Get completed DDoS test results"""
    results = ddos_engine.get_test_results()
    return {
        'results': results,
        'total': len(results),
        'timestamp': datetime.now().isoformat()
    }

@app.get("/api/ddos/config")
async def get_ddos_config():
    """Get DDoS module configuration"""
    return ddos_engine.export_config()

@app.get("/api/modules/status")
async def get_modules_status():
    """Get status of all modules"""
    return {
        "modules": {
            "edr_evasion": {
                "name": "Evasão EDR",
                "status": "ready",
                "description": "ROP gadgets, syscalls, module stomping"
            },
            "memory_evasion": {
                "name": "Evasão de Memória",
                "status": "ready",
                "description": "Ofuscação sleep, stack spoofing, criptografia"
            },
            "telemetry_bypass": {
                "name": "Bypass de Telemetria",
                "status": "ready",
                "description": "AMSI, ETW, evasão Sysmon"
            },
            "c2_framework": {
                "name": "Framework C2",
                "status": "ready",
                "description": "Perfis adaptáveis, gerenciamento de beacon"
            },
            "post_exploitation": {
                "name": "Pós-Exploração",
                "status": "ready",
                "description": "COFF, BOF, execução inline .NET"
            },
            "bas_engine": {
                "name": "Motor BAS",
                "status": "ready",
                "description": "14 táticas MITRE, 40+ técnicas"
            },
            "ddos_testing": {
                "name": "Teste DDoS",
                "status": "ready",
                "description": "5 métodos de ataque, apenas testes autorizados"
            },
            "automated_reporting": {
                "name": "Relatórios",
                "status": "ready",
                "description": "Relatórios automatizados, múltiplos formatos"
            },
            "orchestrator": {
                "name": "Orquestrador",
                "status": "ready",
                "description": "Orquestração central de operações"
            },
            "recon": {
                "name": "Reconhecimento",
                "status": "ready",
                "description": "Resolução de domínio e varredura de portas"
            }
        },
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/recon/resolve")
async def resolve_domain(target: str):
    """Resolve domain to IP addresses"""
    try:
        resultado = resolver_dominio(target)
        log_operation('Recon', 'Domain resolved', target)
        return resultado
    except Exception as e:
        log_operation('ERROR', 'Recon resolve failed', str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/recon/scan")
async def scan_ports(target: str, ports: str = "top", timeout: float = 1.0, workers: int = 50):
    """Scan ports on target"""
    try:
        host = extrair_host(target)
        portas_list = parse_portas(ports)

        aberta = scan_portas(
            ip=host,
            portas=portas_list,
            host=host,
            timeout=timeout,
            workers=workers,
            banner=True
        )

        log_operation('Recon', 'Port scan completed', f'{host}:{ports}')
        return {
            'target': target,
            'host': host,
            'ports_scanned': len(portas_list),
            'open_ports': aberta,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        log_operation('ERROR', 'Recon scan failed', str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/modules/config/{module_name}")
async def get_module_config(module_name: str):
    """Get configuration of specific module"""
    modules_config = {
        "edr_evasion": {
            "name": "Evasão EDR",
            "version": "4.0",
            "status": "ready",
            "features": ["ROP Gadget Discovery", "Indirect Syscalls", "Module Stomping", "Sandbox Detection"]
        },
        "memory_evasion": {
            "name": "Evasão de Memória",
            "version": "4.0",
            "status": "ready",
            "features": ["Sleep Obfuscation (Ekko)", "Stack Spoofing", "Memory Encryption", "APC Abuse"]
        },
        "telemetry_bypass": {
            "name": "Bypass de Telemetria",
            "version": "4.0",
            "status": "ready",
            "features": ["AMSI Bypass (VEH)", "ETW Disabling", "Log Manipulation", "Sysmon Evasion"]
        },
        "c2_framework": {
            "name": "Framework C2",
            "version": "4.0",
            "status": "ready",
            "features": ["Malleable C2 Profiles", "Beacon Management", "Redirector Cascades", "Protocol Support"]
        },
        "post_exploitation": {
            "name": "Pós-Exploração",
            "version": "4.0",
            "status": "ready",
            "features": ["COFF Execution", "BOF Execution", ".NET Inline Execution", "Mimikatz/BloodHound"]
        },
        "bas_engine": {
            "name": "Motor BAS",
            "version": "4.0",
            "status": "ready",
            "features": ["14 MITRE Tactics", "40+ Techniques", "Severity Scoring", "Attack Paths"]
        },
        "ddos_testing": {
            "name": "Teste DDoS",
            "version": "4.0",
            "status": "ready",
            "features": ["SYN Flood", "UDP Flood", "HTTP Flood", "Slowloris", "DNS Amplification"]
        },
        "automated_reporting": {
            "name": "Relatórios",
            "version": "4.0",
            "status": "ready",
            "features": ["Jinja2 Templates", "HTML/PDF Export", "Auto-Generation", "Recommendations"]
        },
        "orchestrator": {
            "name": "Orquestrador",
            "version": "4.0",
            "status": "ready",
            "features": ["5-Phase Operations", "Module Coordination", "Result Aggregation", "Timeline"]
        }
    }

    if module_name in modules_config:
        return modules_config[module_name]
    else:
        raise HTTPException(status_code=404, detail="Módulo não encontrado")

# ============================================================================
# Operations Logging
# ============================================================================

@app.get("/api/operations")
async def get_operations(limit: int = 100):
    """Get operation logs"""
    return {
        'operations': operation_logs[-limit:],
        'total': len(operation_logs),
        'timestamp': datetime.now().isoformat()
    }

@app.post("/api/operations/clear")
async def clear_operations():
    """Clear operation logs"""
    global operation_logs
    operation_logs = []
    return {'status': 'cleared'}

# ============================================================================
# Page Routes
# ============================================================================

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/modules", response_class=HTMLResponse)
async def modules_page(request: Request):
    """Modules page"""
    return templates.TemplateResponse("modules.html", {"request": request})

@app.get("/c2", response_class=HTMLResponse)
async def c2_page(request: Request):
    """C2 page"""
    return templates.TemplateResponse("c2.html", {"request": request})

@app.get("/bas", response_class=HTMLResponse)
async def bas_page(request: Request):
    """BAS page"""
    return templates.TemplateResponse("bas.html", {"request": request})

@app.get("/operations", response_class=HTMLResponse)
async def operations_page(request: Request):
    """Operations page"""
    return templates.TemplateResponse("operations.html", {"request": request})

@app.get("/reporting", response_class=HTMLResponse)
async def reporting_page(request: Request):
    """Reporting page"""
    return templates.TemplateResponse("reporting.html", {"request": request})

@app.get("/evasion", response_class=HTMLResponse)
async def evasion_page(request: Request):
    """Evasion page"""
    return templates.TemplateResponse("evasion.html", {"request": request})

@app.get("/ddos", response_class=HTMLResponse)
async def ddos_page(request: Request):
    """DDoS testing page"""
    return templates.TemplateResponse("ddos.html", {"request": request})

@app.get("/recon", response_class=HTMLResponse)
async def recon_page(request: Request):
    """Reconnaissance page"""
    return templates.TemplateResponse("recon.html", {"request": request})

# ============================================================================
# Helper Functions
# ============================================================================

def _validate_ddos_authorization(target_host: str) -> bool:
    """Validate if target is authorized for DDoS testing"""
    authorized_ranges = [
        '127.', '192.168.', '10.',
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.'
    ]
    return any(target_host.startswith(r) for r in authorized_ranges)

def parse_portas(spec):
    """Parse port specification (top, 1-1024, 80,443, etc)"""
    spec = spec.strip().lower()
    TOP_PORTS = [20, 21, 22, 23, 25, 53, 67, 69, 80, 110, 111, 123, 135, 137, 139, 143, 161, 389,
                 443, 445, 465, 514, 587, 631, 636, 993, 995, 1080, 1433, 1521, 2049, 2375, 2376,
                 3000, 3306, 3389, 4444, 5000, 5432, 5601, 5900, 5985, 6379, 7001, 8000, 8008, 8080,
                 8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 15672, 27017]

    if spec in ("top", "comuns"):
        return TOP_PORTS

    portas = set()
    for parte in spec.split(","):
        parte = parte.strip()
        if "-" in parte:
            ini, fim = parte.split("-", 1)
            ini, fim = int(ini), int(fim)
            for p in range(ini, fim + 1):
                portas.add(p)
        else:
            portas.add(int(parte))

    return sorted(portas)

# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": str(exc)},
    )

# ============================================================================
# Startup/Shutdown
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """On startup"""
    print("[*] PenteIA v4.0 - FastAPI Dashboard")
    print("[*] Starting FastAPI application...")
    print("[*] Access at: http://localhost:8000")
    log_operation("SYSTEM", "Started", "FastAPI server online")

@app.on_event("shutdown")
async def shutdown_event():
    """On shutdown"""
    log_operation("SYSTEM", "Shutdown", "FastAPI server offline")
    print("[*] FastAPI server stopped")

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app_fastapi:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info"
    )


