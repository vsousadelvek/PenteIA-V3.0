"""
ext_router_missing.py — PenteIA V4.0
Wire dos engines que existem mas não tinham endpoints FastAPI:
  - apt_engine          → /api/apt/*
  - edr_evasion_core    → /api/evasion/config  (complementa hardcoded)
  - memory_evasion      → /api/evasion/memory
  - telemetry_bypass    → /api/evasion/telemetry
  - c2_framework        → /api/c2/framework/*
  - post_exploitation   → /api/post-exploitation/*
"""
from __future__ import annotations
import uuid
import base64
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import get_current_user
from models import User

missing_router = APIRouter()


def _get_db():
    from database import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════════════════
# APT SIMULATION  /api/apt/*
# ══════════════════════════════════════════════════════════════════════════════

@missing_router.get("/apt/groups", tags=["APT"])
async def apt_list_groups(current_user: User = Depends(get_current_user)):
    """Lista todos os grupos APT com perfis e kill chains."""
    from apt_engine import list_apt_groups
    return {"groups": list_apt_groups()}


@missing_router.get("/apt/groups/{group_id}", tags=["APT"])
async def apt_get_group(group_id: str, current_user: User = Depends(get_current_user)):
    """Retorna perfil completo de um grupo APT."""
    from apt_engine import get_apt_group
    group = get_apt_group(group_id)
    if not group:
        raise HTTPException(404, f"Grupo APT '{group_id}' não encontrado")
    return group


class APTSimulateRequest(BaseModel):
    target: str
    mode: str = "simulated"       # simulated | authorized
    auth_token: Optional[str] = None


@missing_router.post("/apt/simulate/{group_id}", tags=["APT"])
async def apt_simulate(
    group_id: str,
    req: APTSimulateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """
    Inicia simulação de APT contra o alvo.
    Executa o kill chain do grupo em ordem, via execution_engine.
    """
    from apt_engine import get_apt_group, get_apt_simulation_plan
    from subscription_engine import can_start_attack, open_session

    group = get_apt_group(group_id)
    if not group:
        raise HTTPException(404, f"Grupo APT '{group_id}' não encontrado")

    # Gate de billing
    allowed, reason = can_start_attack(current_user, db)
    if not allowed:
        raise HTTPException(402, reason)

    plan = get_apt_simulation_plan(group_id)
    simulation_id = str(uuid.uuid4())

    open_session(current_user.id, "apt", db, reference_id=simulation_id)

    # Executa cada step do kill chain
    try:
        from execution_engine import execute_technique
    except ImportError:
        execute_technique = None

    results = []
    for step in plan:
        if execute_technique:
            try:
                tech_result = execute_technique(
                    technique_id=step["technique_id"],
                    target=req.target,
                    mode=req.mode,
                    auth_token=req.auth_token,
                )
            except Exception as e:
                tech_result = {"status": "error", "detail": str(e)}
        else:
            tech_result = {"status": "simulated", "detail": "execution_engine não disponível"}

        results.append({
            "order": step["order"],
            "technique_id": step["technique_id"],
            "name": step["name"],
            "tactic": step["tactic"],
            "description": step["description"],
            "result": tech_result,
        })

    # Fecha sessão
    try:
        from subscription_engine import close_session_by_ref
        close_session_by_ref(simulation_id, "apt", db)
    except Exception:
        pass

    score = round(
        sum(1 for r in results if r["result"].get("status") not in ("error", "blocked")) / max(len(results), 1) * 100,
        1,
    )

    return {
        "simulation_id": simulation_id,
        "group_id": group_id,
        "group_name": group["name"],
        "target": req.target,
        "mode": req.mode,
        "steps_total": len(plan),
        "steps_executed": len(results),
        "exposure_score": score,
        "results": results,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# EDR EVASION CONFIG  /api/evasion/config  /api/evasion/memory  /api/evasion/telemetry
# ══════════════════════════════════════════════════════════════════════════════

@missing_router.get("/evasion/config", tags=["Evasion"])
async def evasion_edr_config(current_user: User = Depends(get_current_user)):
    """Retorna configuração real do EDR Evasion Core (ROP gadgets, syscall map, module stomp)."""
    try:
        from edr_evasion_core import export_evasion_config
        config = export_evasion_config()
        config["source"] = "edr_evasion_core.py"
        return config
    except Exception as e:
        raise HTTPException(500, f"Erro ao exportar config de evasão: {e}")


@missing_router.get("/evasion/memory", tags=["Evasion"])
async def evasion_memory_config(current_user: User = Depends(get_current_user)):
    """Retorna configuração de Memory Evasion (sleep obfuscation, stack spoofing, APC)."""
    try:
        from memory_evasion import export_memory_evasion_config
        config = export_memory_evasion_config()
        config["source"] = "memory_evasion.py"
        return config
    except Exception as e:
        raise HTTPException(500, f"Erro ao exportar config de memory evasion: {e}")


@missing_router.get("/evasion/telemetry", tags=["Evasion"])
async def evasion_telemetry_config(current_user: User = Depends(get_current_user)):
    """Retorna configuração de Telemetry Bypass (AMSI VEH, ETW disable, Event Log manipulation)."""
    try:
        from telemetry_bypass import export_telemetry_bypass_config
        config = export_telemetry_bypass_config()
        config["source"] = "telemetry_bypass.py"
        return config
    except Exception as e:
        raise HTTPException(500, f"Erro ao exportar config de telemetry bypass: {e}")


class SandboxCheckRequest(BaseModel):
    target: str = "local"


@missing_router.post("/evasion/sandbox-check", tags=["Evasion"])
async def evasion_sandbox_check(
    req: SandboxCheckRequest,
    current_user: User = Depends(get_current_user),
):
    """Executa detecção de sandbox/análise dinâmica (Cuckoo, VMware, VirtualBox, debuggers)."""
    try:
        from edr_evasion_core import SandboxDetector
        from telemetry_bypass import AntiAnalysisDetection
        detector = SandboxDetector()
        anti = AntiAnalysisDetection()
        sandbox_detected = detector.check_all()
        analysis_tools = anti.check_all()
        return {
            "target": req.target,
            "sandbox_detected": sandbox_detected,
            "analysis_tools_found": analysis_tools,
            "is_safe_to_execute": not sandbox_detected and len(analysis_tools) == 0,
            "checks_performed": ["registry_keys", "files", "processes", "drivers", "timing", "debugger", "profilers", "network_sniffers"],
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        raise HTTPException(500, f"Erro no sandbox check: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# C2 FRAMEWORK ENHANCEMENTS  /api/c2/framework/*
# ══════════════════════════════════════════════════════════════════════════════

# Instância singleton do C2Controller
_c2_controller = None

def _get_c2():
    global _c2_controller
    if _c2_controller is None:
        from c2_framework import C2Controller
        _c2_controller = C2Controller()
    return _c2_controller


@missing_router.get("/c2/framework/status", tags=["C2"])
async def c2_framework_status(current_user: User = Depends(get_current_user)):
    """Retorna status completo do C2 Framework (profiles, sessões, cascatas)."""
    try:
        ctrl = _get_c2()
        return ctrl.get_framework_status()
    except Exception as e:
        raise HTTPException(500, f"Erro ao obter status do C2: {e}")


@missing_router.get("/c2/framework/profiles", tags=["C2"])
async def c2_list_profiles(current_user: User = Depends(get_current_user)):
    """Lista perfis Malleable C2 disponíveis (Azure Telemetry, AWS SDK, O365, DoH)."""
    try:
        ctrl = _get_c2()
        profiles = []
        for name, profile in ctrl.profiles.items():
            p = profile.to_dict()
            if hasattr(profile, 'get_http_get_config'):
                p["http_get"] = profile.get_http_get_config()
            if hasattr(profile, 'get_http_post_config'):
                p["http_post"] = profile.get_http_post_config()
            if hasattr(profile, 'get_dns_query_format'):
                p["dns_config"] = profile.get_dns_query_format()
            profiles.append(p)
        return {"profiles": profiles}
    except Exception as e:
        raise HTTPException(500, f"Erro ao listar profiles: {e}")


class BeaconRegisterRequest(BaseModel):
    profile: str = "azure"     # azure | aws | o365 | doh


@missing_router.post("/c2/framework/beacon/register", tags=["C2"])
async def c2_register_beacon(
    req: BeaconRegisterRequest,
    current_user: User = Depends(get_current_user),
):
    """Registra beacon com perfil Malleable C2."""
    try:
        ctrl = _get_c2()
        session = ctrl.register_beacon(req.profile)
        return {
            "beacon_id": session.beacon_id,
            "profile": session.profile.to_dict(),
            "created_at": session.created_at.isoformat(),
            "status": "alive",
        }
    except Exception as e:
        raise HTTPException(500, f"Erro ao registrar beacon: {e}")


@missing_router.get("/c2/framework/sessions", tags=["C2"])
async def c2_active_sessions(current_user: User = Depends(get_current_user)):
    """Lista sessões de beacon ativas."""
    try:
        ctrl = _get_c2()
        return {"sessions": ctrl.list_active_sessions()}
    except Exception as e:
        raise HTTPException(500, f"Erro ao listar sessões: {e}")


class CascadeCreateRequest(BaseModel):
    team_server: str
    team_port: int = 443
    redirectors: List[dict] = []


@missing_router.post("/c2/framework/cascade", tags=["C2"])
async def c2_create_cascade(
    req: CascadeCreateRequest,
    current_user: User = Depends(get_current_user),
):
    """Cria cascata de redirectores e gera config nginx."""
    try:
        ctrl = _get_c2()
        cascade = ctrl.create_cascade(req.team_server, req.team_port)
        for r in req.redirectors:
            cascade.add_redirector(
                name=r.get("name", "redirector"),
                cloud_provider=r.get("cloud_provider", "aws"),
                ip_address=r.get("ip_address", "0.0.0.0"),
                port=r.get("port", 443),
            )
        nginx_cfg = cascade.build_nginx_config(req.team_server, req.team_port)
        status = cascade.get_cascade_status()
        status["nginx_config"] = nginx_cfg
        return status
    except Exception as e:
        raise HTTPException(500, f"Erro ao criar cascata: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# POST-EXPLOITATION  /api/post-exploitation/*
# ══════════════════════════════════════════════════════════════════════════════

@missing_router.get("/post-exploitation/modules", tags=["Post-Exploitation"])
async def postex_list_modules(current_user: User = Depends(get_current_user)):
    """Lista módulos de post-exploração disponíveis (Mimikatz, BloodHound, Rubeus, COFF/BOF, .NET)."""
    try:
        from post_exploitation import PostExecModule, export_post_exploitation_config
        config = export_post_exploitation_config()
        modules = [
            {
                "id": m.value,
                "name": m.value.capitalize(),
                "description": {
                    "mimikatz": "Dump de credenciais LSASS, SAM, LSA secrets e Kerberos tickets inline (COFF/BOF)",
                    "bloodhound": "Coleta de dados AD com SharpHound inline — grafo de caminhos de ataque",
                    "rubeus": "Operações Kerberos: dump de tickets, Kerberoasting, requisição de TGT",
                    "seatbelt": "Enumeração de segurança: GPOs, credenciais, configurações inseguras",
                    "sharphound": "Coleta BloodHound inline via .NET assembly em memória",
                    "inveigh": "LLMNR/NBT-NS poisoning e captura de hashes NTLMv2",
                    "jaws": "Enumeração de privilege escalation paths no Windows",
                }.get(m.value, m.value),
            }
            for m in PostExecModule
        ]
        return {"modules": modules, "config": config}
    except Exception as e:
        raise HTTPException(500, f"Erro ao listar módulos: {e}")


class MimikatzRequest(BaseModel):
    module: str = "sekurlsa::logonpasswords"
    args: str = ""
    extract_all: bool = False


@missing_router.post("/post-exploitation/mimikatz", tags=["Post-Exploitation"])
async def postex_mimikatz(
    req: MimikatzRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """Executa Mimikatz inline (COFF/BOF). Requer autorização de pentest."""
    try:
        from post_exploitation import MimikatzInline
        mimi = MimikatzInline()
        if req.extract_all:
            result = mimi.extract_all_secrets()
        else:
            result = mimi.execute_command(req.module, req.args)
        return {
            "engine": "MimikatzInline",
            "execution_method": "COFF_inline",
            "no_process_tree": True,
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        raise HTTPException(500, f"Erro ao executar Mimikatz: {e}")


class BloodHoundRequest(BaseModel):
    domain: Optional[str] = None
    methods: List[str] = ["All"]


@missing_router.post("/post-exploitation/bloodhound", tags=["Post-Exploitation"])
async def postex_bloodhound(
    req: BloodHoundRequest,
    current_user: User = Depends(get_current_user),
):
    """Coleta dados AD via BloodHound/SharpHound inline."""
    try:
        from post_exploitation import BloodHoundCollector
        bh = BloodHoundCollector()
        result = bh.collect_domain_data(domain=req.domain, methods=req.methods)
        return {
            "engine": "BloodHoundCollector",
            "execution_method": "dotnet_inline",
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        raise HTTPException(500, f"Erro ao executar BloodHound: {e}")


class RubeusRequest(BaseModel):
    operation: str = "dump_tickets"   # dump_tickets | kerberoast | request_tgt
    username: Optional[str] = None
    password: Optional[str] = None
    hash_value: Optional[str] = None


@missing_router.post("/post-exploitation/rubeus", tags=["Post-Exploitation"])
async def postex_rubeus(
    req: RubeusRequest,
    current_user: User = Depends(get_current_user),
):
    """Operações Kerberos via Rubeus inline."""
    try:
        from post_exploitation import RubeusKerberos
        rubeus = RubeusKerberos()
        if req.operation == "dump_tickets":
            result = rubeus.dump_tickets()
        elif req.operation == "kerberoast":
            result = rubeus.kerberoast()
        elif req.operation == "request_tgt":
            if not req.username:
                raise HTTPException(400, "username obrigatório para request_tgt")
            result = rubeus.request_tgt(req.username, req.password, req.hash_value)
        else:
            raise HTTPException(400, f"Operação desconhecida: {req.operation}")
        return {
            "engine": "RubeusKerberos",
            "execution_method": "COFF_inline",
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Erro ao executar Rubeus: {e}")


class COFFRequest(BaseModel):
    coff_b64: str           # COFF binary em base64
    entry_function: str = "go"
    args: str = ""


@missing_router.post("/post-exploitation/coff", tags=["Post-Exploitation"])
async def postex_coff(
    req: COFFRequest,
    current_user: User = Depends(get_current_user),
):
    """Carrega e executa COFF/BOF inline (sem criar processo)."""
    try:
        from post_exploitation import COFFLoader
        loader = COFFLoader()
        coff_bytes = base64.b64decode(req.coff_b64)
        meta = loader.load_coff(coff_bytes, req.entry_function)
        result = loader.execute_coff(meta["coff_id"], args=req.args)
        return {
            "engine": "COFFLoader",
            "execution_method": "inline_coff",
            "no_process_tree": True,
            "coff_meta": meta,
            "execution": result,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        raise HTTPException(500, f"Erro ao executar COFF: {e}")


class DotNetRequest(BaseModel):
    assembly_b64: str
    assembly_name: str
    class_name: str
    method_name: str
    args: List[str] = []


@missing_router.post("/post-exploitation/dotnet", tags=["Post-Exploitation"])
async def postex_dotnet(
    req: DotNetRequest,
    current_user: User = Depends(get_current_user),
):
    """Executa assembly .NET inline via CLR (sem criar processo)."""
    try:
        from post_exploitation import DotNetExecutor
        executor = DotNetExecutor()
        asm_bytes = base64.b64decode(req.assembly_b64)
        executor.load_dotnet_assembly(asm_bytes, req.assembly_name)
        result = executor.execute_method(
            assembly_name=req.assembly_name,
            class_name=req.class_name,
            method_name=req.method_name,
            args=req.args,
        )
        return {
            "engine": "DotNetExecutor",
            "execution_method": "clr_inline",
            "no_process_tree": True,
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        raise HTTPException(500, f"Erro ao executar .NET assembly: {e}")


@missing_router.get("/post-exploitation/summary", tags=["Post-Exploitation"])
async def postex_summary(current_user: User = Depends(get_current_user)):
    """Resumo de configuração dos módulos de post-exploração."""
    try:
        from post_exploitation import export_post_exploitation_config
        return export_post_exploitation_config()
    except Exception as e:
        raise HTTPException(500, f"Erro ao obter summary: {e}")
