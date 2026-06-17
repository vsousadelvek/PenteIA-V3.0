"""
ext_router_v5.py — PenteIA V4.0
Round 4 endpoints: Real Execution Engine, MSSP White-Label Portal, AD Attacks
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from database import get_db
from auth import get_current_user
from models import User, Simulation
from pydantic import BaseModel
from typing import Optional, List
import uuid

ext_router_v5 = APIRouter()

# ── Optional imports ──────────────────────────────────────────────────────────

try:
    from execution_engine import (
        execute_technique, execute_playbook, load_evidence, list_executions
    )
    _HAS_EXEC = True
except ImportError:
    _HAS_EXEC = False

try:
    from mssp_engine import (
        create_partner, get_partner, list_partners, update_partner_branding,
        delete_partner, create_client, list_clients, update_client_metrics,
        delete_client, get_partner_portfolio, generate_partner_report_data,
        MSSP_PLANS
    )
    _HAS_MSSP = True
except ImportError:
    _HAS_MSSP = False

try:
    from ad_attack_engine import (
        list_techniques as ad_list_techniques,
        get_technique as ad_get_technique,
        list_attack_paths, get_attack_path,
        simulate_ad_technique, simulate_attack_path, get_ad_risk_score,
    )
    _HAS_AD = True
except ImportError:
    _HAS_AD = False


def _unavailable(feature: str):
    raise HTTPException(status_code=501, detail=f"{feature} not available")


# ── Pydantic models ───────────────────────────────────────────────────────────

class ExecuteTechniqueRequest(BaseModel):
    technique_id: str
    target: str
    mode: str = "simulated"
    auth_token: Optional[str] = None

class ExecutePlaybookRequest(BaseModel):
    technique_ids: List[str]
    target: str
    mode: str = "simulated"
    auth_token: Optional[str] = None

class CreatePartnerRequest(BaseModel):
    name: str
    slug: str
    logo_url: str = ""
    primary_color: str = "#E53E3E"
    secondary_color: str = "#1A202C"
    contact_email: str = ""

class UpdateBrandingRequest(BaseModel):
    logo_url: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    company_name: Optional[str] = None
    report_footer: Optional[str] = None

class CreateClientRequest(BaseModel):
    name: str
    sector: str
    contact_email: str
    tenant_org_id: Optional[str] = None

class UpdateClientMetricsRequest(BaseModel):
    risk_score: float
    simulation_count: int
    last_simulation: str

class ADSimulateRequest(BaseModel):
    target_domain: str
    target_dc: str = ""

class ADPathSimulateRequest(BaseModel):
    target_domain: str


# ── REAL EXECUTION ENGINE ─────────────────────────────────────────────────────

@ext_router_v5.post("/execution/technique", status_code=201, tags=["Real Execution"])
def execution_technique(req: ExecuteTechniqueRequest,
                         db: Session = Depends(get_db),
                         current_user: User = Depends(get_current_user)):
    if not _HAS_EXEC: _unavailable("execution_engine")
    try:
        evidence = execute_technique(req.technique_id, req.target, req.mode, req.auth_token)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Persist as simulation
    sim_id = str(uuid.uuid4())
    sim = Simulation(
        id=sim_id, target=req.target, playbook_id=req.technique_id,
        user_id=current_user.id, status="completed", score=75.0,
    )
    sim.results = {
        "techniques": [{"id": req.technique_id, "status": "found", "severity": "high",
                         "tactic": "EXECUTION", "name": req.technique_id}],
        "execution_id": evidence["execution_id"],
        "mode": req.mode,
        "real_execution": True,
    }
    db.add(sim)
    db.commit()

    return {**evidence, "simulation_id": sim_id}

@ext_router_v5.post("/execution/playbook", status_code=201, tags=["Real Execution"])
def execution_playbook(req: ExecutePlaybookRequest,
                        current_user: User = Depends(get_current_user)):
    if not _HAS_EXEC: _unavailable("execution_engine")
    try:
        result = execute_playbook(req.technique_ids, req.target, req.mode, req.auth_token)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return result

@ext_router_v5.get("/execution/evidence/{execution_id}", tags=["Real Execution"])
def execution_evidence(execution_id: str, current_user: User = Depends(get_current_user)):
    if not _HAS_EXEC: _unavailable("execution_engine")
    ev = load_evidence(execution_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev

@ext_router_v5.get("/execution/history", tags=["Real Execution"])
def execution_history(current_user: User = Depends(get_current_user)):
    if not _HAS_EXEC: _unavailable("execution_engine")
    return {"executions": list_executions()}


# ── MSSP PORTAL ───────────────────────────────────────────────────────────────

@ext_router_v5.get("/mssp/partners", tags=["MSSP"])
def mssp_partners(current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    return {"partners": list_partners(owner_user_id=current_user.id), "plans": MSSP_PLANS}

@ext_router_v5.post("/mssp/partners", status_code=201, tags=["MSSP"])
def mssp_create_partner(req: CreatePartnerRequest, current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    try:
        partner = create_partner(
            name=req.name, slug=req.slug, owner_user_id=current_user.id,
            logo_url=req.logo_url, primary_color=req.primary_color,
            secondary_color=req.secondary_color, contact_email=req.contact_email,
        )
        return partner
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@ext_router_v5.get("/mssp/partners/{partner_id}", tags=["MSSP"])
def mssp_get_partner(partner_id: str, current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    p = get_partner(partner_id)
    if not p or p["owner_user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Partner not found")
    return p

@ext_router_v5.patch("/mssp/partners/{partner_id}/branding", tags=["MSSP"])
def mssp_update_branding(partner_id: str, req: UpdateBrandingRequest,
                          current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    p = get_partner(partner_id)
    if not p or p["owner_user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Partner not found")
    branding = {k: v for k, v in req.dict().items() if v is not None}
    return update_partner_branding(partner_id, branding)

@ext_router_v5.delete("/mssp/partners/{partner_id}", tags=["MSSP"])
def mssp_delete_partner(partner_id: str, current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    if not delete_partner(partner_id, current_user.id):
        raise HTTPException(status_code=404, detail="Partner not found")
    return {"status": "deleted"}

@ext_router_v5.get("/mssp/partners/{partner_id}/portfolio", tags=["MSSP"])
def mssp_portfolio(partner_id: str, current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    p = get_partner(partner_id)
    if not p or p["owner_user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Partner not found")
    return get_partner_portfolio(partner_id)

@ext_router_v5.get("/mssp/partners/{partner_id}/report-data", tags=["MSSP"])
def mssp_report_data(partner_id: str, current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    p = get_partner(partner_id)
    if not p or p["owner_user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Partner not found")
    return generate_partner_report_data(partner_id)

# Clients
@ext_router_v5.get("/mssp/partners/{partner_id}/clients", tags=["MSSP"])
def mssp_clients(partner_id: str, current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    p = get_partner(partner_id)
    if not p or p["owner_user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Partner not found")
    return {"clients": list_clients(partner_id)}

@ext_router_v5.post("/mssp/partners/{partner_id}/clients", status_code=201, tags=["MSSP"])
def mssp_create_client(partner_id: str, req: CreateClientRequest,
                        current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    p = get_partner(partner_id)
    if not p or p["owner_user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Partner not found")
    try:
        return create_client(partner_id, req.name, req.sector, req.contact_email, req.tenant_org_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

@ext_router_v5.delete("/mssp/partners/{partner_id}/clients/{client_id}", tags=["MSSP"])
def mssp_delete_client(partner_id: str, client_id: str,
                        current_user: User = Depends(get_current_user)):
    if not _HAS_MSSP: _unavailable("mssp_engine")
    p = get_partner(partner_id)
    if not p or p["owner_user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Partner not found")
    if not delete_client(client_id, partner_id):
        raise HTTPException(status_code=404, detail="Client not found")
    return {"status": "deleted"}


# ── ACTIVE DIRECTORY ATTACKS ──────────────────────────────────────────────────

@ext_router_v5.get("/ad-attacks/techniques", tags=["AD Attacks"])
def ad_techniques(current_user: User = Depends(get_current_user)):
    if not _HAS_AD: _unavailable("ad_attack_engine")
    return {"techniques": ad_list_techniques(), "count": len(ad_list_techniques())}

@ext_router_v5.get("/ad-attacks/techniques/{technique_id}", tags=["AD Attacks"])
def ad_technique_get(technique_id: str, current_user: User = Depends(get_current_user)):
    if not _HAS_AD: _unavailable("ad_attack_engine")
    t = ad_get_technique(technique_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return t

@ext_router_v5.post("/ad-attacks/techniques/{technique_id}/simulate", status_code=201, tags=["AD Attacks"])
def ad_simulate(technique_id: str, req: ADSimulateRequest,
                db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not _HAS_AD: _unavailable("ad_attack_engine")
    try:
        result = simulate_ad_technique(technique_id, req.target_domain, req.target_dc)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Persist as simulation
    sim_id = str(uuid.uuid4())
    tech = ad_get_technique(technique_id)
    sim = Simulation(
        id=sim_id, target=req.target_domain, playbook_id=technique_id,
        user_id=current_user.id, status="completed",
        score=tech.get("cvss_like_score", 7.0) * 10 if tech else 70.0,
    )
    sim.results = {
        "techniques": [{"id": technique_id, "name": tech["name"] if tech else technique_id,
                         "tactic": tech["tactic"] if tech else "CREDENTIAL_ACCESS",
                         "status": "found", "severity": tech["severity"] if tech else "high"}],
        "ad_attack": True,
        "ad_result": result,
    }
    db.add(sim)
    db.commit()

    return {**result, "simulation_id": sim_id}

@ext_router_v5.get("/ad-attacks/paths", tags=["AD Attacks"])
def ad_paths(current_user: User = Depends(get_current_user)):
    if not _HAS_AD: _unavailable("ad_attack_engine")
    return {"paths": list_attack_paths(), "count": len(list_attack_paths())}

@ext_router_v5.post("/ad-attacks/paths/{path_id}/simulate", status_code=201, tags=["AD Attacks"])
def ad_path_simulate(path_id: str, req: ADPathSimulateRequest,
                      db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not _HAS_AD: _unavailable("ad_attack_engine")
    try:
        result = simulate_attack_path(path_id, req.target_domain)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    sim_id = str(uuid.uuid4())
    sim = Simulation(
        id=sim_id, target=req.target_domain, playbook_id=path_id,
        user_id=current_user.id, status="completed", score=95.0,
    )
    sim.results = {
        "techniques": [{"id": s["technique_id"], "status": "found", "severity": "critical",
                         "tactic": "CREDENTIAL_ACCESS", "name": s["technique_id"]}
                        for s in result["step_results"] if s["status"] == "completed"],
        "ad_path": True,
        "path_result": result,
    }
    db.add(sim)
    db.commit()

    return {**result, "simulation_id": sim_id}
