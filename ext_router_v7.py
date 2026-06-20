"""
ext_router_v7.py — PenteIA V4.0
Round 5: K8s/Container, API Security (OWASP), OT/ICS, TIP, BSaC, CISO Dashboard
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from database import get_db
from auth import get_current_user
from models import User, Simulation
from pydantic import BaseModel
from typing import Optional
import uuid

ext_router_v7 = APIRouter()

# ── Optional imports ──────────────────────────────────────────────────────────

try:
    from k8s_engine import list_techniques as k8s_list, get_technique as k8s_get, simulate_technique as k8s_sim, CATEGORIES as K8S_CATS
    _HAS_K8S = True
except ImportError:
    _HAS_K8S = False

try:
    from api_security_engine import list_vulnerabilities, get_vulnerability, scan_endpoint as api_scan_ep
    _HAS_API_SEC = True
except ImportError:
    _HAS_API_SEC = False

try:
    from ot_ics_engine import list_techniques as ot_list, get_technique as ot_get, simulate_technique as ot_sim, get_sector_risk, SECTORS as OT_SECTORS
    _HAS_OT = True
except ImportError:
    _HAS_OT = False

try:
    from tip_engine import save_tip_config, get_tip_client, get_tip_config
    _HAS_TIP = True
except ImportError:
    _HAS_TIP = False

try:
    from bsac_engine import (
        parse_playbook, validate_playbook, execute_playbook_yaml,
        generate_junit_xml, get_example_playbook, get_github_actions_template
    )
    _HAS_BSAC = True
except ImportError:
    _HAS_BSAC = False

try:
    from ciso_dashboard_engine import (
        create_dashboard_token, validate_token, list_tokens,
        revoke_token, build_dashboard_data
    )
    _HAS_CISO = True
except ImportError:
    _HAS_CISO = False


def _unavail(feat):
    raise HTTPException(status_code=501, detail=f"{feat} not available")


def _persist_sim(technique_id, target, user_id, score, tactic, severity, tech_name, db, extra=None):
    sim_id = str(uuid.uuid4())
    sim = Simulation(id=sim_id, target=target, playbook_id=technique_id,
                     user_id=user_id, status="completed", score=score)
    sim.results = {
        "techniques": [{"id": technique_id, "name": tech_name, "tactic": tactic,
                         "status": "found", "severity": severity}],
        **(extra or {})
    }
    db.add(sim)
    db.commit()
    return sim_id


# ── Pydantic Models ───────────────────────────────────────────────────────────

class K8sSimRequest(BaseModel):
    target: str

class APIScanRequest(BaseModel):
    base_url: str
    endpoint: str = "/"
    method: str = "GET"
    headers: dict = {}
    test_bola: bool = True
    test_auth: bool = True
    test_ssrf: bool = True

class OTSimRequest(BaseModel):
    target: str
    sector: str = "energy"

class TIPConfigRequest(BaseModel):
    tip_type: str
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    api_token: Optional[str] = None
    verify_ssl: bool = True

class TIPEnrichRequest(BaseModel):
    technique_id: str

class BSaCRunRequest(BaseModel):
    playbook_yaml: str
    target: str

class CISOTokenRequest(BaseModel):
    org_name: str
    expires_days: int = 30
    label: str = ""

class CISORevokeRequest(BaseModel):
    token_hash_prefix: str


# ── K8s / Container ───────────────────────────────────────────────────────────

@ext_router_v7.get("/k8s/techniques", tags=["K8s Security"])
def k8s_techniques(
    category: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_user)
):
    if not _HAS_K8S:
        _unavail("k8s_engine")
    techs = k8s_list(category)
    return {"techniques": techs, "categories": K8S_CATS, "count": len(techs)}

@ext_router_v7.get("/k8s/techniques/{tid}", tags=["K8s Security"])
def k8s_technique_detail(tid: str, current_user: User = Depends(get_current_user)):
    if not _HAS_K8S:
        _unavail("k8s_engine")
    t = k8s_get(tid)
    if not t:
        raise HTTPException(status_code=404, detail=f"Technique {tid} not found")
    return t

@ext_router_v7.post("/k8s/techniques/{tid}/simulate", status_code=201, tags=["K8s Security"])
def k8s_simulate(
    tid: str, req: K8sSimRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not _HAS_K8S:
        _unavail("k8s_engine")
    try:
        result = k8s_sim(tid, req.target)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    t = k8s_get(tid)
    score = 90.0 if t and t.get("severity") == "critical" else 70.0
    sim_id = _persist_sim(
        tid, req.target, current_user.id, score,
        t["tactic"] if t else "PRIVILEGE_ESCALATION",
        t["severity"] if t else "critical",
        t["name"] if t else tid, db, {"k8s_result": result}
    )
    return {**result, "simulation_id": sim_id}


# ── API Security ──────────────────────────────────────────────────────────────

@ext_router_v7.get("/api-security/owasp-top10", tags=["API Security"])
def api_owasp_list(current_user: User = Depends(get_current_user)):
    if not _HAS_API_SEC:
        _unavail("api_security_engine")
    vulns = list_vulnerabilities()
    return {"vulnerabilities": vulns, "count": len(vulns)}

@ext_router_v7.get("/api-security/owasp-top10/{vid}", tags=["API Security"])
def api_owasp_detail(vid: str, current_user: User = Depends(get_current_user)):
    if not _HAS_API_SEC:
        _unavail("api_security_engine")
    v = get_vulnerability(vid)
    if not v:
        raise HTTPException(status_code=404, detail=f"Vulnerability {vid} not found")
    return v

@ext_router_v7.post("/api-security/scan", status_code=201, tags=["API Security"])
def api_scan(
    req: APIScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not _HAS_API_SEC:
        _unavail("api_security_engine")
    result = api_scan_ep(
        req.base_url, req.endpoint, req.method,
        req.headers or {}, req.test_bola, req.test_auth, req.test_ssrf
    )
    if result.get("findings"):
        sim_id = _persist_sim(
            "API-SCAN", req.base_url, current_user.id,
            min(100, len(result["findings"]) * 15),
            "INITIAL_ACCESS", result.get("risk_level", "medium"),
            "API Security Scan", db, {"api_scan": result}
        )
        result["simulation_id"] = sim_id
    return result


# ── OT / ICS ──────────────────────────────────────────────────────────────────

@ext_router_v7.get("/ot-ics/techniques", tags=["OT/ICS"])
def ot_techniques(
    sector: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_user)
):
    if not _HAS_OT:
        _unavail("ot_ics_engine")
    techs = ot_list(sector)
    return {"techniques": techs, "sectors": OT_SECTORS, "count": len(techs)}

@ext_router_v7.get("/ot-ics/sectors/{sector}", tags=["OT/ICS"])
def ot_sector_detail(sector: str, current_user: User = Depends(get_current_user)):
    if not _HAS_OT:
        _unavail("ot_ics_engine")
    return get_sector_risk(sector)

@ext_router_v7.post("/ot-ics/techniques/{tid}/simulate", status_code=201, tags=["OT/ICS"])
def ot_simulate(
    tid: str, req: OTSimRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not _HAS_OT:
        _unavail("ot_ics_engine")
    try:
        result = ot_sim(tid, req.target, req.sector)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    t = ot_get(tid)
    sim_id = _persist_sim(
        tid, req.target, current_user.id, 95.0,
        t["tactic"] if t else "IMPACT",
        t["severity"] if t else "critical",
        t["name"] if t else tid, db, {"ot_result": result}
    )
    return {**result, "simulation_id": sim_id}


# ── Threat Intelligence Platform ──────────────────────────────────────────────

@ext_router_v7.post("/tip/configure", tags=["Threat Intel"])
def tip_configure(req: TIPConfigRequest, current_user: User = Depends(get_current_user)):
    if not _HAS_TIP:
        _unavail("tip_engine")
    config = {
        "base_url": req.base_url,
        "api_key": req.api_key,
        "api_token": req.api_token,
        "verify_ssl": req.verify_ssl,
    }
    save_tip_config(current_user.id, req.tip_type, config)
    client = get_tip_client(current_user.id)
    if not client:
        raise HTTPException(status_code=400, detail="Unknown TIP type")
    result = client.test_connection()
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=f"TIP connection failed: {result.get('message')}")
    return {"status": "ok", "tip_type": req.tip_type, **result}

@ext_router_v7.get("/tip/config", tags=["Threat Intel"])
def tip_config_get(current_user: User = Depends(get_current_user)):
    if not _HAS_TIP:
        _unavail("tip_engine")
    return get_tip_config(current_user.id)

@ext_router_v7.post("/tip/enrich", tags=["Threat Intel"])
def tip_enrich(req: TIPEnrichRequest, current_user: User = Depends(get_current_user)):
    if not _HAS_TIP:
        _unavail("tip_engine")
    client = get_tip_client(current_user.id)
    if not client:
        raise HTTPException(status_code=400, detail="TIP not configured. POST /api/tip/configure first.")
    if hasattr(client, "enrich_technique"):
        return client.enrich_technique(req.technique_id)
    return {"message": "Enrichment not supported for this TIP type"}


# ── Breach Simulation as Code ─────────────────────────────────────────────────

@ext_router_v7.get("/bsac/example", tags=["BSaC"])
def bsac_example(current_user: User = Depends(get_current_user)):
    if not _HAS_BSAC:
        _unavail("bsac_engine")
    return {"playbook_yaml": get_example_playbook(), "github_actions": get_github_actions_template()}

@ext_router_v7.post("/bsac/validate", tags=["BSaC"])
def bsac_validate(req: BSaCRunRequest, current_user: User = Depends(get_current_user)):
    if not _HAS_BSAC:
        _unavail("bsac_engine")
    try:
        pb = parse_playbook(req.playbook_yaml)
        errors = validate_playbook(pb)
        return {"valid": len(errors) == 0, "errors": errors, "playbook": pb}
    except ValueError as e:
        return {"valid": False, "errors": [str(e)]}

@ext_router_v7.post("/bsac/run", status_code=201, tags=["BSaC"])
def bsac_run(
    req: BSaCRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not _HAS_BSAC:
        _unavail("bsac_engine")
    result = execute_playbook_yaml(req.playbook_yaml, req.target, current_user.id, db)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail={"errors": result.get("errors")})
    return result

@ext_router_v7.post("/bsac/run/junit", tags=["BSaC"])
def bsac_run_junit(req: BSaCRunRequest, current_user: User = Depends(get_current_user)):
    if not _HAS_BSAC:
        _unavail("bsac_engine")
    result = execute_playbook_yaml(req.playbook_yaml, req.target, current_user.id)
    xml = generate_junit_xml(result)
    return Response(content=xml, media_type="application/xml")


# ── CISO Dashboard ────────────────────────────────────────────────────────────

@ext_router_v7.post("/ciso-dashboard/tokens", status_code=201, tags=["CISO Dashboard"])
def ciso_create_token(req: CISOTokenRequest, current_user: User = Depends(get_current_user)):
    if not _HAS_CISO:
        _unavail("ciso_dashboard_engine")
    return create_dashboard_token(current_user.id, req.org_name, req.expires_days, req.label)

@ext_router_v7.get("/ciso-dashboard/tokens", tags=["CISO Dashboard"])
def ciso_list_tokens(current_user: User = Depends(get_current_user)):
    if not _HAS_CISO:
        _unavail("ciso_dashboard_engine")
    return {"tokens": list_tokens(current_user.id)}

@ext_router_v7.delete("/ciso-dashboard/tokens", tags=["CISO Dashboard"])
def ciso_revoke(req: CISORevokeRequest, current_user: User = Depends(get_current_user)):
    if not _HAS_CISO:
        _unavail("ciso_dashboard_engine")
    if not revoke_token(req.token_hash_prefix, current_user.id):
        raise HTTPException(status_code=404, detail="Token not found")
    return {"status": "revoked"}

@ext_router_v7.get("/ciso-dashboard/view/{token}", tags=["CISO Dashboard"])
def ciso_view(token: str, db: Session = Depends(get_db)):
    if not _HAS_CISO:
        _unavail("ciso_dashboard_engine")
    entry = validate_token(token)
    if not entry:
        raise HTTPException(status_code=403, detail="Invalid or expired token")
    sims = (
        db.query(Simulation)
        .filter(Simulation.user_id == entry["user_id"], Simulation.status == "completed")
        .order_by(Simulation.date.desc())
        .limit(20)
        .all()
    )
    sims_data = [
        {"score": s.score or 0, "date": s.date.isoformat() if s.date else "", "target": s.target, "results": s.results or {}}
        for s in sims
    ]
    return build_dashboard_data(sims_data, entry["org_name"])
