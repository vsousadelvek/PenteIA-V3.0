"""
ext_router_v6.py — PenteIA V4.0
GAPs 5-8: KEV trigger, EDR loop check, sector benchmarking, attack path graph.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from auth import get_current_user
from models import User
from pydantic import BaseModel
from typing import Optional, List
import os
import json

ext_router_v6 = APIRouter()

_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Optional imports ─────────────────────────────────────────────────────────

try:
    from epss_engine import get_kev_diff, check_kev_intersection, refresh_kev_cache
    _HAS_EPSS = True
except ImportError:
    _HAS_EPSS = False

try:
    from gap7_benchmark_data import get_benchmark, list_sectors
    _HAS_BENCH = True
except ImportError:
    _HAS_BENCH = False

try:
    from gap8_attack_paths import build_attack_graph, build_demo_graph
    _HAS_GRAPH = True
except ImportError:
    _HAS_GRAPH = False

try:
    from ad_attack_engine import run_ad_assessment
    _HAS_AD = True
except ImportError:
    _HAS_AD = False


# ── GAP 5 — KEV Diff & Trigger ───────────────────────────────────────────────

@ext_router_v6.get("/kev/diff", tags=["KEV Trigger"])
async def kev_diff(current_user: User = Depends(get_current_user)):
    """Return new and removed CVEs since last KEV snapshot."""
    if not _HAS_EPSS:
        raise HTTPException(503, "epss_engine not available")
    try:
        diff = get_kev_diff()
        return diff
    except Exception as e:
        raise HTTPException(500, str(e))


class KEVCheckRequest(BaseModel):
    cves: List[str]

@ext_router_v6.post("/kev/check-intersection", tags=["KEV Trigger"])
async def kev_check_intersection(req: KEVCheckRequest, current_user: User = Depends(get_current_user)):
    """Check which of the provided CVE IDs are currently in CISA KEV."""
    if not _HAS_EPSS:
        raise HTTPException(503, "epss_engine not available")
    try:
        in_kev = check_kev_intersection(req.cves)
        return {
            "provided": len(req.cves),
            "in_kev": in_kev,
            "in_kev_count": len(in_kev),
            "safe": [c for c in req.cves if c.upper() not in in_kev],
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@ext_router_v6.post("/kev/refresh", tags=["KEV Trigger"])
async def kev_refresh(current_user: User = Depends(get_current_user)):
    """Force refresh the KEV cache from CISA and return the diff."""
    if not _HAS_EPSS:
        raise HTTPException(503, "epss_engine not available")
    try:
        count = refresh_kev_cache()
        diff = get_kev_diff()
        return {"refreshed": True, "total_kev_entries": count, "diff": diff}
    except Exception as e:
        raise HTTPException(500, str(e))


# ── GAP 6 — EDR Loop Check ───────────────────────────────────────────────────

class EDRCheckRequest(BaseModel):
    edr_alerted: bool
    alert_time: Optional[str] = None
    edr_product: Optional[str] = None
    alert_id: Optional[str] = None

@ext_router_v6.post("/execution/edr-check/{test_filename}", tags=["EDR Loop"])
async def edr_check(
    test_filename: str,
    req: EDRCheckRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Client confirms whether EDR alerted on a T1070 test file.
    test_filename: the filename returned in the T1070 execution evidence.
    """
    record_path = os.path.join(_DIR, "_edr_pending.json")
    try:
        try:
            with open(record_path, "r", encoding="utf-8") as fh:
                pending = json.load(fh)
        except Exception:
            pending = {}

        if test_filename not in pending:
            raise HTTPException(404, f"Teste EDR '{test_filename}' não encontrado. Execute T1070 primeiro.")

        record = pending[test_filename]
        record["edr_alerted"] = req.edr_alerted
        record["edr_alert_time"] = req.alert_time
        record["edr_product"] = req.edr_product
        record["alert_id"] = req.alert_id
        record["detection_gap_confirmed"] = not req.edr_alerted
        record["loop_closed_at"] = __import__("datetime").datetime.utcnow().isoformat()

        pending[test_filename] = record
        with open(record_path, "w", encoding="utf-8") as fh:
            json.dump(pending, fh, ensure_ascii=False, indent=2)

        verdict = "GAP DE DETECÇÃO CONFIRMADO" if not req.edr_alerted else "EDR detectou o ataque"
        return {
            "test_filename": test_filename,
            "edr_alerted": req.edr_alerted,
            "detection_gap_confirmed": not req.edr_alerted,
            "verdict": verdict,
            "record": record,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@ext_router_v6.get("/execution/edr-pending", tags=["EDR Loop"])
async def edr_pending_checks(current_user: User = Depends(get_current_user)):
    """List all pending EDR checks (T1070 tests awaiting confirmation)."""
    record_path = os.path.join(_DIR, "_edr_pending.json")
    try:
        with open(record_path, "r", encoding="utf-8") as fh:
            pending = json.load(fh)
        pending_list = [{"filename": k, **v} for k, v in pending.items() if v.get("detection_gap_confirmed") is None]
        closed_list = [{"filename": k, **v} for k, v in pending.items() if v.get("detection_gap_confirmed") is not None]
        return {"pending": pending_list, "closed": closed_list, "total": len(pending)}
    except FileNotFoundError:
        return {"pending": [], "closed": [], "total": 0}
    except Exception as e:
        raise HTTPException(500, str(e))


# ── GAP 7 — Sector Benchmarking ─────────────────────────────────────────────

@ext_router_v6.get("/bas/benchmark/sectors", tags=["Benchmarking"])
async def benchmark_sectors(current_user: User = Depends(get_current_user)):
    """List all available benchmark sectors."""
    if not _HAS_BENCH:
        raise HTTPException(503, "gap7_benchmark_data not available")
    return {"sectors": list_sectors()}


@ext_router_v6.get("/bas/benchmark/{sector}", tags=["Benchmarking"])
async def benchmark_sector(
    sector: str,
    score: float = Query(..., ge=0, le=100, description="BAS score do cliente (0-100)"),
    current_user: User = Depends(get_current_user),
):
    """Compare client BAS score against sector peers."""
    if not _HAS_BENCH:
        raise HTTPException(503, "gap7_benchmark_data not available")
    result = get_benchmark(sector, score)
    if "error" in result:
        raise HTTPException(404, result["error"])
    return result


# ── GAP 8 — Attack Path Graph ────────────────────────────────────────────────

@ext_router_v6.get("/ad/attack-graph", tags=["Attack Graph"])
async def attack_graph(
    dc_host: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    password: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
):
    """
    Return React Flow nodes+edges for the AD attack path graph.
    Without credentials: returns a demo graph.
    With dc_host+username+password+domain: performs real LDAP enumeration.
    """
    if not _HAS_GRAPH:
        raise HTTPException(503, "gap8_attack_paths not available")

    if dc_host and username and password and domain:
        if not _HAS_AD:
            raise HTTPException(503, "ad_attack_engine not available")
        try:
            assessment = run_ad_assessment(dc_host, username, password, domain)
            return build_attack_graph(assessment)
        except Exception as e:
            raise HTTPException(500, f"LDAP assessment failed: {e}")
    else:
        return build_demo_graph()
