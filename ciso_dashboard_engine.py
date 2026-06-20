"""
ciso_dashboard_engine.py — PenteIA V4.0
Live CISO Dashboard engine.
Generates shareable tokens for read-only executive dashboards.
"""
import uuid
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

_TOKENS_PATH = Path(__file__).parent / "ciso_tokens.json"


def _load():
    if _TOKENS_PATH.exists():
        try:
            return json.loads(_TOKENS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save(data):
    _TOKENS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def create_dashboard_token(user_id, org_name, expires_days=30, label=""):
    token = str(uuid.uuid4()).replace("-", "")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()
    entry = {
        "token_hash": token_hash,
        "user_id": user_id,
        "org_name": org_name,
        "label": label or f"Dashboard {datetime.utcnow().strftime('%Y-%m-%d')}",
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at,
        "views": 0,
        "last_viewed": None,
        "active": True,
    }
    data = _load()
    data[token_hash] = entry
    _save(data)
    return {"token": token, **entry}


def validate_token(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    data = _load()
    entry = data.get(token_hash)
    if not entry or not entry.get("active"):
        return None
    if datetime.fromisoformat(entry["expires_at"]) < datetime.utcnow():
        return None
    entry["views"] += 1
    entry["last_viewed"] = datetime.utcnow().isoformat()
    data[token_hash] = entry
    _save(data)
    return entry


def list_tokens(user_id):
    return [
        {**v, "token_preview": v["token_hash"][:8] + "..."}
        for v in _load().values()
        if v.get("user_id") == user_id
    ]


def revoke_token(token_hash_prefix, user_id):
    data = _load()
    for th, entry in data.items():
        if th.startswith(token_hash_prefix) and entry.get("user_id") == user_id:
            entry["active"] = False
            _save(data)
            return True
    return False


def build_dashboard_data(simulations, org_name):
    if not simulations:
        return {
            "org_name": org_name, "risk_score": 0, "trend": "stable",
            "simulations": [], "top_risks": [],
            "generated_at": datetime.utcnow().isoformat(),
        }
    scores = [s.get("score", 0) for s in simulations]
    avg = sum(scores) / len(scores)
    half = len(scores) // 2
    prev = sum(scores[half:]) / max(1, len(scores) - half)
    curr = sum(scores[:half]) / max(1, half)
    trend = "improving" if curr < prev else "worsening" if curr > prev else "stable"
    from collections import Counter
    all_techs = [t for s in simulations for t in (s.get("results") or {}).get("techniques", []) if t.get("status") == "found"]
    top_risks = [{"id": t, "count": c} for t, c in Counter(t.get("id") for t in all_techs).most_common(5)]
    return {
        "org_name": org_name,
        "risk_score": round(avg, 1),
        "trend": trend,
        "total_simulations": len(simulations),
        "last_simulation": simulations[0].get("date", "") if simulations else "",
        "critical_findings": sum(1 for t in all_techs if t.get("severity") == "critical"),
        "top_risks": top_risks,
        "score_history": [{"date": s.get("date", "")[:10], "score": s.get("score", 0)} for s in simulations[:12]],
        "generated_at": datetime.utcnow().isoformat(),
    }
