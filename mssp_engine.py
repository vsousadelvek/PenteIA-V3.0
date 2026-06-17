"""
mssp_engine.py — PenteIA V4.0
MSSP White-Label Portal engine.
Manages partner branding, client portfolios, aggregate risk scores,
and white-label PDF report generation.
"""
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

_STORE_PATH = Path(__file__).parent / "mssp_data.json"

# ── Data model ────────────────────────────────────────────────────────────────

def _load() -> dict:
    if _STORE_PATH.exists():
        try:
            return json.loads(_STORE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"partners": {}, "clients": {}, "assignments": {}}


def _save(data: dict):
    _STORE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ── Partners ──────────────────────────────────────────────────────────────────

def create_partner(name: str, slug: str, owner_user_id: str,
                   logo_url: str = "", primary_color: str = "#E53E3E",
                   secondary_color: str = "#1A202C", contact_email: str = "") -> dict:
    """Create a new MSSP partner."""
    data = _load()
    if slug in data["partners"]:
        raise ValueError(f"Partner slug '{slug}' already exists")
    partner = {
        "id": str(uuid.uuid4()),
        "name": name,
        "slug": slug,
        "owner_user_id": owner_user_id,
        "branding": {
            "logo_url": logo_url,
            "primary_color": primary_color,
            "secondary_color": secondary_color,
            "company_name": name,
            "report_footer": f"Relatório gerado por {name} | Powered by PenteIA V4.0",
        },
        "contact_email": contact_email,
        "plan": "mssp_standard",
        "client_count": 0,
        "created_at": datetime.utcnow().isoformat(),
        "active": True,
    }
    data["partners"][partner["id"]] = partner
    _save(data)
    return partner


def get_partner(partner_id: str) -> Optional[dict]:
    return _load()["partners"].get(partner_id)


def get_partner_by_slug(slug: str) -> Optional[dict]:
    for p in _load()["partners"].values():
        if p["slug"] == slug:
            return p
    return None


def list_partners(owner_user_id: Optional[str] = None) -> list:
    partners = list(_load()["partners"].values())
    if owner_user_id:
        partners = [p for p in partners if p["owner_user_id"] == owner_user_id]
    return partners


def update_partner_branding(partner_id: str, branding: dict) -> dict:
    data = _load()
    if partner_id not in data["partners"]:
        raise KeyError(f"Partner {partner_id} not found")
    data["partners"][partner_id]["branding"].update(branding)
    _save(data)
    return data["partners"][partner_id]


def delete_partner(partner_id: str, owner_user_id: str) -> bool:
    data = _load()
    partner = data["partners"].get(partner_id)
    if not partner or partner["owner_user_id"] != owner_user_id:
        return False
    del data["partners"][partner_id]
    # Remove assignments
    data["assignments"] = {k: v for k, v in data["assignments"].items() if v["partner_id"] != partner_id}
    _save(data)
    return True


# ── Clients ───────────────────────────────────────────────────────────────────

def create_client(partner_id: str, name: str, sector: str, contact_email: str,
                  tenant_org_id: Optional[str] = None) -> dict:
    data = _load()
    if partner_id not in data["partners"]:
        raise KeyError(f"Partner {partner_id} not found")
    client = {
        "id": str(uuid.uuid4()),
        "partner_id": partner_id,
        "name": name,
        "sector": sector,
        "contact_email": contact_email,
        "tenant_org_id": tenant_org_id,
        "risk_score": None,
        "last_simulation": None,
        "simulation_count": 0,
        "created_at": datetime.utcnow().isoformat(),
        "active": True,
    }
    data["clients"][client["id"]] = client
    data["partners"][partner_id]["client_count"] = sum(
        1 for c in data["clients"].values() if c["partner_id"] == partner_id
    )
    _save(data)
    return client


def list_clients(partner_id: str) -> list:
    return [c for c in _load()["clients"].values() if c["partner_id"] == partner_id]


def update_client_metrics(client_id: str, risk_score: float, simulation_count: int,
                           last_simulation: str) -> dict:
    data = _load()
    if client_id not in data["clients"]:
        raise KeyError(f"Client {client_id} not found")
    data["clients"][client_id].update({
        "risk_score": risk_score,
        "simulation_count": simulation_count,
        "last_simulation": last_simulation,
    })
    _save(data)
    return data["clients"][client_id]


def delete_client(client_id: str, partner_id: str) -> bool:
    data = _load()
    client = data["clients"].get(client_id)
    if not client or client["partner_id"] != partner_id:
        return False
    del data["clients"][client_id]
    _save(data)
    return True


# ── Portfolio analytics ───────────────────────────────────────────────────────

def get_partner_portfolio(partner_id: str) -> dict:
    """Return aggregate risk metrics for all clients of a partner."""
    clients = list_clients(partner_id)
    partner = get_partner(partner_id)
    if not partner:
        raise KeyError(f"Partner {partner_id} not found")

    scored = [c for c in clients if c["risk_score"] is not None]
    avg_risk = sum(c["risk_score"] for c in scored) / len(scored) if scored else 0
    critical_clients = [c for c in scored if c["risk_score"] >= 70]
    by_sector: dict = {}
    for c in clients:
        sec = c.get("sector", "unknown")
        by_sector.setdefault(sec, []).append(c.get("risk_score") or 0)

    return {
        "partner": partner,
        "total_clients": len(clients),
        "scored_clients": len(scored),
        "avg_risk_score": round(avg_risk, 1),
        "critical_clients": len(critical_clients),
        "by_sector": {sec: round(sum(scores)/len(scores), 1) for sec, scores in by_sector.items()},
        "clients": sorted(clients, key=lambda c: c.get("risk_score") or 0, reverse=True),
    }


def generate_partner_report_data(partner_id: str) -> dict:
    """Build data structure for white-label PDF generation."""
    portfolio = get_partner_portfolio(partner_id)
    partner = portfolio["partner"]
    return {
        "branding": partner["branding"],
        "partner_name": partner["name"],
        "generated_at": datetime.utcnow().isoformat(),
        "portfolio_summary": {
            "total_clients": portfolio["total_clients"],
            "avg_risk_score": portfolio["avg_risk_score"],
            "critical_clients": portfolio["critical_clients"],
            "by_sector": portfolio["by_sector"],
        },
        "clients": portfolio["clients"],
        "report_type": "mssp_portfolio",
    }


# ── MSSP plan limits ──────────────────────────────────────────────────────────

MSSP_PLANS = {
    "mssp_standard": {"max_clients": 20, "label": "MSSP Standard", "price_brl": 4990},
    "mssp_professional": {"max_clients": 100, "label": "MSSP Professional", "price_brl": 12990},
    "mssp_enterprise": {"max_clients": -1, "label": "MSSP Enterprise", "price_brl": 0},
}
