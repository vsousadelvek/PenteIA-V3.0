"""
defender_engine.py — PenteIA V4.0
Microsoft Defender XDR / Defender for Endpoint integration.
Uses Microsoft Graph Security API and Defender Advanced Hunting.
"""
import requests
from typing import Optional
from datetime import datetime, timedelta

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SECURITY_BASE = "https://api.securitycenter.microsoft.com/api"
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


class DefenderClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    def _get_token(self) -> str:
        if self._token and self._token_expiry and datetime.utcnow() < self._token_expiry:
            return self._token
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://securitycenter.microsoft.com/.default",
        }
        r = requests.post(TOKEN_URL.format(tenant_id=self.tenant_id), data=data, timeout=15)
        r.raise_for_status()
        token_data = r.json()
        self._token = token_data["access_token"]
        self._token_expiry = datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 3600) - 60)
        return self._token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}", "Content-Type": "application/json"}

    def test_connection(self) -> dict:
        try:
            self._get_token()
            r = requests.get(f"{SECURITY_BASE}/machines?$top=1", headers=self._headers(), timeout=10)
            if r.status_code in (200, 204):
                return {"status": "ok", "message": "Defender XDR conectado"}
            return {"status": "error", "message": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_alerts(self, hours_back: int = 24) -> list:
        since = (datetime.utcnow() - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            r = requests.get(
                f"{SECURITY_BASE}/alerts?$filter=alertCreationTime ge {since}&$top=200&$orderby=alertCreationTime desc",
                headers=self._headers(), timeout=15
            )
            r.raise_for_status()
            return r.json().get("value", [])
        except Exception:
            return []

    def run_advanced_hunting(self, kql_query: str) -> list:
        try:
            r = requests.post(
                f"{SECURITY_BASE}/advancedqueries/run",
                json={"Query": kql_query},
                headers=self._headers(), timeout=30,
            )
            r.raise_for_status()
            return r.json().get("Results", [])
        except Exception:
            return []

    def correlate_with_simulation(self, simulation_techniques: list, hours_back: int = 24) -> dict:
        alerts = self.get_alerts(hours_back)

        # Build canonical lookup: uppercase WITH dots (e.g. "T1003.006")
        alert_technique_map: dict[str, str] = {}  # tid → alert_id
        alert_names_text = ""
        for alert in alerts:
            alert_id = alert.get("id", "")
            for technique in alert.get("mitreTechniques", []):
                canonical = technique.upper().strip()
                if canonical and canonical not in alert_technique_map:
                    alert_technique_map[canonical] = alert_id
            alert_names_text += " " + alert.get("title", "").lower()

        def _defender_match(sim_tid: str) -> bool:
            """Hierarchical matching — exact, parent, child, keyword."""
            tid = sim_tid.upper().strip()
            if tid in alert_technique_map:
                return True
            parent = tid.split(".")[0]
            if parent in alert_technique_map:
                return True
            for cs_tid in alert_technique_map:
                if cs_tid.startswith(parent + "."):
                    return True
            return False

        results = []
        detected_count = 0
        for tech in simulation_techniques:
            tid = tech.get("id", "")
            name = tech.get("name", "").lower()
            detected = _defender_match(tid) or any(
                word in alert_names_text for word in name.split()[:2] if len(word) > 4
            )
            if detected:
                detected_count += 1
            results.append({**tech, "defender_detected": detected})

        return {
            "total": len(results),
            "detected": detected_count,
            "detection_rate": round(detected_count / len(results) * 100, 1) if results else 0,
            "techniques": results,
            "alerts_analyzed": len(alerts),
        }


_DEFENDER_CONFIGS: dict = {}

def save_defender_config(user_id: str, tenant_id: str, client_id: str, client_secret: str) -> DefenderClient:
    client = DefenderClient(tenant_id, client_id, client_secret)
    _DEFENDER_CONFIGS[user_id] = {"tenant_id": tenant_id, "client_id": client_id, "client_secret": client_secret}
    return client

def get_defender_client(user_id: str) -> Optional[DefenderClient]:
    cfg = _DEFENDER_CONFIGS.get(user_id)
    if not cfg:
        return None
    return DefenderClient(cfg["tenant_id"], cfg["client_id"], cfg["client_secret"])
