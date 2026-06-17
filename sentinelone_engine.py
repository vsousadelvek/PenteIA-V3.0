"""
sentinelone_engine.py — PenteIA V4.0
SentinelOne integration: correlate BAS technique results with S1 threat detections.
"""
import requests
from typing import Optional
from datetime import datetime, timedelta

class SentinelOneClient:
    def __init__(self, base_url: str, api_token: str, site_id: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"ApiToken {api_token}",
            "Content-Type": "application/json",
        }
        self.site_id = site_id

    def test_connection(self) -> dict:
        try:
            r = requests.get(f"{self.base_url}/web/api/v2.1/system/status", headers=self.headers, timeout=10)
            if r.status_code == 200:
                return {"status": "ok", "version": r.json().get("data", {}).get("health", "ok")}
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_threats(self, hours_back: int = 24) -> list:
        since = (datetime.utcnow() - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        params = {"createdAt__gte": since, "limit": 200, "sortBy": "createdAt", "sortOrder": "desc"}
        if self.site_id:
            params["siteIds"] = self.site_id
        try:
            r = requests.get(f"{self.base_url}/web/api/v2.1/threats", headers=self.headers, params=params, timeout=15)
            r.raise_for_status()
            return r.json().get("data", [])
        except Exception:
            return []

    def get_mitre_coverage(self) -> dict:
        try:
            r = requests.get(f"{self.base_url}/web/api/v2.1/threats/mitre", headers=self.headers, timeout=15)
            r.raise_for_status()
            return r.json().get("data", {})
        except Exception:
            return {}

    def correlate_with_simulation(self, simulation_techniques: list, hours_back: int = 24) -> dict:
        threats = self.get_threats(hours_back)
        threat_names = " ".join(t.get("threatInfo", {}).get("threatName", "").lower() for t in threats)
        threat_classifications = " ".join(t.get("threatInfo", {}).get("classification", "").lower() for t in threats)
        threat_mitre = []
        for t in threats:
            indicators = t.get("threatInfo", {}).get("mitigationStatus", "")
            mitre_data = t.get("threatInfo", {}).get("mitre", {})
            if mitre_data:
                for tac, techs in mitre_data.items():
                    threat_mitre.extend(techs if isinstance(techs, list) else [])

        results = []
        detected_count = 0
        for tech in simulation_techniques:
            tid = tech.get("id", "")
            name = tech.get("name", "").lower()
            detected = (
                tid in threat_mitre or
                any(word in threat_names for word in name.split()[:2] if len(word) > 4) or
                any(word in threat_classifications for word in name.split()[:2] if len(word) > 4)
            )
            if detected:
                detected_count += 1
            results.append({**tech, "s1_detected": detected, "s1_source": "threat" if detected else None})

        return {
            "total": len(results),
            "detected": detected_count,
            "detection_rate": round(detected_count / len(results) * 100, 1) if results else 0,
            "techniques": results,
            "threats_analyzed": len(threats),
        }


_S1_CONFIGS: dict = {}

def save_s1_config(user_id: str, base_url: str, api_token: str, site_id: Optional[str] = None) -> SentinelOneClient:
    client = SentinelOneClient(base_url, api_token, site_id)
    _S1_CONFIGS[user_id] = {"base_url": base_url, "api_token": api_token, "site_id": site_id}
    return client

def get_s1_client(user_id: str) -> Optional[SentinelOneClient]:
    cfg = _S1_CONFIGS.get(user_id)
    if not cfg:
        return None
    return SentinelOneClient(cfg["base_url"], cfg["api_token"], cfg.get("site_id"))
