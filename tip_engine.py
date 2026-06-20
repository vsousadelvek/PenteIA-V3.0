"""
tip_engine.py — PenteIA V4.0
Threat Intelligence Platform (TIP) integration.
Supports: MISP, OpenCTI, OTX AlienVault.
"""
import requests
from typing import Optional

_TIP_CONFIGS = {}


class MISPClient:
    def __init__(self, base_url, api_key, verify_ssl=True):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
        self.verify_ssl = verify_ssl

    def test_connection(self):
        try:
            r = requests.get(f"{self.base_url}/servers/getVersion", headers=self.headers, verify=self.verify_ssl, timeout=10)
            if r.status_code == 200:
                return {"status": "ok", "version": r.json().get("version", "unknown")}
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def search_ioc(self, ioc):
        try:
            body = {"returnFormat": "json", "value": ioc, "limit": 20}
            r = requests.post(f"{self.base_url}/attributes/restSearch", json=body, headers=self.headers, verify=self.verify_ssl, timeout=15)
            r.raise_for_status()
            attrs = r.json().get("response", {}).get("Attribute", [])
            return [{"type": a.get("type"), "value": a.get("value"), "event_id": a.get("event_id")} for a in attrs[:10]]
        except Exception:
            return []

    def enrich_technique(self, technique_id):
        iocs = self.search_ioc(technique_id)
        return {"technique_id": technique_id, "misp_matches": len(iocs), "iocs": iocs, "source": "MISP"}


class OpenCTIClient:
    def __init__(self, base_url, api_token):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    def test_connection(self):
        query = '{"query": "{ about { version } }"}'
        try:
            r = requests.post(f"{self.base_url}/graphql", data=query, headers=self.headers, timeout=10)
            if r.status_code == 200:
                return {"status": "ok", "version": r.json().get("data", {}).get("about", {}).get("version", "unknown")}
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def search_indicator(self, pattern):
        return []


class OTXClient:
    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key):
        self.headers = {"X-OTX-API-KEY": api_key}

    def test_connection(self):
        try:
            r = requests.get(f"{self.BASE}/user/me", headers=self.headers, timeout=10)
            if r.status_code == 200:
                return {"status": "ok", "username": r.json().get("username")}
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def enrich_ioc(self, ioc_type, ioc_value):
        endpoints = {
            "ip": f"{self.BASE}/indicators/IPv4/{ioc_value}/general",
            "domain": f"{self.BASE}/indicators/domain/{ioc_value}/general",
            "hash": f"{self.BASE}/indicators/file/{ioc_value}/general",
            "url": f"{self.BASE}/indicators/url/{ioc_value}/general",
        }
        url = endpoints.get(ioc_type, endpoints["domain"])
        try:
            r = requests.get(url, headers=self.headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                return {
                    "ioc": ioc_value, "type": ioc_type,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0),
                    "source": "OTX",
                }
            return {"ioc": ioc_value, "error": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"ioc": ioc_value, "error": str(e)}


def save_tip_config(user_id, tip_type, config):
    _TIP_CONFIGS[user_id] = {"type": tip_type, **config}


def get_tip_client(user_id):
    cfg = _TIP_CONFIGS.get(user_id)
    if not cfg:
        return None
    t = cfg["type"]
    if t == "misp":
        return MISPClient(cfg.get("base_url", ""), cfg.get("api_key", ""), cfg.get("verify_ssl", True))
    if t == "opencti":
        return OpenCTIClient(cfg.get("base_url", ""), cfg.get("api_token", ""))
    if t == "otx":
        return OTXClient(cfg.get("api_key", ""))
    return None


def get_tip_config(user_id):
    cfg = _TIP_CONFIGS.get(user_id, {})
    return {k: v for k, v in cfg.items() if "key" not in k.lower() and "token" not in k.lower() and "secret" not in k.lower()}
