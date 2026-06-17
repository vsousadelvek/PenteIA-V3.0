"""
soar_engine.py — PenteIA V4.0
SOAR integration: Splunk SOAR (Phantom) and Palo Alto XSOAR.
Sends BAS findings as SOAR events/cases for playbook testing.
"""
import requests
import json
from typing import Optional
from datetime import datetime


class SplunkSOARClient:
    """Splunk SOAR (formerly Phantom) REST API client."""

    def __init__(self, base_url: str, auth_token: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "ph-auth-token": auth_token,
            "Content-Type": "application/json",
        }
        self.verify_ssl = verify_ssl

    def test_connection(self) -> dict:
        try:
            r = requests.get(f"{self.base_url}/rest/version", headers=self.headers,
                           timeout=10, verify=self.verify_ssl)
            if r.status_code == 200:
                return {"status": "ok", "version": r.json().get("version", "unknown")}
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def create_event(self, simulation: dict, technique: dict) -> dict:
        tid = technique.get("id", "")
        name = technique.get("name", "")
        severity_map = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
        sev = severity_map.get(technique.get("severity", "medium"), "medium")

        container = {
            "name": f"[PenteIA BAS] {tid}: {name}",
            "description": f"BAS technique detected by PenteIA V4.0\nTarget: {simulation.get('target','')}\nStatus: {technique.get('status','')}",
            "severity": sev,
            "status": "new",
            "label": "penteia_bas",
            "tags": ["penteia", "bas", "red_team", tid],
            "source_data_identifier": f"penteia_{simulation.get('id','')[:8]}_{tid}",
            "custom_fields": {
                "mitre_technique": tid,
                "mitre_tactic": technique.get("tactic", ""),
                "bas_score": simulation.get("score", 0),
                "simulation_target": simulation.get("target", ""),
            },
        }

        try:
            r = requests.post(f"{self.base_url}/rest/container", json=container,
                            headers=self.headers, timeout=15, verify=self.verify_ssl)
            r.raise_for_status()
            result = r.json()
            container_id = result.get("id")

            # Add artifact with IOC details
            artifact = {
                "container_id": container_id,
                "name": f"Technique: {tid}",
                "label": "mitre_technique",
                "cef": {
                    "mitreTechniqueId": tid,
                    "mitreTechniqueName": name,
                    "mitreTactic": technique.get("tactic", ""),
                    "targetHostname": simulation.get("target", ""),
                    "severity": technique.get("severity", ""),
                    "toolName": "PenteIA V4.0",
                },
                "type": "network",
                "run_automation": True,
            }
            requests.post(f"{self.base_url}/rest/artifact", json=artifact,
                         headers=self.headers, timeout=10, verify=self.verify_ssl)

            return {"status": "ok", "container_id": container_id,
                    "url": f"{self.base_url}/mission/{container_id}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def push_simulation(self, simulation: dict, only_critical: bool = False) -> dict:
        techniques = simulation.get("techniques", [])
        if only_critical:
            techniques = [t for t in techniques if t.get("severity") in ("critical", "high")]

        results = []
        errors = 0
        for t in techniques:
            if t.get("status") != "found":
                continue
            res = self.create_event(simulation, t)
            results.append(res)
            if res.get("status") == "error":
                errors += 1

        return {"pushed": len(results), "errors": errors, "events": results}


class XSOARClient:
    """Palo Alto XSOAR (Cortex XSOAR) REST API client."""

    def __init__(self, base_url: str, api_key: str, server_url: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def test_connection(self) -> dict:
        try:
            r = requests.get(f"{self.base_url}/about", headers=self.headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                return {"status": "ok", "version": data.get("demistoVersion", "unknown")}
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def create_incident(self, simulation: dict, technique: dict) -> dict:
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        tid = technique.get("id", "")

        incident = {
            "name": f"[PenteIA BAS] {tid}: {technique.get('name','')}",
            "type": "PenteIA BAS Finding",
            "severity": severity_map.get(technique.get("severity", "medium"), 2),
            "details": (
                f"BAS finding from PenteIA V4.0\n"
                f"Target: {simulation.get('target','')}\n"
                f"Technique: {tid} — {technique.get('name','')}\n"
                f"Tactic: {technique.get('tactic','')}\n"
                f"Status: {technique.get('status','')}\n"
                f"Simulation score: {simulation.get('score',0):.1f}%"
            ),
            "labels": [
                {"type": "MITRE Technique", "value": tid},
                {"type": "Tool", "value": "PenteIA V4.0"},
                {"type": "Target", "value": simulation.get("target", "")},
            ],
            "CustomFields": {
                "mitretechnique": tid,
                "mitre_tactic": technique.get("tactic", ""),
                "bas_score": simulation.get("score", 0),
            },
        }

        try:
            r = requests.post(f"{self.base_url}/incident", json=incident,
                            headers=self.headers, timeout=15)
            r.raise_for_status()
            result = r.json()
            return {"status": "ok", "incident_id": result.get("id"),
                    "name": result.get("name")}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def push_simulation(self, simulation: dict, only_critical: bool = False) -> dict:
        techniques = simulation.get("techniques", [])
        if only_critical:
            techniques = [t for t in techniques if t.get("severity") in ("critical", "high")]

        results = []
        errors = 0
        for t in techniques:
            if t.get("status") != "found":
                continue
            res = self.create_incident(simulation, t)
            results.append(res)
            if res.get("status") == "error":
                errors += 1

        return {"pushed": len(results), "errors": errors, "incidents": results}


_SOAR_CONFIGS: dict = {}

def save_soar_config(user_id: str, soar_type: str, config: dict) -> dict:
    _SOAR_CONFIGS[user_id] = {"type": soar_type, **config}
    return {"status": "ok", "type": soar_type}

def get_soar_client(user_id: str):
    cfg = _SOAR_CONFIGS.get(user_id)
    if not cfg:
        return None
    t = cfg.get("type")
    if t == "splunk_soar":
        return SplunkSOARClient(cfg["base_url"], cfg["auth_token"], cfg.get("verify_ssl", True))
    elif t == "xsoar":
        return XSOARClient(cfg["base_url"], cfg["api_key"])
    return None
