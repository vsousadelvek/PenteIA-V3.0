"""
purple_team_engine.py — PenteIA V4.0
Purple Team mode: maps BAS simulation results to SIEM/EDR detection outcomes.
Provides detection confidence scoring per technique.
"""
from typing import Optional
import json

# Detection source types
DETECTION_SOURCES = ["siem", "edr", "ndr", "soar", "manual"]

# MITRE technique → expected detection signals
DETECTION_HINTS = {
    "T1059": ["powershell execution", "cmd spawn", "script block logging"],
    "T1055": ["process injection", "remote thread", "memory write"],
    "T1003": ["lsass dump", "credential access", "mimikatz"],
    "T1021": ["lateral movement", "psexec", "wmi remote"],
    "T1070": ["log deletion", "event log cleared"],
    "T1078": ["valid account", "new logon", "unusual logon"],
    "T1486": ["ransomware", "file encryption", "shadow copy deletion"],
    "T1190": ["exploit public facing", "web shell", "cve exploitation"],
    "T1133": ["external remote service", "vpn", "rdp"],
    "T1566": ["phishing", "suspicious attachment", "macro execution"],
    "BR-PIX-001": ["pix transaction", "financial fraud", "unusual transfer"],
    "BR-MALW-001": ["grandoreiro", "banking trojan", "brazil malware"],
    "BR-PHISH-001": ["phishing email", "banking credential harvest"],
}


class PurpleTeamResult:
    """Holds purple team assessment for a single technique."""
    def __init__(self, technique_id: str, technique_name: str, tactic: str):
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactic = tactic
        self.detected = False
        self.detection_source: Optional[str] = None
        self.detection_time_seconds: Optional[int] = None
        self.alert_generated = False
        self.alert_fidelity: str = "none"  # none/low/medium/high
        self.notes: str = ""
        self.confidence_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "detected": self.detected,
            "detection_source": self.detection_source,
            "detection_time_seconds": self.detection_time_seconds,
            "alert_generated": self.alert_generated,
            "alert_fidelity": self.alert_fidelity,
            "notes": self.notes,
            "confidence_score": round(self.confidence_score, 2),
            "hints": DETECTION_HINTS.get(self.technique_id, []),
        }


def calculate_confidence(result: PurpleTeamResult) -> float:
    """Calculate detection confidence score 0-100."""
    score = 0.0
    if result.detected:
        score += 40.0
    if result.alert_generated:
        score += 20.0
    fidelity_bonus = {"high": 30.0, "medium": 20.0, "low": 10.0, "none": 0.0}
    score += fidelity_bonus.get(result.alert_fidelity, 0)
    if result.detection_source:
        score += 10.0
    if result.detection_time_seconds is not None and result.detection_time_seconds < 300:
        score += 5.0
    return min(100.0, score)


def create_purple_session(simulation_results: dict) -> dict:
    """Initialize a purple team session from simulation results."""
    techniques = simulation_results.get("techniques", [])
    session = {
        "total_techniques": len(techniques),
        "assessed": 0,
        "detected": 0,
        "detection_rate": 0.0,
        "avg_confidence": 0.0,
        "coverage_by_tactic": {},
        "techniques": []
    }

    for t in techniques:
        pt = PurpleTeamResult(
            technique_id=t.get("id", ""),
            technique_name=t.get("name", ""),
            tactic=t.get("tactic", ""),
        )
        session["techniques"].append(pt.to_dict())

    return session


def update_technique_detection(session: dict, technique_id: str, detection_data: dict) -> dict:
    """Update detection result for a specific technique."""
    for t in session.get("techniques", []):
        if t["technique_id"] == technique_id:
            pt = PurpleTeamResult(technique_id, t["technique_name"], t["tactic"])
            pt.detected = detection_data.get("detected", False)
            pt.detection_source = detection_data.get("detection_source")
            pt.detection_time_seconds = detection_data.get("detection_time_seconds")
            pt.alert_generated = detection_data.get("alert_generated", False)
            pt.alert_fidelity = detection_data.get("alert_fidelity", "none")
            pt.notes = detection_data.get("notes", "")
            pt.confidence_score = calculate_confidence(pt)
            t.update(pt.to_dict())
            break

    return _recalculate_session(session)


def _recalculate_session(session: dict) -> dict:
    """Recalculate aggregate metrics."""
    techs = session.get("techniques", [])
    assessed = [t for t in techs if t.get("detected") is not None and t.get("detection_source") is not None]
    detected = [t for t in techs if t.get("detected")]

    session["assessed"] = len(assessed)
    session["detected"] = len(detected)
    session["detection_rate"] = round(len(detected) / len(techs) * 100, 1) if techs else 0.0
    session["avg_confidence"] = round(
        sum(t.get("confidence_score", 0) for t in detected) / len(detected), 1
    ) if detected else 0.0

    # Coverage by tactic
    tactic_map: dict = {}
    for t in techs:
        tac = t.get("tactic", "UNKNOWN")
        if tac not in tactic_map:
            tactic_map[tac] = {"total": 0, "detected": 0}
        tactic_map[tac]["total"] += 1
        if t.get("detected"):
            tactic_map[tac]["detected"] += 1

    session["coverage_by_tactic"] = {
        tac: {
            "total": v["total"],
            "detected": v["detected"],
            "rate": round(v["detected"] / v["total"] * 100, 1) if v["total"] else 0,
        }
        for tac, v in tactic_map.items()
    }

    return session


def generate_purple_report(session: dict) -> dict:
    """Generate a purple team gap analysis report."""
    techs = session.get("techniques", [])
    gaps = [t for t in techs if not t.get("detected")]
    detected = [t for t in techs if t.get("detected")]

    # Group gaps by tactic
    gaps_by_tactic: dict = {}
    for t in gaps:
        tac = t.get("tactic", "UNKNOWN")
        gaps_by_tactic.setdefault(tac, []).append(t["technique_id"])

    # Priority gaps (critical techniques not detected)
    priority_ids = {"T1003", "T1055", "T1486", "T1190", "BR-PIX-001", "BR-MALW-001"}
    critical_gaps = [t for t in gaps if t.get("technique_id") in priority_ids]

    return {
        "detection_rate": session.get("detection_rate", 0),
        "avg_confidence": session.get("avg_confidence", 0),
        "total_techniques": session.get("total_techniques", 0),
        "detected_count": len(detected),
        "gap_count": len(gaps),
        "critical_gaps": critical_gaps,
        "gaps_by_tactic": gaps_by_tactic,
        "coverage_by_tactic": session.get("coverage_by_tactic", {}),
        "recommendations": _generate_recommendations(gaps_by_tactic, session.get("detection_rate", 0)),
    }


def _generate_recommendations(gaps_by_tactic: dict, detection_rate: float) -> list:
    """Generate prioritized tuning recommendations."""
    recs = []
    if detection_rate < 50:
        recs.append({"priority": "critical", "action": "Habilitar logging de PowerShell e auditoria de processos no SIEM"})
        recs.append({"priority": "critical", "action": "Revisar regras de detecção de lateral movement (T1021)"})
    if "CREDENTIAL_ACCESS" in gaps_by_tactic:
        recs.append({"priority": "high", "action": "Adicionar alertas para dump de credenciais (LSASS, SAM)"})
    if "EXECUTION" in gaps_by_tactic:
        recs.append({"priority": "high", "action": "Tunar regras de execução de scripts no EDR"})
    if "EXFILTRATION" in gaps_by_tactic:
        recs.append({"priority": "medium", "action": "Configurar DLP e monitoramento de transferências grandes"})
    if detection_rate >= 80:
        recs.append({"priority": "info", "action": "Excelente cobertura — focar em redução de false positives e MTTD"})
    return recs


# In-memory session store (keyed by simulation_id)
_SESSIONS: dict = {}

def get_or_create_session(sim_id: str, simulation_results: dict) -> dict:
    if sim_id not in _SESSIONS:
        _SESSIONS[sim_id] = create_purple_session(simulation_results)
    return _SESSIONS[sim_id]

def get_session(sim_id: str) -> dict | None:
    return _SESSIONS.get(sim_id)

def save_session(sim_id: str, session: dict):
    _SESSIONS[sim_id] = session
