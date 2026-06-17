"""
ai_scenario_generator.py — PenteIA V4.0
Auto-generates BAS scenarios from live threat intelligence:
  - CISA Known Exploited Vulnerabilities (KEV) feed
  - NVD CVE database
  - Manual CVE/description input

Uses Claude API (claude-haiku-4-5) to generate kill chains, IOCs,
detection hints, and ATT&CK mappings automatically.
"""
import os
import json
import uuid
import logging
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger("penteia.ai_scenarios")

# Persistence file
_STORE_PATH = Path(__file__).parent / "generated_scenarios.json"
_PROCESSED_KEV_PATH = Path(__file__).parent / "processed_kev_ids.json"

# CISA KEV feed
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD API
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Tactic mapping keywords → MITRE tactic
_TACTIC_HINTS = {
    "remote code execution": "EXECUTION",
    "command injection": "EXECUTION",
    "arbitrary code": "EXECUTION",
    "privilege escalation": "PRIVILEGE_ESCALATION",
    "elevation of privilege": "PRIVILEGE_ESCALATION",
    "authentication bypass": "INITIAL_ACCESS",
    "sql injection": "INITIAL_ACCESS",
    "path traversal": "INITIAL_ACCESS",
    "directory traversal": "INITIAL_ACCESS",
    "cross-site scripting": "INITIAL_ACCESS",
    "deserialization": "EXECUTION",
    "buffer overflow": "EXECUTION",
    "use after free": "EXECUTION",
    "memory corruption": "EXECUTION",
    "information disclosure": "COLLECTION",
    "credential": "CREDENTIAL_ACCESS",
    "password": "CREDENTIAL_ACCESS",
    "ransomware": "IMPACT",
    "denial of service": "IMPACT",
    "data exfil": "EXFILTRATION",
    "lateral": "LATERAL_MOVEMENT",
    "persistence": "PERSISTENCE",
    "backdoor": "PERSISTENCE",
    "webshell": "PERSISTENCE",
    "defense evasion": "DEFENSE_EVASION",
    "log clean": "DEFENSE_EVASION",
}

# Severity → CVSS approximate
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


# ── Persistence helpers ───────────────────────────────────────────────────────

def _load_store() -> list:
    if _STORE_PATH.exists():
        try:
            return json.loads(_STORE_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def _save_store(scenarios: list):
    _STORE_PATH.write_text(json.dumps(scenarios, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_processed_kev() -> set:
    if _PROCESSED_KEV_PATH.exists():
        try:
            return set(json.loads(_PROCESSED_KEV_PATH.read_text(encoding="utf-8")))
        except Exception:
            return set()
    return set()


def _save_processed_kev(ids: set):
    _PROCESSED_KEV_PATH.write_text(json.dumps(sorted(ids), ensure_ascii=False), encoding="utf-8")


# ── CISA KEV feed ─────────────────────────────────────────────────────────────

def fetch_kev_feed(limit: int = 20) -> list:
    """Fetch latest entries from CISA Known Exploited Vulnerabilities feed."""
    try:
        r = requests.get(KEV_FEED_URL, timeout=15)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        # Sort by dateAdded descending (newest first)
        vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        return vulns[:limit]
    except Exception as e:
        logger.warning(f"KEV feed fetch failed: {e}")
        return []


def fetch_nvd_cve(cve_id: str) -> Optional[dict]:
    """Fetch CVE details from NVD API."""
    try:
        r = requests.get(NVD_CVE_URL, params={"cveId": cve_id}, timeout=15)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
        return None
    except Exception as e:
        logger.warning(f"NVD fetch for {cve_id} failed: {e}")
        return None


# ── Tactic inference (fallback without AI) ────────────────────────────────────

def _infer_tactic(text: str) -> str:
    text_lower = text.lower()
    for keyword, tactic in _TACTIC_HINTS.items():
        if keyword in text_lower:
            return tactic
    return "INITIAL_ACCESS"


def _infer_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    return "low"


# ── Claude API generation ─────────────────────────────────────────────────────

def _call_claude(prompt: str, model: str = "claude-haiku-4-5-20251001") -> Optional[str]:
    """Call Claude API and return text response."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not set — using heuristic generation")
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text if msg.content else None
    except Exception as e:
        logger.error(f"Claude API call failed: {e}")
        return None


_GENERATION_PROMPT = """You are a senior red team expert. Generate a Breach and Attack Simulation (BAS) scenario from this CVE.

CVE ID: {cve_id}
Product/Vendor: {product}
Description: {description}
CVSS Score: {cvss}
Known ransomware use: {ransomware}

Return ONLY valid JSON with this exact structure (no markdown, no explanation):
{{
  "technique_id": "T1XXX",
  "technique_name": "Short technique name",
  "tactic": "ONE_OF: INITIAL_ACCESS|EXECUTION|PERSISTENCE|PRIVILEGE_ESCALATION|DEFENSE_EVASION|CREDENTIAL_ACCESS|DISCOVERY|LATERAL_MOVEMENT|COLLECTION|EXFILTRATION|COMMAND_AND_CONTROL|IMPACT",
  "severity": "critical|high|medium|low",
  "attack_name": "Short descriptive attack name",
  "description": "2-3 sentence description of what this attack does and why it matters",
  "affected_systems": ["list", "of", "affected", "products"],
  "kill_chain": [
    {{"step": 1, "action": "Attacker action step 1"}},
    {{"step": 2, "action": "Attacker action step 2"}},
    {{"step": 3, "action": "Attacker action step 3"}},
    {{"step": 4, "action": "Attacker action step 4"}},
    {{"step": 5, "action": "Attacker action step 5"}}
  ],
  "iocs": ["indicator1", "indicator2", "indicator3"],
  "detection_hints": ["SIEM/EDR rule or log source to detect this", "another detection hint"],
  "remediation": ["Patch to version X", "Disable feature Y", "Apply workaround Z"],
  "references": ["{cve_id}"]
}}"""


def generate_scenario_from_cve(cve_id: str, product: str, description: str,
                                 cvss: float = 7.0, ransomware: bool = False) -> dict:
    """Generate a BAS scenario from CVE data using Claude API, with heuristic fallback."""
    prompt = _GENERATION_PROMPT.format(
        cve_id=cve_id, product=product, description=description,
        cvss=cvss, ransomware="Yes" if ransomware else "No",
    )

    raw = _call_claude(prompt)

    if raw:
        try:
            # Strip markdown fences if present
            clean = raw.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            scenario = json.loads(clean.strip())
            scenario["cve_id"] = cve_id
            scenario["source"] = "ai_generated"
            scenario["generated_at"] = datetime.utcnow().isoformat()
            return scenario
        except json.JSONDecodeError:
            logger.warning(f"Claude returned invalid JSON for {cve_id}, using heuristic")

    # Heuristic fallback (no Claude API key or parse failure)
    return _heuristic_scenario(cve_id, product, description, cvss, ransomware)


def _heuristic_scenario(cve_id: str, product: str, description: str,
                         cvss: float, ransomware: bool) -> dict:
    """Generate a basic scenario without AI when Claude is unavailable."""
    tactic = _infer_tactic(description)
    severity = _infer_severity(cvss)
    # Map tactic to a plausible MITRE technique
    tactic_to_tid = {
        "INITIAL_ACCESS": "T1190", "EXECUTION": "T1059", "PERSISTENCE": "T1543",
        "PRIVILEGE_ESCALATION": "T1068", "DEFENSE_EVASION": "T1070",
        "CREDENTIAL_ACCESS": "T1003", "DISCOVERY": "T1082",
        "LATERAL_MOVEMENT": "T1021", "COLLECTION": "T1005",
        "EXFILTRATION": "T1041", "COMMAND_AND_CONTROL": "T1071",
        "IMPACT": "T1486",
    }
    tid = tactic_to_tid.get(tactic, "T1190")

    return {
        "technique_id": tid,
        "technique_name": f"Exploit: {product}",
        "tactic": tactic,
        "severity": severity,
        "attack_name": f"{cve_id} — {product} Exploit",
        "description": description[:300],
        "affected_systems": [product],
        "kill_chain": [
            {"step": 1, "action": f"Reconhecimento do {product} exposto"},
            {"step": 2, "action": f"Exploração da vulnerabilidade {cve_id}"},
            {"step": 3, "action": "Execução de payload pós-exploração"},
            {"step": 4, "action": "Estabelecimento de persistência"},
            {"step": 5, "action": "Exfiltração ou impacto no objetivo final"},
        ],
        "iocs": [cve_id, product.lower().replace(" ", "-"), "exploit"],
        "detection_hints": [
            f"Monitor for exploitation attempts against {product}",
            f"Alert on {cve_id} exploit signatures in IDS/WAF",
        ],
        "remediation": [f"Apply vendor patch for {cve_id}", "Enable exploit protection in EDR"],
        "references": [cve_id],
        "cve_id": cve_id,
        "source": "heuristic",
        "generated_at": datetime.utcnow().isoformat(),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def create_scenario_from_input(cve_id: str, product: str, description: str,
                                cvss: float = 7.0, ransomware: bool = False) -> dict:
    """Public: generate and persist a new scenario."""
    scenario = generate_scenario_from_cve(cve_id, product, description, cvss, ransomware)
    scenario["id"] = str(uuid.uuid4())
    scenario["cve_id"] = cve_id
    # Persist
    store = _load_store()
    # Replace if already exists for this CVE
    store = [s for s in store if s.get("cve_id") != cve_id]
    store.insert(0, scenario)
    _save_store(store)
    return scenario


def run_kev_sweep(max_new: int = 5) -> dict:
    """
    Fetch latest CISA KEV entries and generate scenarios for any not yet processed.
    Returns summary: {processed, new, skipped, scenarios}
    """
    feed = fetch_kev_feed(limit=50)
    processed_ids = _load_processed_kev()

    new_scenarios = []
    skipped = 0
    errors = 0

    for entry in feed:
        cve_id = entry.get("cveID", "")
        if not cve_id or cve_id in processed_ids:
            skipped += 1
            continue
        if len(new_scenarios) >= max_new:
            break

        product = f"{entry.get('vendorProject', '')} {entry.get('product', '')}".strip()
        description = entry.get("shortDescription", "")
        ransomware = entry.get("knownRansomwareCampaignUse", "Unknown") == "Known"

        try:
            scenario = create_scenario_from_input(cve_id, product, description, 8.0, ransomware)
            scenario["kev_date_added"] = entry.get("dateAdded", "")
            scenario["kev_required_action"] = entry.get("requiredAction", "")
            new_scenarios.append(scenario)
            processed_ids.add(cve_id)
            logger.info(f"Generated scenario for {cve_id}")
        except Exception as e:
            logger.error(f"Failed to generate scenario for {cve_id}: {e}")
            errors += 1

    _save_processed_kev(processed_ids)
    return {
        "processed": len(new_scenarios),
        "skipped": skipped,
        "errors": errors,
        "new_scenarios": new_scenarios,
    }


def list_scenarios(limit: int = 50, source: Optional[str] = None,
                   severity: Optional[str] = None, tactic: Optional[str] = None) -> list:
    store = _load_store()
    if source:
        store = [s for s in store if s.get("source") == source]
    if severity:
        store = [s for s in store if s.get("severity") == severity]
    if tactic:
        store = [s for s in store if s.get("tactic") == tactic]
    return store[:limit]


def get_scenario(scenario_id: str) -> Optional[dict]:
    return next((s for s in _load_store() if s.get("id") == scenario_id), None)


def delete_scenario(scenario_id: str) -> bool:
    store = _load_store()
    new_store = [s for s in store if s.get("id") != scenario_id]
    if len(new_store) == len(store):
        return False
    _save_store(new_store)
    return True


def get_kev_feed_preview(limit: int = 20) -> list:
    """Return raw KEV feed for UI preview (no generation)."""
    processed = _load_processed_kev()
    feed = fetch_kev_feed(limit=limit)
    for entry in feed:
        entry["already_generated"] = entry.get("cveID", "") in processed
    return feed


def get_stats() -> dict:
    store = _load_store()
    processed = _load_processed_kev()
    by_severity = {}
    by_tactic = {}
    by_source = {}
    for s in store:
        sev = s.get("severity", "unknown")
        tac = s.get("tactic", "unknown")
        src = s.get("source", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_tactic[tac] = by_tactic.get(tac, 0) + 1
        by_source[src] = by_source.get(src, 0) + 1
    return {
        "total_generated": len(store),
        "kev_ids_processed": len(processed),
        "by_severity": by_severity,
        "by_tactic": by_tactic,
        "by_source": by_source,
        "latest": store[0].get("generated_at") if store else None,
    }
