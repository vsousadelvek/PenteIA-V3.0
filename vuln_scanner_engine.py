"""
vuln_scanner_engine.py — PenteIA V4.0
Vulnerability scanner integrations: Tenable.io REST API, Qualys VMDR API,
and Nessus XML file parser (.nessus format).

All HTTP errors are caught and returned gracefully.
"""

import base64
import threading
import xml.etree.ElementTree as ET
from typing import Optional, Union

import requests

# ---------------------------------------------------------------------------
# Thread-safe in-memory config store
# ---------------------------------------------------------------------------

_lock = threading.Lock()

_tenable_clients: dict[str, "TenableClient"] = {}
_qualys_clients: dict[str, "QualysClient"] = {}

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_TENABLE_SEVERITY_MAP = {
    0: "informational",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

_QUALYS_SEVERITY_MAP = {
    "1": "informational",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}

_NESSUS_SEVERITY_MAP = {
    "0": "informational",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}


def _safe_float(value, default: Optional[float] = None) -> Optional[float]:
    """Convert value to float, returning default on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Tenable.io
# ---------------------------------------------------------------------------

class TenableClient:
    """Client for the Tenable.io REST API."""

    _BASE_URL = "https://cloud.tenable.com"

    def __init__(self, access_key: str, secret_key: str) -> None:
        self.access_key = access_key
        self.secret_key = secret_key
        self._headers = {
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: Optional[dict] = None) -> requests.Response:
        url = f"{self._BASE_URL}{path}"
        return requests.get(url, headers=self._headers, params=params, timeout=30)

    def test_connection(self) -> dict:
        """
        GET /session — verify API keys.
        Returns {"status": "ok", "username": str} or {"status": "error", "message": str}.
        """
        try:
            response = self._get("/session")
            response.raise_for_status()
            data = response.json()
            return {
                "status": "ok",
                "username": data.get("username", ""),
                "name": data.get("name", ""),
            }
        except requests.exceptions.HTTPError as exc:
            return {
                "status": "error",
                "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
            }
        except requests.RequestException as exc:
            return {"status": "error", "message": str(exc)}

    def get_scans(self) -> list[dict]:
        """
        GET /scans — list all scans.
        Returns list of scan dicts: [{id, uuid, name, status, start_time, ...}].
        Returns empty list on error.
        """
        try:
            response = self._get("/scans")
            response.raise_for_status()
            data = response.json()
            scans = data.get("scans") or []
            return [
                {
                    "id": s.get("id"),
                    "uuid": s.get("uuid"),
                    "name": s.get("name"),
                    "status": s.get("status"),
                    "start_time": s.get("starttime"),
                    "last_modification_date": s.get("last_modification_date"),
                    "folder_id": s.get("folder_id"),
                }
                for s in scans
            ]
        except requests.RequestException:
            return []

    def import_scan_vulnerabilities(self, scan_id: str) -> list[dict]:
        """
        GET /scans/{scan_id} — fetch scan detail and normalize vulnerabilities.

        Iterates hosts and their plugins to build a flat list normalized to:
        [{cve_id, name, cvss, severity, host, plugin_id, description}]
        """
        try:
            response = self._get(f"/scans/{scan_id}")
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            return []
        except requests.RequestException:
            return []

        try:
            data = response.json()
        except ValueError:
            return []

        hosts = data.get("hosts") or []
        vulnerabilities = data.get("vulnerabilities") or []

        # Build a plugin_id -> vuln info map from the top-level vulnerabilities list
        plugin_map: dict[str, dict] = {}
        for vuln in vulnerabilities:
            pid = str(vuln.get("plugin_id", ""))
            if pid:
                plugin_map[pid] = vuln

        results: list[dict] = []

        for host in hosts:
            hostname = host.get("hostname") or host.get("host-ip") or ""
            host_id = host.get("host_id")

            if not host_id:
                continue

            # Fetch per-host plugin detail
            try:
                host_resp = self._get(f"/scans/{scan_id}/hosts/{host_id}")
                host_resp.raise_for_status()
                host_data = host_resp.json()
            except requests.RequestException:
                host_data = {}

            host_vulns = host_data.get("vulnerabilities") or []

            for hv in host_vulns:
                plugin_id = str(hv.get("plugin_id", ""))
                plugin_name = hv.get("plugin_name", "")
                severity_int = hv.get("severity", 0)
                severity_label = _TENABLE_SEVERITY_MAP.get(severity_int, "unknown")

                # Pull additional detail from plugin_map
                pinfo = plugin_map.get(plugin_id, {})
                cvss = _safe_float(pinfo.get("cvss_base_score") or hv.get("cvss_base_score"))

                # CVE extraction — can be a list or a single string
                cve_raw = pinfo.get("cve") or hv.get("cve")
                if isinstance(cve_raw, list):
                    cve_id = cve_raw[0] if cve_raw else None
                elif isinstance(cve_raw, str) and cve_raw.strip():
                    cve_id = cve_raw.strip()
                else:
                    cve_id = None

                results.append({
                    "cve_id": cve_id,
                    "name": plugin_name,
                    "cvss": cvss,
                    "severity": severity_label,
                    "host": hostname,
                    "plugin_id": plugin_id,
                    "description": pinfo.get("description") or hv.get("description") or "",
                })

        return results

    def get_assets(self) -> list[dict]:
        """
        GET /assets — list all assets.
        Returns list of asset dicts: [{id, ipv4, fqdn, last_seen, ...}].
        Returns empty list on error.
        """
        try:
            response = self._get("/assets")
            response.raise_for_status()
            data = response.json()
            assets = data.get("assets") or []
            return [
                {
                    "id": a.get("id"),
                    "ipv4": a.get("ipv4", []),
                    "fqdn": a.get("fqdn", []),
                    "last_seen": a.get("last_seen"),
                    "operating_system": a.get("operating_system", []),
                    "agent_name": a.get("agent_name", []),
                    "sources": a.get("sources", []),
                }
                for a in assets
            ]
        except requests.RequestException:
            return []


# ---------------------------------------------------------------------------
# Qualys VMDR
# ---------------------------------------------------------------------------

class QualysClient:
    """Client for the Qualys VMDR API using Basic authentication."""

    def __init__(
        self,
        username: str,
        password: str,
        platform_url: str = "https://qualysapi.qg3.apps.qualys.com",
    ) -> None:
        self.platform_url = platform_url.rstrip("/")
        raw = f"{username}:{password}"
        encoded = base64.b64encode(raw.encode()).decode()
        self._headers = {
            "Authorization": f"Basic {encoded}",
            "X-Requested-With": "PenteIA-V4.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/xml, text/xml, */*",
        }

    def _url(self, path: str) -> str:
        return f"{self.platform_url}{path}"

    def test_connection(self) -> dict:
        """
        GET /api/2.0/fo/subscription/summary/ — verify credentials.
        Returns {"status": "ok", "platform": str} or {"status": "error", "message": str}.
        """
        try:
            response = requests.get(
                self._url("/api/2.0/fo/subscription/summary/"),
                headers=self._headers,
                timeout=30,
            )
            response.raise_for_status()
            # Parse minimal XML to confirm it's a valid Qualys response
            try:
                root = ET.fromstring(response.text)
                platform = root.findtext(".//PLATFORM") or self.platform_url
            except ET.ParseError:
                platform = self.platform_url
            return {"status": "ok", "platform": platform}
        except requests.exceptions.HTTPError as exc:
            return {
                "status": "error",
                "message": f"HTTP {exc.response.status_code}: {exc.response.text[:500]}",
            }
        except requests.RequestException as exc:
            return {"status": "error", "message": str(exc)}

    def get_vulnerability_report(self, days_back: int = 30) -> list[dict]:
        """
        POST /api/2.0/fo/report/ — request host detection list and parse results.

        Uses the VMDR host detection list API (action=list) which returns XML.
        Normalizes to: [{cve_id, title, severity, cvss, host, qid}].
        """
        # Use the host detection list endpoint — widely supported across Qualys platforms
        try:
            payload = {
                "action": "list",
                "show_igs": "1",
                "show_results": "1",
                "num_hosts_processed": "0",
                "truncation_limit": "1000",
                "status": "New,Active,Re-Opened,Fixed",
            }
            response = requests.post(
                self._url("/api/2.0/fo/asset/host/vm/detection/"),
                headers=self._headers,
                data=payload,
                timeout=60,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            return []
        except requests.RequestException:
            return []

        return self._parse_detection_xml(response.text)

    def _parse_detection_xml(self, xml_text: str) -> list[dict]:
        """Parse Qualys host detection XML and return normalized vuln list."""
        results: list[dict] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return results

        # Structure: HOST_LIST_VM_DETECTION_OUTPUT > RESPONSE > HOST_LIST > HOST
        for host_el in root.iter("HOST"):
            ip = host_el.findtext("IP") or ""
            fqdn = host_el.findtext("DNS") or host_el.findtext("NETBIOS") or ip
            hostname = fqdn or ip

            for detection in host_el.iter("DETECTION"):
                qid = detection.findtext("QID") or ""
                title = detection.findtext("RESULTS") or ""
                severity_raw = detection.findtext("SEVERITY") or "0"
                severity_label = _QUALYS_SEVERITY_MAP.get(severity_raw, "unknown")

                # CVE may be a comma-separated list
                cve_list_el = detection.findtext("CVE_LIST")
                cve_id: Optional[str] = None
                if cve_list_el:
                    first_cve = cve_list_el.split(",")[0].strip()
                    cve_id = first_cve if first_cve else None

                cvss = _safe_float(
                    detection.findtext("CVSS_FINAL")
                    or detection.findtext("CVSS_BASE")
                )

                # Try to get human-readable title from QG_TITLE element
                qg_title = detection.findtext("QG_TITLE") or title or f"QID-{qid}"

                results.append({
                    "cve_id": cve_id,
                    "title": qg_title,
                    "severity": severity_label,
                    "cvss": cvss,
                    "host": hostname,
                    "qid": qid,
                    "description": title,
                })

        return results


# ---------------------------------------------------------------------------
# Nessus XML Parser
# ---------------------------------------------------------------------------

def parse_nessus_xml(xml_content: Union[str, bytes]) -> list[dict]:
    """
    Parse a .nessus file (Nessus XML format) and return normalized vulns.

    Iterates ReportHost > ReportItem elements and extracts:
      plugin_name, cvss_base_score, cve, severity, pluginID, description, solution

    Returns list of:
      [{cve_id, name, cvss, severity, host, plugin_id, description}]
    """
    results: list[dict] = []

    try:
        if isinstance(xml_content, bytes):
            root = ET.fromstring(xml_content)
        else:
            root = ET.fromstring(xml_content.encode("utf-8"))
    except ET.ParseError:
        return results

    # Nessus XML structure: NessusClientData_v2 > Report > ReportHost > ReportItem
    for report_host in root.iter("ReportHost"):
        # hostname from name attribute or HostProperties
        hostname = report_host.get("name", "")
        if not hostname:
            host_props = report_host.find("HostProperties")
            if host_props is not None:
                for tag in host_props.findall("tag"):
                    if tag.get("name") in ("host-ip", "hostname"):
                        hostname = tag.text or ""
                        break

        for item in report_host.findall("ReportItem"):
            plugin_id = item.get("pluginID", "")
            plugin_name = item.get("pluginName", "")
            severity_raw = item.get("severity", "0")
            severity_label = _NESSUS_SEVERITY_MAP.get(severity_raw, "unknown")

            # CVE — may be repeated elements
            cve_elements = item.findall("cve")
            if cve_elements:
                cve_id = cve_elements[0].text or None
            else:
                cve_id = None

            # CVSS
            cvss = _safe_float(
                _first_text(item, "cvss_base_score")
                or _first_text(item, "cvss3_base_score")
            )

            description = _first_text(item, "description") or ""
            solution = _first_text(item, "solution") or ""

            results.append({
                "cve_id": cve_id,
                "name": plugin_name,
                "cvss": cvss,
                "severity": severity_label,
                "host": hostname,
                "plugin_id": plugin_id,
                "description": description,
                "solution": solution,
            })

    return results


def _first_text(element: ET.Element, tag: str) -> Optional[str]:
    """Return the text of the first child element with the given tag, or None."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return None


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

_SEVERITY_SORT_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "unknown": 5,
}


def normalize_vulns(raw_vulns: list[dict], source: str) -> list[dict]:
    """
    Normalize a list of raw vulnerability dicts into the PenteIA standard format.

    source: "tenable" | "qualys" | "nessus" (or any label)

    Each input dict may use varying field names depending on the source.
    Output format per entry:
      {
        "cve_id": str | None,
        "name": str,
        "cvss": float | None,
        "severity": str,
        "host": str,
        "source": str,
        "description": str,
        "remediation": str,
      }

    Results are sorted by severity (critical first).
    """
    normalized: list[dict] = []

    for raw in raw_vulns:
        # cve_id — present under different keys
        cve_id = (
            raw.get("cve_id")
            or raw.get("cve")
            or None
        )

        # name — Qualys uses "title", others use "name"
        name = (
            raw.get("name")
            or raw.get("title")
            or raw.get("plugin_name")
            or "Unknown"
        )

        # cvss
        cvss = _safe_float(raw.get("cvss") or raw.get("cvss_base_score"))

        # severity — already normalized to lowercase label by parsers
        severity = (raw.get("severity") or "unknown").lower()

        # host
        host = raw.get("host") or raw.get("hostname") or ""

        # description
        description = raw.get("description") or ""

        # remediation — nessus has "solution", others may have "remediation"
        remediation = (
            raw.get("remediation")
            or raw.get("solution")
            or ""
        )

        normalized.append({
            "cve_id": cve_id,
            "name": name,
            "cvss": cvss,
            "severity": severity,
            "host": host,
            "source": source,
            "description": description,
            "remediation": remediation,
        })

    # Sort: by severity priority, then by CVSS descending (None treated as 0)
    normalized.sort(
        key=lambda v: (
            _SEVERITY_SORT_ORDER.get(v["severity"], 99),
            -(v["cvss"] or 0.0),
        )
    )

    return normalized


# ---------------------------------------------------------------------------
# Thread-safe config store helpers
# ---------------------------------------------------------------------------

# --- Tenable ---

def save_tenable_config(
    user_id: str,
    access_key: str,
    secret_key: str,
) -> "TenableClient":
    """
    Instantiate a TenableClient, cache it for user_id, and return it.
    """
    client = TenableClient(access_key, secret_key)
    with _lock:
        _tenable_clients[user_id] = client
    return client


def get_tenable_client(user_id: str) -> Optional["TenableClient"]:
    """Return the cached TenableClient for user_id, or None if not configured."""
    with _lock:
        return _tenable_clients.get(user_id)


# --- Qualys ---

def save_qualys_config(
    user_id: str,
    username: str,
    password: str,
    platform_url: str = "https://qualysapi.qg3.apps.qualys.com",
) -> "QualysClient":
    """
    Instantiate a QualysClient, cache it for user_id, and return it.
    """
    client = QualysClient(username, password, platform_url)
    with _lock:
        _qualys_clients[user_id] = client
    return client


def get_qualys_client(user_id: str) -> Optional["QualysClient"]:
    """Return the cached QualysClient for user_id, or None if not configured."""
    with _lock:
        return _qualys_clients.get(user_id)
