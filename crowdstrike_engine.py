"""
crowdstrike_engine.py — PenteIA V4.0
CrowdStrike Falcon API integration for detection rate correlation.
OAuth2 client-credentials flow with automatic token refresh on 401.
"""

import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Thread-safe in-memory config store
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_cs_clients: dict[str, "CrowdStrikeClient"] = {}


# ---------------------------------------------------------------------------
# CrowdStrike Falcon client
# ---------------------------------------------------------------------------

class CrowdStrikeClient:
    """
    Thin wrapper around the CrowdStrike Falcon API.

    Authentication uses OAuth2 client-credentials; the access token is cached
    and refreshed automatically when it expires or when the API returns 401.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "https://api.crowdstrike.com",
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")

        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._token_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        """
        Return a valid OAuth2 access token, fetching a new one when the
        cached token is missing or within 30 seconds of expiry.
        """
        with self._token_lock:
            now = time.monotonic()
            if self._token and now < self._token_expires_at - 30:
                return self._token

            url = f"{self.base_url}/oauth2/token"
            payload = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            }
            try:
                response = requests.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=15,
                )
                response.raise_for_status()
                data = response.json()
                self._token = data["access_token"]
                expires_in = int(data.get("expires_in", 1800))
                self._token_expires_at = now + expires_in
                return self._token
            except requests.exceptions.HTTPError as exc:
                raise RuntimeError(
                    f"CrowdStrike OAuth2 token request failed: "
                    f"HTTP {exc.response.status_code} — {exc.response.text}"
                ) from exc
            except requests.RequestException as exc:
                raise RuntimeError(
                    f"CrowdStrike OAuth2 token request failed: {exc}"
                ) from exc

    def _invalidate_token(self) -> None:
        """Force token re-fetch on the next request."""
        with self._token_lock:
            self._token = None
            self._token_expires_at = 0.0

    def _auth_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: Optional[dict] = None, _retry: bool = True) -> requests.Response:
        """
        Authenticated GET with a single automatic retry on 401 (token refresh).
        """
        url = f"{self.base_url}{path}"
        try:
            response = requests.get(
                url, headers=self._auth_headers(), params=params, timeout=20
            )
            if response.status_code == 401 and _retry:
                self._invalidate_token()
                return self._get(path, params=params, _retry=False)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError:
            raise
        except requests.RequestException as exc:
            raise RuntimeError(f"GET {path} failed: {exc}") from exc

    def _post_json(self, path: str, body: dict, _retry: bool = True) -> requests.Response:
        """
        Authenticated POST (JSON body) with a single automatic retry on 401.
        """
        url = f"{self.base_url}{path}"
        try:
            response = requests.post(
                url, headers=self._auth_headers(), json=body, timeout=20
            )
            if response.status_code == 401 and _retry:
                self._invalidate_token()
                return self._post_json(path, body, _retry=False)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError:
            raise
        except requests.RequestException as exc:
            raise RuntimeError(f"POST {path} failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def test_connection(self) -> dict:
        """
        Verify credentials and API reachability.

        Uses the sensor-visibility-exclusions query endpoint as a lightweight
        health probe (returns an empty list when no exclusions exist, which is
        still a 200).

        Returns {"status": "ok", "message": str} or {"status": "error", "message": str}.
        """
        path = "/sensor-visibility-exclusions/queries/sensor-visibility-exclusions/v1"
        try:
            self._get(path, params={"limit": 1})
            return {"status": "ok", "message": "CrowdStrike Falcon connection successful."}
        except RuntimeError as exc:
            return {"status": "error", "message": str(exc)}
        except requests.exceptions.HTTPError as exc:
            return {
                "status": "error",
                "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
            }

    def get_detections(
        self,
        start_time: str,
        end_time: str,
        severity: Optional[list] = None,
    ) -> list[dict]:
        """
        Retrieve Falcon detections within [start_time, end_time].

        start_time / end_time — ISO 8601 strings, e.g. "2024-01-01T00:00:00Z".
        severity — optional list of severity strings to filter on
                   (e.g. ["High", "Critical"]).  Filtering is done client-side
                   after the API returns summaries.

        Returns a list of dicts:
          {id, tactic, technique, technique_id, severity, timestamp,
           hostname, filename}
        """
        # Step 1 — query detection IDs
        fql = (
            f"created_timestamp:>='{start_time}'"
            f"+created_timestamp:<='{end_time}'"
        )
        ids: list[str] = []
        offset = 0
        limit = 100  # Falcon max per page

        while True:
            try:
                resp = self._get(
                    "/detections/queries/detections/v1",
                    params={"filter": fql, "limit": limit, "offset": offset},
                )
            except (RuntimeError, requests.exceptions.HTTPError):
                break

            data = resp.json()
            page_ids: list[str] = data.get("resources", []) or []
            ids.extend(page_ids)
            meta = data.get("meta", {})
            pagination = meta.get("pagination", {})
            total = pagination.get("total", len(ids))
            offset += len(page_ids)
            if not page_ids or offset >= total:
                break

        if not ids:
            return []

        # Step 2 — fetch summaries in batches of 1000 (Falcon limit)
        results: list[dict] = []
        batch_size = 1000
        for i in range(0, len(ids), batch_size):
            batch = ids[i : i + batch_size]
            try:
                resp = self._post_json(
                    "/detections/entities/summaries/GET/v1",
                    {"ids": batch},
                )
            except (RuntimeError, requests.exceptions.HTTPError):
                continue

            resources = resp.json().get("resources", []) or []
            for r in resources:
                behaviors = r.get("behaviors", [{}])
                # Take the first behavior for tactic/technique information
                first_b = behaviors[0] if behaviors else {}

                entry = {
                    "id": r.get("detection_id", ""),
                    "tactic": first_b.get("tactic", ""),
                    "technique": first_b.get("technique", ""),
                    "technique_id": first_b.get("technique_id", ""),
                    "severity": r.get("max_severity_displayname", ""),
                    "timestamp": r.get("created_timestamp", ""),
                    "hostname": (r.get("device", {}) or {}).get("hostname", ""),
                    "filename": first_b.get("filename", ""),
                }
                results.append(entry)

        if severity:
            severity_lower = {s.lower() for s in severity}
            results = [
                r for r in results if r["severity"].lower() in severity_lower
            ]

        return results

    def correlate_with_simulation(
        self,
        simulation_techniques: list[str],
        hours_back: int = 24,
    ) -> dict:
        """
        Compare simulation technique IDs against CrowdStrike detections.

        simulation_techniques — list of MITRE technique IDs, e.g. ["T1059.001", "T1003"].
        hours_back           — look back window in hours (default 24).

        Returns:
        {
          "detected":      [{"technique_id": str, "technique_name": str,
                             "falcon_detected": True, "detection_id": str}],
          "not_detected":  [{"technique_id": str, "technique_name": str,
                             "falcon_detected": False}],
          "detection_rate_pct": float,   # 0.0–100.0
          "total_tested":  int,
          "total_detected": int,
        }
        """
        now_utc = datetime.now(timezone.utc)
        end_time = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        delta_seconds = hours_back * 3600
        start_dt = datetime.fromtimestamp(
            now_utc.timestamp() - delta_seconds, tz=timezone.utc
        )
        start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            raw_detections = self.get_detections(start_time, end_time)
        except Exception:
            raw_detections = []

        # Build lookup: canonical technique_id → (technique_name, detection_id)
        # Canonical = uppercase, WITH dots preserved (e.g. "T1003.006")
        falcon_map: dict[str, tuple[str, str]] = {}
        for det in raw_detections:
            raw_tid = (det.get("technique_id") or "").upper().strip()
            if raw_tid:
                if raw_tid not in falcon_map:
                    falcon_map[raw_tid] = (det.get("technique", ""), det.get("id", ""))

        def _cs_match(sim_tid: str) -> tuple[bool, str, str]:
            """
            Hierarchical matching: exact → parent → child.
            T1003.006 simulated → detects T1003.006 or T1003 (parent) or any T1003.x (child).
            Returns (matched, technique_name, detection_id).
            """
            tid = sim_tid.upper().strip()
            # 1. Exact match
            if tid in falcon_map:
                return True, *falcon_map[tid]
            # 2. Parent match — strip sub-technique (.NNN)
            parent = tid.split(".")[0]
            if parent in falcon_map:
                return True, *falcon_map[parent]
            # 3. Child match — sim has parent, CS detected a child
            for cs_tid, (cs_name, cs_id) in falcon_map.items():
                if cs_tid.startswith(parent + "."):
                    return True, cs_name, cs_id
            return False, "", ""

        detected: list[dict] = []
        not_detected: list[dict] = []

        for technique_id in simulation_techniques:
            matched, technique_name, detection_id = _cs_match(technique_id)
            if matched:
                detected.append(
                    {
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "falcon_detected": True,
                        "detection_id": detection_id,
                    }
                )
            else:
                not_detected.append(
                    {
                        "technique_id": technique_id,
                        "technique_name": "",
                        "falcon_detected": False,
                    }
                )

        total_tested = len(simulation_techniques)
        total_detected = len(detected)
        detection_rate_pct = (
            round(total_detected / total_tested * 100, 2) if total_tested else 0.0
        )

        return {
            "detected": detected,
            "not_detected": not_detected,
            "detection_rate_pct": detection_rate_pct,
            "total_tested": total_tested,
            "total_detected": total_detected,
        }


# ---------------------------------------------------------------------------
# Thread-safe config store helpers
# ---------------------------------------------------------------------------

def save_cs_config(
    user_id: str,
    client_id: str,
    client_secret: str,
    base_url: str = "https://api.crowdstrike.com",
) -> CrowdStrikeClient:
    """
    Instantiate a CrowdStrikeClient, cache it for user_id, and return it.
    """
    client = CrowdStrikeClient(client_id, client_secret, base_url)
    with _lock:
        _cs_clients[user_id] = client
    return client


def get_cs_client(user_id: str) -> Optional[CrowdStrikeClient]:
    """Return the cached CrowdStrikeClient for user_id, or None if not configured."""
    with _lock:
        return _cs_clients.get(user_id)
