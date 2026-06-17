"""
epss_engine.py — EPSS + CISA KEV vulnerability scoring engine for PenteIA V4.0

Exports:
    get_epss_score(cve_id)        -> float
    is_in_kev(cve_id)             -> bool
    enrich_vulnerability(cve_id, cvss_score) -> dict
    enrich_batch(cve_list)        -> list[dict]
    refresh_kev_cache()           -> int
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DIR = os.path.dirname(os.path.abspath(__file__))

_EPSS_CACHE_FILE = os.path.join(_DIR, "_epss_cache.json")
_KEV_CACHE_FILE = os.path.join(_DIR, "_kev_cache.json")

_EPSS_API_URL = "https://api.first.org/data/v1/epss"
_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

_EPSS_TTL_HOURS = 24
_KEV_TTL_HOURS = 12

_REQUEST_TIMEOUT = 15  # seconds

# Max CVEs per batch request to the EPSS API (no hard limit documented,
# but keeping it reasonable avoids very long URLs / server rejections).
_EPSS_BATCH_CHUNK = 100

# ---------------------------------------------------------------------------
# Thread locks — one per cache file
# ---------------------------------------------------------------------------

_epss_lock = threading.Lock()
_kev_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Low-level cache helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hours_since(iso_ts: str) -> float:
    """Return hours elapsed since *iso_ts* (ISO-8601 string, UTC)."""
    try:
        ts = datetime.fromisoformat(iso_ts)
        delta = datetime.now(timezone.utc) - ts
        return delta.total_seconds() / 3600.0
    except Exception:
        return float("inf")


def _load_cache(path: str) -> dict[str, Any]:
    """Read a cache file; return empty structure on any error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_cache(path: str, payload: dict[str, Any]) -> None:
    """Persist *payload* to *path* atomically (write + rename)."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception as exc:
        logger.warning("epss_engine: could not write cache %s: %s", path, exc)
        try:
            os.remove(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# EPSS cache — structure: {"updated_at": "...", "data": {"CVE-...": 0.xx, ...}}
# ---------------------------------------------------------------------------

def _epss_cache_is_fresh(cache: dict, cve_id: str) -> bool:
    """True if *cve_id* exists in cache and cache is younger than TTL."""
    if not cache or "data" not in cache:
        return False
    if cve_id.upper() not in cache["data"]:
        return False
    return _hours_since(cache.get("updated_at", "")) < _EPSS_TTL_HOURS


def _fetch_epss_api(cve_ids: list[str]) -> dict[str, float]:
    """
    Call the FIRST EPSS API for one or more CVE IDs (comma-separated).
    Returns mapping {CVE-ID: epss_score}.  Never raises.
    """
    if not cve_ids:
        return {}

    scores: dict[str, float] = {}
    # Process in chunks to avoid excessively long query strings.
    for i in range(0, len(cve_ids), _EPSS_BATCH_CHUNK):
        chunk = cve_ids[i : i + _EPSS_BATCH_CHUNK]
        params = {"cve": ",".join(chunk)}
        try:
            resp = requests.get(_EPSS_API_URL, params=params, timeout=_REQUEST_TIMEOUT)
            resp.raise_for_status()
            payload = resp.json()
            for entry in payload.get("data", []):
                cve = entry.get("cve", "").upper()
                try:
                    scores[cve] = float(entry.get("epss", 0.0))
                except (TypeError, ValueError):
                    scores[cve] = 0.0
        except requests.RequestException as exc:
            logger.warning("epss_engine: EPSS API error for chunk %s: %s", chunk[:3], exc)
        except (ValueError, KeyError) as exc:
            logger.warning("epss_engine: EPSS API parse error: %s", exc)

    return scores


def get_epss_score(cve_id: str) -> float:
    """
    Return the EPSS probability score (0.0–1.0) for *cve_id*.
    Returns 0.0 on any network or parse error.
    """
    cve_id = cve_id.strip().upper()
    if not cve_id:
        return 0.0

    with _epss_lock:
        cache = _load_cache(_EPSS_CACHE_FILE)
        if _epss_cache_is_fresh(cache, cve_id):
            return float(cache["data"][cve_id])

        # Fetch from API
        scores = _fetch_epss_api([cve_id])

        # Merge into cache
        if "data" not in cache:
            cache["data"] = {}
        cache["data"].update(scores)

        # Only update timestamp if we actually got data back
        if scores:
            cache["updated_at"] = _now_iso()

        # Store 0.0 for unknowns so we don't hit the API repeatedly
        if cve_id not in cache["data"]:
            cache["data"][cve_id] = 0.0

        _save_cache(_EPSS_CACHE_FILE, cache)
        return float(cache["data"][cve_id])


def _get_epss_scores_batch(cve_ids: list[str]) -> dict[str, float]:
    """
    Retrieve EPSS scores for multiple CVEs, using the cache where possible
    and batching the remainder into a single API call.
    Returns {CVE-ID: score}.
    """
    results: dict[str, float] = {}
    missing: list[str] = []

    with _epss_lock:
        cache = _load_cache(_EPSS_CACHE_FILE)
        cache_data = cache.get("data", {})
        cache_age_ok = _hours_since(cache.get("updated_at", "")) < _EPSS_TTL_HOURS

        for cve in cve_ids:
            cve_upper = cve.strip().upper()
            if cache_age_ok and cve_upper in cache_data:
                results[cve_upper] = float(cache_data[cve_upper])
            else:
                missing.append(cve_upper)

        if missing:
            fetched = _fetch_epss_api(missing)
            if "data" not in cache:
                cache["data"] = {}
            cache["data"].update(fetched)
            if fetched:
                cache["updated_at"] = _now_iso()
            for cve in missing:
                score = fetched.get(cve, 0.0)
                cache["data"].setdefault(cve, score)
                results[cve] = float(cache["data"][cve])
            _save_cache(_EPSS_CACHE_FILE, cache)

    return results


# ---------------------------------------------------------------------------
# KEV cache — structure: {"updated_at": "...", "data": {"CVE-...": true, ...}}
# ---------------------------------------------------------------------------

def _kev_cache_is_fresh(cache: dict) -> bool:
    if not cache or "data" not in cache:
        return False
    return _hours_since(cache.get("updated_at", "")) < _KEV_TTL_HOURS


def _fetch_kev_json() -> dict[str, bool]:
    """
    Download the CISA KEV catalogue.
    Returns mapping {CVE-ID: True} for every entry.  Never raises.
    """
    try:
        resp = requests.get(_KEV_JSON_URL, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        entries: dict[str, bool] = {}
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cveID", "").strip().upper()
            if cve:
                entries[cve] = True
        return entries
    except requests.RequestException as exc:
        logger.warning("epss_engine: KEV download error: %s", exc)
    except (ValueError, KeyError) as exc:
        logger.warning("epss_engine: KEV parse error: %s", exc)
    return {}


def _get_kev_data() -> dict[str, bool]:
    """Return KEV dict from cache (refreshing if stale)."""
    with _kev_lock:
        cache = _load_cache(_KEV_CACHE_FILE)
        if _kev_cache_is_fresh(cache):
            return cache["data"]

        entries = _fetch_kev_json()
        if entries:
            cache = {"updated_at": _now_iso(), "data": entries}
            _save_cache(_KEV_CACHE_FILE, cache)
            return entries

        # Return whatever is in the stale cache rather than empty
        return cache.get("data", {})


def is_in_kev(cve_id: str) -> bool:
    """Return True if *cve_id* appears in the CISA Known Exploited Vulnerabilities catalogue."""
    cve_id = cve_id.strip().upper()
    if not cve_id:
        return False
    kev_data = _get_kev_data()
    return bool(kev_data.get(cve_id, False))


def refresh_kev_cache() -> int:
    """
    Force-refresh the KEV cache regardless of TTL.
    Returns the count of KEV entries after refresh (0 on error).
    """
    with _kev_lock:
        entries = _fetch_kev_json()
        if entries:
            cache = {"updated_at": _now_iso(), "data": entries}
            _save_cache(_KEV_CACHE_FILE, cache)
            return len(entries)
        # Keep existing data on failure
        existing = _load_cache(_KEV_CACHE_FILE)
        return len(existing.get("data", {}))


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------

def _compute_composite(cvss: float, epss: float, kev: bool) -> tuple[float, str]:
    """
    composite = 0.35*(cvss/10) + 0.45*epss + 0.20*(1.0 if kev else 0.0)

    Priority thresholds:
        CRITICAL >= 0.85
        HIGH     >= 0.65
        MEDIUM   >= 0.40
        LOW       < 0.40
    """
    kev_score = 1.0 if kev else 0.0
    cvss_norm = max(0.0, min(float(cvss), 10.0)) / 10.0
    epss_norm = max(0.0, min(float(epss), 1.0))

    composite = round(0.35 * cvss_norm + 0.45 * epss_norm + 0.20 * kev_score, 4)

    if composite >= 0.85:
        priority = "CRITICAL"
    elif composite >= 0.65:
        priority = "HIGH"
    elif composite >= 0.40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return composite, priority


def enrich_vulnerability(cve_id: str, cvss_score: float) -> dict:
    """
    Enrich a single CVE with EPSS + KEV data and compute a composite risk score.

    Returns::

        {
            "cve_id":          str,
            "cvss":            float,
            "epss":            float,
            "kev":             bool,
            "composite_score": float,
            "priority":        str   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        }
    """
    cve_id = cve_id.strip().upper()
    epss = get_epss_score(cve_id)
    kev = is_in_kev(cve_id)
    composite, priority = _compute_composite(cvss_score, epss, kev)

    return {
        "cve_id": cve_id,
        "cvss": float(cvss_score),
        "epss": epss,
        "kev": kev,
        "composite_score": composite,
        "priority": priority,
    }


def enrich_batch(cve_list: list[dict]) -> list[dict]:
    """
    Enrich a list of vulnerabilities in one optimised pass.

    Each item in *cve_list* must contain at least::

        {"cve_id": "CVE-XXXX-YYYY", "cvss": 7.5}

    Extra keys are preserved in the output.

    Returns a list of dicts with the same order as the input, each augmented
    with ``epss``, ``kev``, ``composite_score``, and ``priority`` fields.
    """
    if not cve_list:
        return []

    # Normalise input and de-duplicate CVE IDs for the batch EPSS call.
    normalised = [
        {**item, "_cve_upper": item.get("cve_id", "").strip().upper()}
        for item in cve_list
    ]
    unique_cves = list({item["_cve_upper"] for item in normalised if item["_cve_upper"]})

    # Batch-fetch EPSS scores (single API call for all missing CVEs).
    epss_map = _get_epss_scores_batch(unique_cves) if unique_cves else {}

    # Fetch KEV data once (already cached after first call).
    kev_data = _get_kev_data()

    results: list[dict] = []
    for item in normalised:
        cve_upper = item["_cve_upper"]
        cvss = float(item.get("cvss", 0.0))
        epss = epss_map.get(cve_upper, 0.0)
        kev = bool(kev_data.get(cve_upper, False))
        composite, priority = _compute_composite(cvss, epss, kev)

        out = {k: v for k, v in item.items() if k != "_cve_upper"}
        out.update(
            {
                "cve_id": cve_upper,
                "cvss": cvss,
                "epss": epss,
                "kev": kev,
                "composite_score": composite,
                "priority": priority,
            }
        )
        results.append(out)

    return results


# ---------------------------------------------------------------------------
# Module-level self-test (python epss_engine.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, stream=sys.stderr)

    test_cves = [
        {"cve_id": "CVE-2021-44228", "cvss": 10.0},  # Log4Shell
        {"cve_id": "CVE-2022-30190", "cvss": 7.8},   # Follina
        {"cve_id": "CVE-2023-23397", "cvss": 9.8},   # Outlook NTLM
        {"cve_id": "CVE-2024-99999", "cvss": 5.0},   # fictitious
    ]

    print("=== Batch enrichment ===")
    enriched = enrich_batch(test_cves)
    for row in enriched:
        print(
            f"{row['cve_id']:20s}  CVSS={row['cvss']:.1f}  "
            f"EPSS={row['epss']:.4f}  KEV={str(row['kev']):5s}  "
            f"composite={row['composite_score']:.4f}  priority={row['priority']}"
        )

    print("\n=== KEV refresh ===")
    count = refresh_kev_cache()
    print(f"KEV catalogue contains {count} entries.")
