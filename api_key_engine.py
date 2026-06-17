"""
api_key_engine.py — PenteIA V4.0
API key management for the public REST API.
Provides programmatic access to PenteIA without JWT tokens.

Key format: pk_live_<32 random hex chars>
Example:    pk_live_a3f8b2c9d1e4f7a0b3c6d9e2f5a8b1c4
"""

import secrets
import hashlib
import time
from threading import Lock

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------

_key_cache: dict[str, dict] = {}  # key_hash -> {user_id, name, enabled}
_cache_lock = Lock()

_rate_limits: dict[str, dict] = {}  # key_hash -> {count, reset_at}
_rl_lock = Lock()

# ---------------------------------------------------------------------------
# Key generation & hashing
# ---------------------------------------------------------------------------

def generate_api_key() -> str:
    """Generate a new API key with the pk_live_ prefix."""
    return "pk_live_" + secrets.token_hex(32)


def hash_key(key: str) -> str:
    """Return the SHA-256 hex digest of an API key (used for storage)."""
    return hashlib.sha256(key.encode()).hexdigest()

# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------

def add_key_to_cache(
    key_hash: str,
    user_id: str,
    name: str,
    enabled: bool = True,
) -> None:
    """Insert or update a key entry in the in-memory cache (thread-safe)."""
    with _cache_lock:
        _key_cache[key_hash] = {
            "user_id": user_id,
            "name": name,
            "enabled": enabled,
        }


def remove_key_from_cache(key_hash: str) -> None:
    """Remove a key entry from the in-memory cache (thread-safe)."""
    with _cache_lock:
        _key_cache.pop(key_hash, None)


def load_keys_from_db(db_session) -> int:
    """
    Load all enabled ApiKey rows from the database into _key_cache.
    Intended to be called once at application startup.

    Returns the number of keys loaded.
    """
    try:
        # Import here to avoid circular imports at module level.
        from models import ApiKey  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError(
            "Could not import ApiKey model from models.py. "
            "Make sure the model is defined before calling load_keys_from_db."
        ) from exc

    rows = db_session.query(ApiKey).filter(ApiKey.enabled == True).all()  # noqa: E712

    with _cache_lock:
        _key_cache.clear()
        for row in rows:
            _key_cache[row.key_hash] = {
                "user_id": str(row.user_id),
                "name": row.name,
                "enabled": True,
            }

    return len(rows)

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_api_key(key: str) -> dict | None:
    """
    Validate an API key.

    Returns a dict with ``user_id`` and ``name`` if the key is valid and
    enabled, or ``None`` if the key is invalid, unknown, or disabled.
    """
    if not isinstance(key, str) or not key.startswith("pk_live_"):
        return None

    key_hash = hash_key(key)

    with _cache_lock:
        entry = _key_cache.get(key_hash)

    if entry is None or not entry.get("enabled", False):
        return None

    return {
        "user_id": entry["user_id"],
        "name": entry["name"],
    }

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def check_rate_limit(
    key_hash: str,
    limit: int = 1000,
    window_seconds: int = 3600,
) -> bool:
    """
    Check whether a key has exceeded the allowed request count within the
    rolling time window.

    Returns ``True`` if the request is allowed, ``False`` if rate limited.
    The counter is automatically reset after ``window_seconds`` have elapsed.
    """
    now = time.monotonic()

    with _rl_lock:
        entry = _rate_limits.get(key_hash)

        if entry is None or now >= entry["reset_at"]:
            # First request in this window (or window has expired).
            _rate_limits[key_hash] = {
                "count": 1,
                "reset_at": now + window_seconds,
            }
            return True

        if entry["count"] >= limit:
            return False

        entry["count"] += 1
        return True

# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_api_user(api_key: str | None = Security(api_key_header)) -> dict | None:
    """
    FastAPI dependency that authenticates requests via the X-API-Key header.

    - If no key is present, returns ``None`` so the caller can fall back to
      JWT authentication.
    - If a key is present but invalid, raises HTTP 401.
    - If the key is valid but rate-limited, raises HTTP 429.
    - Otherwise returns ``{user_id, api_key_name}``.
    """
    if not api_key:
        return None

    user_info = validate_api_key(api_key)
    if user_info is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked API key.",
        )

    key_hash = hash_key(api_key)
    if not check_rate_limit(key_hash):
        raise HTTPException(
            status_code=429,
            detail="API key rate limit exceeded. Try again later.",
        )

    return {
        "user_id": user_info["user_id"],
        "api_key_name": user_info["name"],
    }

# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = [
    "generate_api_key",
    "hash_key",
    "validate_api_key",
    "add_key_to_cache",
    "remove_key_from_cache",
    "load_keys_from_db",
    "check_rate_limit",
    "get_api_user",
    "api_key_header",
]
