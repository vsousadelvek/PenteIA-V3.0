"""
sso_engine.py — PenteIA V4.0
SSO via OAuth2/OIDC: Authorization Code flow with PKCE.
Supports Azure AD, Google Workspace, Okta, and generic OIDC.
No external OIDC library — implemented with requests + secrets + hashlib.
"""

import secrets
import hashlib
import base64
import logging
from typing import Optional
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider templates
# ---------------------------------------------------------------------------

PROVIDERS: dict = {
    "azure": {
        "name": "Microsoft Azure AD",
        "auth_url": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
        "scopes": "openid email profile",
    },
    "google": {
        "name": "Google Workspace",
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scopes": "openid email profile",
    },
    "okta": {
        "name": "Okta",
        "auth_url": "https://{domain}/oauth2/default/v1/authorize",
        "token_url": "https://{domain}/oauth2/default/v1/token",
        "userinfo_url": "https://{domain}/oauth2/default/v1/userinfo",
        "scopes": "openid email profile",
    },
    "generic": {
        "name": "Generic OIDC",
        "auth_url": "{issuer}/authorize",
        "token_url": "{issuer}/token",
        "userinfo_url": "{issuer}/userinfo",
        "scopes": "openid email profile",
    },
}

# ---------------------------------------------------------------------------
# In-memory state stores
# ---------------------------------------------------------------------------

# Global SSO configuration (one config at a time; multi-org can extend later)
_sso_config: dict = {}

# Ephemeral PKCE state: state_token → {provider, code_verifier, redirect_uri}
_sso_states: dict = {}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_urls(template: dict, extra: dict) -> dict:
    """Replace {placeholder} values in URL templates using extra dict."""
    resolved = {}
    for key, value in template.items():
        if isinstance(value, str) and extra:
            for placeholder, replacement in extra.items():
                value = value.replace(f"{{{placeholder}}}", str(replacement))
        resolved[key] = value
    return resolved


def _generate_pkce_pair() -> tuple[str, str]:
    """
    Generate a PKCE code_verifier and code_challenge (S256 method).

    Returns:
        (code_verifier, code_challenge)
    """
    # RFC 7636: verifier is 43-128 unreserved chars; 64 random bytes → 86-char base64url
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_sso_config(
    provider: str,
    client_id: str,
    client_secret: str,
    extra: Optional[dict] = None,
) -> None:
    """
    Persist SSO configuration in memory.

    Merges the provider template with client credentials and resolves any
    URL placeholders (e.g. {tenant_id}, {domain}, {issuer}) using `extra`.

    Args:
        provider:      One of the keys in PROVIDERS ("azure", "google", "okta", "generic").
        client_id:     OAuth2 client_id issued by the IdP.
        client_secret: OAuth2 client_secret issued by the IdP.
        extra:         Dict of placeholder values to fill in URL templates
                       (e.g. {"tenant_id": "my-tenant"} for Azure).
    """
    global _sso_config

    if provider not in PROVIDERS:
        raise ValueError(f"Unknown SSO provider '{provider}'. Valid: {list(PROVIDERS)}")

    template = PROVIDERS[provider].copy()
    resolved = _resolve_urls(template, extra or {})

    _sso_config = {
        **resolved,
        "provider": provider,
        "client_id": client_id,
        "client_secret": client_secret,
        "extra": extra or {},
    }
    logger.info("SSO config saved for provider '%s'.", provider)


def get_sso_config() -> Optional[dict]:
    """
    Return the current SSO configuration dict, or None if not configured.
    The client_secret is intentionally included (needed for token exchange).
    """
    return _sso_config if _sso_config else None


def get_authorization_url(
    provider: str,
    redirect_uri: str,
    state: Optional[str] = None,
) -> dict:
    """
    Build the IdP authorization URL with PKCE parameters.

    If `state` is not provided a cryptographically random value is generated.
    The PKCE pair and metadata are stored in _sso_states keyed by state.

    Args:
        provider:     Provider key (must match current _sso_config["provider"]).
        redirect_uri: Callback URL registered with the IdP.
        state:        Optional opaque value for CSRF protection.

    Returns:
        {"url": str, "state": str}
    """
    cfg = get_sso_config()
    if not cfg:
        raise RuntimeError("SSO is not configured. Call save_sso_config() first.")
    if cfg.get("provider") != provider:
        raise ValueError(
            f"Requested provider '{provider}' does not match configured provider '{cfg.get('provider')}'."
        )

    if state is None:
        state = secrets.token_urlsafe(32)

    code_verifier, code_challenge = _generate_pkce_pair()

    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "scope": cfg["scopes"],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    auth_url = cfg["auth_url"] + "?" + urlencode(params)

    _sso_states[state] = {
        "provider": provider,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
    }

    logger.debug("Authorization URL generated for provider '%s', state='%s'.", provider, state)
    return {"url": auth_url, "state": state}


def exchange_code_for_token(code: str, state: str) -> dict:
    """
    Exchange an authorization code for tokens using the stored PKCE verifier.

    Args:
        code:  Authorization code returned by the IdP callback.
        state: State value returned by the IdP (must match a stored entry).

    Returns:
        Token response dict (access_token, id_token, token_type, expires_in, …).

    Raises:
        ValueError:   If state is unknown or expired.
        RuntimeError: If the token endpoint returns an error.
    """
    if state not in _sso_states:
        raise ValueError(f"Unknown or expired SSO state: '{state}'.")

    state_data = _sso_states.pop(state)  # consume — one-time use
    cfg = get_sso_config()
    if not cfg:
        raise RuntimeError("SSO is not configured.")

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": state_data["redirect_uri"],
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "code_verifier": state_data["code_verifier"],
    }

    try:
        response = requests.post(
            cfg["token_url"],
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.error("Token exchange failed: %s", exc)
        raise RuntimeError(f"Token exchange failed: {exc}") from exc

    token_data = response.json()
    if "error" in token_data:
        raise RuntimeError(
            f"IdP token error: {token_data.get('error')} — {token_data.get('error_description', '')}"
        )

    return token_data


def get_userinfo(access_token: str, provider: str) -> dict:
    """
    Fetch user information from the IdP userinfo endpoint.

    Args:
        access_token: Bearer token obtained from token exchange.
        provider:     Provider key (used to look up userinfo_url from config).

    Returns:
        Normalized dict with keys: email, name, sub.
        Additional IdP-specific fields may also be present.

    Raises:
        RuntimeError: On HTTP or parsing errors.
    """
    cfg = get_sso_config()
    if not cfg:
        raise RuntimeError("SSO is not configured.")

    userinfo_url = cfg.get("userinfo_url", "")
    if not userinfo_url:
        raise RuntimeError(f"No userinfo_url configured for provider '{provider}'.")

    try:
        response = requests.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.error("Userinfo request failed: %s", exc)
        raise RuntimeError(f"Userinfo request failed: {exc}") from exc

    raw = response.json()

    # Normalize across providers — each IdP uses slightly different field names
    normalized = {
        "email": raw.get("email") or raw.get("upn") or raw.get("preferred_username", ""),
        "name": (
            raw.get("name")
            or raw.get("displayName")
            or raw.get("given_name", "")
        ),
        "sub": raw.get("sub") or raw.get("oid") or raw.get("id", ""),
    }
    # Carry through any extra fields the caller may find useful
    normalized.update({k: v for k, v in raw.items() if k not in normalized})
    return normalized


def get_or_create_sso_user(userinfo: dict, db) -> "object":
    """
    Return an existing User or create a new one for an SSO-authenticated identity.

    The user is looked up by email address.  If not found, a new record is
    created with a random unusable local password so the account cannot be
    used for password-based login.

    Args:
        userinfo: Normalized dict from get_userinfo() — must contain 'email'.
        db:       SQLAlchemy Session.

    Returns:
        User ORM instance.

    Raises:
        ValueError: If email is missing from userinfo.
    """
    # Deferred import to avoid circular dependency with models / auth
    from models import User  # noqa: PLC0415
    from auth import hash_password  # noqa: PLC0415

    email = (userinfo.get("email") or "").strip().lower()
    if not email:
        raise ValueError("SSO userinfo does not contain a valid email address.")

    existing_user: Optional[User] = db.query(User).filter(User.email == email).first()
    if existing_user:
        logger.debug("SSO login — existing user found: %s", email)
        return existing_user

    # Derive a username from the local part of the email; ensure uniqueness
    base_username = email.split("@")[0]
    username = base_username
    suffix = 1
    while db.query(User).filter(User.username == username).first() is not None:
        username = f"{base_username}{suffix}"
        suffix += 1

    # Random non-guessable password hash so the account is SSO-only
    random_pw = "sso_" + secrets.token_hex(16)
    new_user = User(
        email=email,
        username=username,
        role="user",
        password_hash=hash_password(random_pw),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info("SSO login — new user created: %s (username=%s).", email, username)
    return new_user


def list_providers() -> list:
    """
    Return a list of available SSO provider descriptors.

    Returns:
        List of {"id": str, "name": str} dicts.
    """
    return [{"id": pid, "name": pdata["name"]} for pid, pdata in PROVIDERS.items()]
