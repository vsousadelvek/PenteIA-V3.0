"""
Auto-Mitigation Engine for PenteIA V4.0

Given a MITRE ATT&CK technique ID discovered by BAS (Breach and Attack Simulation),
push blocking rules to configured security controls (WAF, Firewall, etc.).
"""

import hashlib
import hmac
import json
import logging
import time
from typing import Any
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mitigation Rules Map
# ---------------------------------------------------------------------------

TECHNIQUE_MITIGATIONS: dict[str, dict[str, Any]] = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "waf_rule": "block_sqli_xss_rfi",
        "firewall_rule": {
            "type": "block_port",
            "description": "Block suspicious web traffic patterns",
        },
    },
    "T1566": {
        "name": "Phishing",
        "waf_rule": "block_malicious_email_patterns",
        "firewall_rule": {
            "type": "dns_block",
            "description": "Block known phishing domains",
        },
    },
    "T1078": {
        "name": "Valid Accounts",
        "action": "force_mfa",
        "description": "Enable MFA enforcement",
    },
    "T1110": {
        "name": "Brute Force",
        "waf_rule": "rate_limit_auth",
        "firewall_rule": {
            "type": "rate_limit",
            "description": "Rate limit authentication endpoints",
        },
    },
    "T1046": {
        "name": "Network Scan",
        "firewall_rule": {
            "type": "block_scanner_ips",
            "description": "Block port scanner signatures",
        },
    },
    "T1021": {
        "name": "Remote Services",
        "firewall_rule": {
            "type": "restrict_rdp_ssh",
            "description": "Restrict RDP/SSH to known IPs",
        },
    },
    "T1486": {
        "name": "Data Encrypted (Ransomware)",
        "action": "isolate_host",
        "description": "Isolate affected host immediately",
    },
    "T1071": {
        "name": "C2 over HTTP/HTTPS",
        "waf_rule": "block_c2_patterns",
        "description": "Block known C2 callback patterns",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "waf_rule": "block_command_injection",
        "firewall_rule": {
            "type": "egress_filter",
            "description": "Block outbound shells and interpreter callbacks",
        },
    },
    "T1055": {
        "name": "Process Injection",
        "action": "enable_edr_alert",
        "description": "Trigger EDR high-sensitivity mode for process injection",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "action": "enable_lsass_protection",
        "description": "Enable LSASS protection and alert on credential access",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "action": "monitor_autorun_keys",
        "description": "Monitor and alert on autorun registry/startup changes",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "action": "restrict_task_creation",
        "description": "Restrict scheduled task creation to administrators",
    },
    "T1082": {
        "name": "System Information Discovery",
        "firewall_rule": {
            "type": "rate_limit",
            "description": "Rate limit responses that expose system info",
        },
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "waf_rule": "block_directory_traversal",
        "firewall_rule": {
            "type": "path_traversal_block",
            "description": "Block directory traversal patterns",
        },
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "waf_rule": "block_tool_download_patterns",
        "firewall_rule": {
            "type": "egress_filter",
            "description": "Block download of known offensive tooling",
        },
    },
    "T1136": {
        "name": "Create Account",
        "action": "alert_account_creation",
        "description": "Alert and require approval for new account creation",
    },
    "T1562": {
        "name": "Impair Defenses",
        "action": "lock_security_config",
        "description": "Lock security tool configuration and alert on tampering",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "action": "monitor_service_creation",
        "description": "Alert on new service/daemon creation",
    },
    "T1204": {
        "name": "User Execution",
        "waf_rule": "block_malicious_file_delivery",
        "firewall_rule": {
            "type": "dns_block",
            "description": "Block delivery domains for malicious payloads",
        },
    },
    "T1036": {
        "name": "Masquerading",
        "action": "enable_binary_validation",
        "description": "Enforce binary signing and path validation",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "waf_rule": "decode_and_inspect_payload",
        "description": "Deep-inspect obfuscated payloads at WAF layer",
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "waf_rule": "block_encoded_execution",
        "description": "Block base64/hex-encoded command execution patterns",
    },
}


# ---------------------------------------------------------------------------
# WAF / Firewall Connectors
# ---------------------------------------------------------------------------


def push_via_webhook(
    webhook_url: str,
    secret: str,
    technique_id: str,
    mitigation: dict,
) -> dict:
    """POST a signed HMAC-SHA256 payload to a generic webhook endpoint."""
    payload = {
        "technique_id": technique_id,
        "mitigation": mitigation,
        "timestamp": int(time.time()),
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-PenteIA-Signature": f"sha256={signature}",
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.post(webhook_url, content=body, headers=headers)
        response.raise_for_status()
        return {
            "status": "ok",
            "message": f"Webhook accepted rule for {technique_id}",
        }
    except httpx.HTTPStatusError as exc:
        logger.error("Webhook HTTP error: %s", exc)
        return {"status": "error", "message": str(exc)}
    except httpx.RequestError as exc:
        logger.error("Webhook connection error: %s", exc)
        return {"status": "error", "message": f"Connection error: {exc}"}


def push_aws_waf(
    region: str,
    web_acl_id: str,
    technique_id: str,
) -> dict:
    """Create an AWS WAF rule for the given technique using boto3."""
    try:
        import boto3  # type: ignore[import]
    except ImportError:
        return {
            "status": "error",
            "message": "boto3 is not installed. Install it with: pip install boto3",
        }

    mitigation = TECHNIQUE_MITIGATIONS.get(technique_id)
    if not mitigation:
        return {
            "status": "error",
            "message": f"No mitigation defined for technique {technique_id}",
        }

    rule_name = f"PenteIA-{technique_id.replace('.', '-')}-{int(time.time())}"
    waf_rule = mitigation.get("waf_rule", "block_generic_threat")

    try:
        client = boto3.client("wafv2", region_name=region)

        response = client.update_web_acl(
            Name=web_acl_id,
            Scope="REGIONAL",
            Id=web_acl_id,
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": rule_name,
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": technique_id.encode(),
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [
                                {"Priority": 0, "Type": "NONE"}
                            ],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": rule_name,
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": web_acl_id,
            },
            LockToken=_get_aws_waf_lock_token(client, web_acl_id, region),
        )
        return {
            "status": "ok",
            "rule_id": rule_name,
            "response": response.get("NextLockToken", ""),
        }
    except Exception as exc:  # broad catch — AWS SDK raises many exception types
        logger.error("AWS WAF error: %s", exc)
        return {"status": "error", "message": str(exc)}


def _get_aws_waf_lock_token(client: Any, web_acl_id: str, region: str) -> str:
    """Retrieve the lock token required for AWS WAF update operations."""
    try:
        response = client.get_web_acl(
            Name=web_acl_id,
            Scope="REGIONAL",
            Id=web_acl_id,
        )
        return response.get("LockToken", "")
    except Exception as exc:
        logger.warning("Could not retrieve AWS WAF lock token: %s", exc)
        return ""


def push_cloudflare_waf(
    zone_id: str,
    api_token: str,
    technique_id: str,
) -> dict:
    """Create a Cloudflare firewall rule for the given technique."""
    mitigation = TECHNIQUE_MITIGATIONS.get(technique_id)
    if not mitigation:
        return {
            "status": "error",
            "message": f"No mitigation defined for technique {technique_id}",
        }

    waf_rule = mitigation.get("waf_rule", "block_generic_threat")
    rule_description = (
        f"PenteIA auto-block: {mitigation['name']} ({technique_id})"
    )

    # Cloudflare Firewall Rules use Wireshark-like filter expressions
    filter_expression = _build_cloudflare_filter(technique_id, waf_rule)

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    payload = [
        {
            "filter": {"expression": filter_expression},
            "action": "block",
            "description": rule_description,
        }
    ]

    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.post(url, json=payload, headers=headers)
        data = response.json()
        if data.get("success"):
            rule_id = data["result"][0]["id"] if data.get("result") else "unknown"
            return {"status": "ok", "rule_id": rule_id}
        errors = data.get("errors", [])
        return {"status": "error", "message": str(errors)}
    except httpx.RequestError as exc:
        logger.error("Cloudflare WAF connection error: %s", exc)
        return {"status": "error", "message": f"Connection error: {exc}"}


def _build_cloudflare_filter(technique_id: str, waf_rule: str) -> str:
    """Build a Cloudflare filter expression based on the WAF rule type."""
    filters: dict[str, str] = {
        "block_sqli_xss_rfi": (
            '(http.request.uri.query contains "UNION SELECT") or '
            '(http.request.uri.query contains "<script") or '
            '(http.request.uri.path contains "../")'
        ),
        "block_malicious_email_patterns": (
            '(http.user_agent contains "phish") or '
            '(http.host contains "phishing")'
        ),
        "rate_limit_auth": '(http.request.uri.path contains "/login")',
        "block_c2_patterns": (
            '(http.request.uri.path contains "/beacon") or '
            '(http.user_agent contains "CobaltStrike")'
        ),
        "block_command_injection": (
            '(http.request.uri.query contains ";") or '
            '(http.request.uri.query contains "|") or '
            '(http.request.uri.query contains "`")'
        ),
        "block_directory_traversal": (
            '(http.request.uri.path contains "../") or '
            '(http.request.uri.path contains "%2e%2e")'
        ),
        "block_tool_download_patterns": (
            '(http.request.uri.path contains ".exe") or '
            '(http.request.uri.path contains "/tools/") or '
            '(http.request.uri.path contains "mimikatz")'
        ),
        "block_malicious_file_delivery": (
            '(http.request.uri.path contains ".hta") or '
            '(http.request.uri.path contains ".vbs") or '
            '(http.request.uri.path contains ".ps1")'
        ),
        "decode_and_inspect_payload": (
            '(http.request.uri.query contains "eval(") or '
            '(http.request.uri.query contains "base64")'
        ),
        "block_encoded_execution": (
            '(http.request.uri.query contains "powershell -enc") or '
            '(http.request.uri.query contains "cmd /c")'
        ),
        "block_malicious_email_patterns": '(http.host contains "suspicious")',
    }
    return filters.get(
        waf_rule,
        f'(http.request.uri contains "{technique_id}")',
    )


def push_pfsense_rule(
    pfsense_url: str,
    api_key: str,
    technique_id: str,
) -> dict:
    """Push a firewall rule to pfSense via the pfSense-API package REST endpoint."""
    mitigation = TECHNIQUE_MITIGATIONS.get(technique_id)
    if not mitigation:
        return {
            "status": "error",
            "message": f"No mitigation defined for technique {technique_id}",
        }

    firewall_rule = mitigation.get("firewall_rule", {})
    rule_type = firewall_rule.get("type", "block_generic")
    description = firewall_rule.get(
        "description", f"PenteIA auto-block for {technique_id}"
    )

    rule_payload = _build_pfsense_rule_payload(technique_id, rule_type, description)

    url = f"{pfsense_url.rstrip('/')}/api/v1/firewall/rule"
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=15.0, verify=False) as client:  # pfSense often uses self-signed certs
            response = client.post(url, json=rule_payload, headers=headers)
        data = response.json()
        if response.status_code in (200, 201) and data.get("status") == "ok":
            return {"status": "ok"}
        return {
            "status": "error",
            "message": data.get("message", f"HTTP {response.status_code}"),
        }
    except httpx.RequestError as exc:
        logger.error("pfSense connection error: %s", exc)
        return {"status": "error", "message": f"Connection error: {exc}"}


def _build_pfsense_rule_payload(
    technique_id: str,
    rule_type: str,
    description: str,
) -> dict:
    """Build a pfSense firewall rule payload based on the rule type."""
    base = {
        "type": "block",
        "interface": "wan",
        "ipprotocol": "inet",
        "protocol": "any",
        "src": "any",
        "dst": "any",
        "descr": f"[PenteIA][{technique_id}] {description}",
        "top": True,
    }

    overrides: dict[str, dict] = {
        "block_port": {
            "protocol": "tcp",
            "dst": "any",
            "dstport": "80-443",
        },
        "dns_block": {
            "protocol": "udp",
            "dst": "any",
            "dstport": "53",
        },
        "rate_limit": {
            "type": "block",
            "protocol": "tcp",
            "dstport": "80-443",
        },
        "restrict_rdp_ssh": {
            "protocol": "tcp",
            "dstport": "22-23,3389",
        },
        "block_scanner_ips": {
            "protocol": "tcp",
            "src": "any",
            "gateway": "default",
        },
        "egress_filter": {
            "interface": "lan",
            "type": "block",
            "src": "any",
            "dst": "any",
        },
        "path_traversal_block": {
            "protocol": "tcp",
            "dstport": "80-443",
        },
    }

    base.update(overrides.get(rule_type, {}))
    return base


# ---------------------------------------------------------------------------
# Config Store
# ---------------------------------------------------------------------------

_CONFIG_STORE_PATH = Path(__file__).parent / ".penteia_waf_configs.json"


def _load_config_store() -> dict:
    if _CONFIG_STORE_PATH.exists():
        try:
            return json.loads(_CONFIG_STORE_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load WAF config store: %s", exc)
    return {}


def _save_config_store(store: dict) -> None:
    try:
        _CONFIG_STORE_PATH.write_text(
            json.dumps(store, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        logger.error("Could not save WAF config store: %s", exc)


def save_waf_config(user_id: str, waf_type: str, config: dict) -> None:
    """Persist WAF connector configuration for a given user."""
    store = _load_config_store()
    store[user_id] = {"waf_type": waf_type, "config": config}
    _save_config_store(store)


def get_waf_config(user_id: str) -> dict | None:
    """Retrieve stored WAF connector configuration for a given user."""
    store = _load_config_store()
    return store.get(user_id)


# ---------------------------------------------------------------------------
# Main Interface
# ---------------------------------------------------------------------------


def get_mitigation_for_technique(technique_id: str) -> dict | None:
    """Return the mitigation definition for a technique ID, or None if unknown."""
    return TECHNIQUE_MITIGATIONS.get(technique_id)


def list_supported_techniques() -> list[str]:
    """Return all technique IDs that have mitigations defined."""
    return list(TECHNIQUE_MITIGATIONS.keys())


def push_mitigation(
    technique_id: str,
    waf_type: str,
    config: dict,
) -> dict:
    """
    Look up the mitigation for technique_id and push a blocking rule to the
    specified WAF/firewall connector.

    Parameters
    ----------
    technique_id : str
        MITRE ATT&CK technique ID (e.g. "T1190").
    waf_type : str
        One of: "webhook", "aws_waf", "cloudflare", "pfsense".
    config : dict
        Connector-specific configuration keys (see individual push_* functions).

    Returns
    -------
    dict
        {success, action_taken, waf_type, technique_id, message}
    """
    mitigation = TECHNIQUE_MITIGATIONS.get(technique_id)
    if mitigation is None:
        return {
            "success": False,
            "action_taken": "none",
            "waf_type": waf_type,
            "technique_id": technique_id,
            "message": (
                f"Technique {technique_id} is not in the mitigation map. "
                f"Supported techniques: {list_supported_techniques()}"
            ),
        }

    action_taken = _describe_action(mitigation)

    connector_result: dict
    waf_type_normalized = waf_type.lower().strip()

    if waf_type_normalized == "webhook":
        webhook_url = config.get("webhook_url", "")
        secret = config.get("secret", "")
        if not webhook_url:
            return _error_result(technique_id, waf_type, "webhook_url is required in config")
        connector_result = push_via_webhook(webhook_url, secret, technique_id, mitigation)

    elif waf_type_normalized == "aws_waf":
        region = config.get("region", "us-east-1")
        web_acl_id = config.get("web_acl_id", "")
        if not web_acl_id:
            return _error_result(technique_id, waf_type, "web_acl_id is required in config")
        connector_result = push_aws_waf(region, web_acl_id, technique_id)

    elif waf_type_normalized == "cloudflare":
        zone_id = config.get("zone_id", "")
        api_token = config.get("api_token", "")
        if not zone_id or not api_token:
            return _error_result(
                technique_id, waf_type, "zone_id and api_token are required in config"
            )
        connector_result = push_cloudflare_waf(zone_id, api_token, technique_id)

    elif waf_type_normalized == "pfsense":
        pfsense_url = config.get("pfsense_url", "")
        api_key = config.get("api_key", "")
        if not pfsense_url or not api_key:
            return _error_result(
                technique_id, waf_type, "pfsense_url and api_key are required in config"
            )
        connector_result = push_pfsense_rule(pfsense_url, api_key, technique_id)

    else:
        return _error_result(
            technique_id,
            waf_type,
            f"Unknown waf_type '{waf_type}'. Supported: webhook, aws_waf, cloudflare, pfsense",
        )

    success = connector_result.get("status") == "ok"
    message = connector_result.get(
        "message",
        f"Rule pushed successfully via {waf_type}" if success else "Push failed",
    )

    return {
        "success": success,
        "action_taken": action_taken,
        "waf_type": waf_type,
        "technique_id": technique_id,
        "message": message,
        "connector_detail": connector_result,
    }


def _describe_action(mitigation: dict) -> str:
    """Derive a human-readable action description from a mitigation definition."""
    parts: list[str] = []
    if "waf_rule" in mitigation:
        parts.append(f"waf_rule:{mitigation['waf_rule']}")
    if "firewall_rule" in mitigation:
        parts.append(f"firewall:{mitigation['firewall_rule'].get('type', 'block')}")
    if "action" in mitigation:
        parts.append(f"action:{mitigation['action']}")
    return ", ".join(parts) if parts else "block"


def _error_result(technique_id: str, waf_type: str, message: str) -> dict:
    return {
        "success": False,
        "action_taken": "none",
        "waf_type": waf_type,
        "technique_id": technique_id,
        "message": message,
    }
