"""
integrations_engine.py — PenteIA V4.0
External integrations: Slack, Microsoft Teams, Jira Cloud, ServiceNow.
All HTTP errors are caught and returned gracefully.
"""

import base64
import json
import threading
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Thread-safe in-memory config store
# ---------------------------------------------------------------------------

_lock = threading.Lock()

_slack_config: dict[str, dict] = {}
_teams_config: dict[str, dict] = {}
_jira_clients: dict[str, "JiraClient"] = {}
_snow_clients: dict[str, "ServiceNowClient"] = {}


# ---------------------------------------------------------------------------
# Slack — incoming webhooks
# ---------------------------------------------------------------------------

def send_slack_alert(webhook_url: str, simulation_data: dict) -> bool:
    """
    Post a Block Kit message to a Slack incoming webhook.

    simulation_data keys used:
      score (int/float), target (str), critical_findings (list[str])
    Returns True on success, False on any error.
    """
    score = simulation_data.get("score", 0)
    target = simulation_data.get("target", "N/A")
    critical_findings = simulation_data.get("critical_findings", [])

    if score >= 75:
        header_emoji = ":red_circle:"
        severity_label = "CRITICAL"
    elif score >= 50:
        header_emoji = ":large_orange_circle:"
        severity_label = "HIGH"
    elif score >= 25:
        header_emoji = ":large_yellow_circle:"
        severity_label = "MEDIUM"
    else:
        header_emoji = ":large_green_circle:"
        severity_label = "LOW"

    findings_text = (
        "\n".join(f"• {f}" for f in critical_findings)
        if critical_findings
        else "_No critical findings reported._"
    )

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{header_emoji} PenteIA — {severity_label} Alert",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{target}"},
                    {"type": "mrkdwn", "text": f"*Simulation Score:*\n{score}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Critical Findings:*\n{findings_text}",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Sent by *PenteIA V4.0* red team platform",
                    }
                ],
            },
        ]
    }

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False


def test_slack_webhook(webhook_url: str) -> dict:
    """
    Send a minimal test message to verify the webhook URL.
    Returns {"status": "ok"/"error", "message": str}.
    """
    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ":white_check_mark: PenteIA V4.0 — Slack webhook test successful.",
                },
            }
        ]
    }
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        return {"status": "ok", "message": "Webhook test successful."}
    except requests.exceptions.HTTPError as exc:
        return {
            "status": "error",
            "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
        }
    except requests.RequestException as exc:
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Microsoft Teams — incoming webhooks
# ---------------------------------------------------------------------------

def _teams_theme_color(score) -> str:
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "0076D7"

    if score >= 75:
        return "FF0000"   # red
    elif score >= 50:
        return "FFA500"   # orange
    elif score >= 25:
        return "FFD700"   # yellow
    return "00B050"       # green


def send_teams_alert(webhook_url: str, simulation_data: dict) -> bool:
    """
    Post a MessageCard to a Microsoft Teams incoming webhook.
    themeColor is determined by simulation score.
    Returns True on success, False on any error.
    """
    score = simulation_data.get("score", 0)
    target = simulation_data.get("target", "N/A")
    critical_findings = simulation_data.get("critical_findings", [])

    findings_text = (
        "  \n".join(f"- {f}" for f in critical_findings)
        if critical_findings
        else "No critical findings reported."
    )

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": _teams_theme_color(score),
        "summary": "PenteIA Red Team Alert",
        "title": "PenteIA V4.0 — Red Team Simulation Alert",
        "sections": [
            {
                "facts": [
                    {"name": "Target", "value": str(target)},
                    {"name": "Simulation Score", "value": str(score)},
                ],
                "markdown": True,
            },
            {
                "title": "Critical Findings",
                "text": findings_text,
                "markdown": True,
            },
        ],
        "potentialAction": [],
    }

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False


def test_teams_webhook(webhook_url: str) -> dict:
    """
    Send a minimal test card to verify the Teams webhook URL.
    Returns {"status": "ok"/"error", "message": str}.
    """
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "0076D7",
        "summary": "PenteIA webhook test",
        "title": "PenteIA V4.0 — Teams webhook test successful",
        "text": "This is a connectivity test from PenteIA V4.0.",
    }
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        return {"status": "ok", "message": "Webhook test successful."}
    except requests.exceptions.HTTPError as exc:
        return {
            "status": "error",
            "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
        }
    except requests.RequestException as exc:
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Jira Cloud REST API v3
# ---------------------------------------------------------------------------

class JiraClient:
    """Client for Jira Cloud REST API v3 using Basic authentication."""

    _PRIORITY_MAP = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    def __init__(
        self,
        jira_url: str,
        email: str,
        api_token: str,
        project_key: str,
    ) -> None:
        self.jira_url = jira_url.rstrip("/")
        self.project_key = project_key

        raw = f"{email}:{api_token}"
        encoded = base64.b64encode(raw.encode()).decode()
        self._headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def test_connection(self) -> dict:
        """GET /rest/api/3/myself — verify credentials."""
        url = f"{self.jira_url}/rest/api/3/myself"
        try:
            response = requests.get(url, headers=self._headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return {
                "status": "ok",
                "display_name": data.get("displayName", ""),
                "email": data.get("emailAddress", ""),
            }
        except requests.exceptions.HTTPError as exc:
            return {
                "status": "error",
                "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
            }
        except requests.RequestException as exc:
            return {"status": "error", "message": str(exc)}

    def create_issue(
        self,
        title: str,
        description: str,
        severity: str,
        cvss: Optional[float] = None,
        technique_id: Optional[str] = None,
    ) -> dict:
        """
        POST /rest/api/3/issue

        issue_type: "Bug" for critical/high, "Task" for medium/low.
        priority: mapped from severity.
        Returns {"key": str, "url": str, "status": "created"} or {"status": "error", ...}.
        """
        severity_lower = (severity or "low").lower()
        issue_type = "Bug" if severity_lower in ("critical", "high") else "Task"
        priority_name = self._PRIORITY_MAP.get(severity_lower, "Low")

        # Build ADF (Atlassian Document Format) description
        content_nodes = [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": description}],
            }
        ]

        metadata_lines = []
        if cvss is not None:
            metadata_lines.append(f"CVSS Score: {cvss}")
        if technique_id:
            metadata_lines.append(f"MITRE Technique: {technique_id}")

        if metadata_lines:
            content_nodes.append(
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": line}
                        for line in metadata_lines
                    ],
                }
            )

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": title,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": content_nodes,
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": priority_name},
            }
        }

        url = f"{self.jira_url}/rest/api/3/issue"
        try:
            response = requests.post(
                url, headers=self._headers, json=payload, timeout=15
            )
            response.raise_for_status()
            data = response.json()
            issue_key = data.get("key", "")
            issue_url = f"{self.jira_url}/browse/{issue_key}"
            return {"key": issue_key, "url": issue_url, "status": "created"}
        except requests.exceptions.HTTPError as exc:
            return {
                "status": "error",
                "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
            }
        except requests.RequestException as exc:
            return {"status": "error", "message": str(exc)}

    def get_issue(self, issue_key: str) -> dict:
        """GET /rest/api/3/issue/{issueKey}"""
        url = f"{self.jira_url}/rest/api/3/issue/{issue_key}"
        try:
            response = requests.get(url, headers=self._headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            fields = data.get("fields", {})
            return {
                "key": data.get("key"),
                "summary": fields.get("summary"),
                "status": fields.get("status", {}).get("name"),
                "priority": fields.get("priority", {}).get("name"),
                "assignee": (
                    (fields.get("assignee") or {}).get("displayName")
                ),
                "url": f"{self.jira_url}/browse/{data.get('key', '')}",
            }
        except requests.exceptions.HTTPError as exc:
            return {
                "status": "error",
                "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
            }
        except requests.RequestException as exc:
            return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# ServiceNow
# ---------------------------------------------------------------------------

class ServiceNowClient:
    """Client for ServiceNow Table API (incident management)."""

    def __init__(self, instance_url: str, username: str, password: str) -> None:
        self.instance_url = instance_url.rstrip("/")
        self._auth = (username, password)
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def test_connection(self) -> dict:
        """
        Verify credentials by querying the incident table (limit 1).
        """
        url = f"{self.instance_url}/api/now/table/incident"
        params = {"sysparm_limit": 1, "sysparm_fields": "sys_id"}
        try:
            response = requests.get(
                url,
                auth=self._auth,
                headers=self._headers,
                params=params,
                timeout=10,
            )
            response.raise_for_status()
            return {"status": "ok", "message": "Connection successful."}
        except requests.exceptions.HTTPError as exc:
            return {
                "status": "error",
                "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
            }
        except requests.RequestException as exc:
            return {"status": "error", "message": str(exc)}

    def create_incident(
        self,
        title: str,
        description: str,
        urgency: int = 2,
        impact: int = 2,
    ) -> dict:
        """
        POST {instance_url}/api/now/table/incident

        urgency / impact: 1=High, 2=Medium, 3=Low (ServiceNow convention).
        Returns {"sys_id": str, "number": str, "url": str} or {"status": "error", ...}.
        """
        payload = {
            "short_description": title,
            "description": description,
            "urgency": str(urgency),
            "impact": str(impact),
        }
        url = f"{self.instance_url}/api/now/table/incident"
        try:
            response = requests.post(
                url,
                auth=self._auth,
                headers=self._headers,
                json=payload,
                timeout=15,
            )
            response.raise_for_status()
            result = response.json().get("result", {})
            sys_id = result.get("sys_id", "")
            number = result.get("number", "")
            incident_url = (
                f"{self.instance_url}/nav_to.do?uri=incident.do?sys_id={sys_id}"
            )
            return {"sys_id": sys_id, "number": number, "url": incident_url}
        except requests.exceptions.HTTPError as exc:
            return {
                "status": "error",
                "message": f"HTTP {exc.response.status_code}: {exc.response.text}",
            }
        except requests.RequestException as exc:
            return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Thread-safe config store helpers
# ---------------------------------------------------------------------------

# --- Slack ---

def save_slack_config(user_id: str, config: dict) -> None:
    """Persist Slack webhook config for a user (in-memory)."""
    with _lock:
        _slack_config[user_id] = config


def get_slack_config(user_id: str) -> Optional[dict]:
    """Retrieve Slack config for a user, or None if not set."""
    with _lock:
        return _slack_config.get(user_id)


# --- Teams ---

def save_teams_config(user_id: str, config: dict) -> None:
    """Persist Teams webhook config for a user (in-memory)."""
    with _lock:
        _teams_config[user_id] = config


def get_teams_config(user_id: str) -> Optional[dict]:
    """Retrieve Teams config for a user, or None if not set."""
    with _lock:
        return _teams_config.get(user_id)


# --- Jira ---

def save_jira_config(
    user_id: str,
    jira_url: str,
    email: str,
    api_token: str,
    project_key: str,
) -> "JiraClient":
    """
    Instantiate a JiraClient, cache it for user_id, and return it.
    """
    client = JiraClient(jira_url, email, api_token, project_key)
    with _lock:
        _jira_clients[user_id] = client
    return client


def get_jira_client(user_id: str) -> Optional["JiraClient"]:
    """Return the cached JiraClient for user_id, or None."""
    with _lock:
        return _jira_clients.get(user_id)


# --- ServiceNow ---

def save_snow_config(
    user_id: str,
    instance_url: str,
    username: str,
    password: str,
) -> "ServiceNowClient":
    """
    Instantiate a ServiceNowClient, cache it for user_id, and return it.
    """
    client = ServiceNowClient(instance_url, username, password)
    with _lock:
        _snow_clients[user_id] = client
    return client


def get_snow_client(user_id: str) -> Optional["ServiceNowClient"]:
    """Return the cached ServiceNowClient for user_id, or None."""
    with _lock:
        return _snow_clients.get(user_id)
