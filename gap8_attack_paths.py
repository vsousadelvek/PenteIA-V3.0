"""
gap8_attack_paths.py — PenteIA V4.0
Converts AD assessment results into React Flow graph format (nodes + edges).
Used by the /api/ad/attack-paths endpoint.
"""
from __future__ import annotations
from typing import Any

# Node type colors (matches React Flow node styling)
_NODE_STYLES = {
    "dc":         {"background": "#1e3a5f", "border": "#3b82f6", "color": "#93c5fd"},
    "spn":        {"background": "#3b1f2b", "border": "#f43f5e", "color": "#fda4af"},
    "asrep":      {"background": "#2d1f0f", "border": "#f97316", "color": "#fdba74"},
    "delegation": {"background": "#1f2d0f", "border": "#84cc16", "color": "#bef264"},
    "user":       {"background": "#1f1f2d", "border": "#8b5cf6", "color": "#c4b5fd"},
    "attacker":   {"background": "#0f1f0f", "border": "#22c55e", "color": "#86efac"},
}

def _node(id: str, label: str, node_type: str, data: dict | None = None, x: float = 0, y: float = 0) -> dict:
    style = _NODE_STYLES.get(node_type, _NODE_STYLES["user"])
    return {
        "id": id,
        "data": {"label": label, **(data or {})},
        "position": {"x": x, "y": y},
        "style": {**style, "borderWidth": 2, "borderRadius": 8, "padding": "8px 12px", "fontSize": "12px"},
        "type": "default",
    }

def _edge(source: str, target: str, label: str, color: str = "#64748b", animated: bool = False) -> dict:
    return {
        "id": f"{source}->{target}",
        "source": source,
        "target": target,
        "label": label,
        "animated": animated,
        "style": {"stroke": color, "strokeWidth": 2},
        "labelStyle": {"fontSize": "10px", "fill": "#94a3b8"},
    }


def build_attack_graph(assessment: dict) -> dict:
    """
    Transform the output of ad_attack_engine.run_ad_assessment() into
    React Flow nodes and edges.

    assessment dict keys (from run_ad_assessment):
      - dc_host: str
      - spns: list[dict]  (each: {account, spn, privileged})
      - asrep_users: list[dict]  (each: {account, dn})
      - domain_users: list[dict]  (each: {account, enabled})
      - unconstrained_delegation: list[dict]  (each: {name, dn})
      - risk_score: int
      - critical_findings: list[str]
    """
    nodes = []
    edges = []

    # Attacker node (origin)
    nodes.append(_node("attacker", "Atacante", "attacker", x=0, y=300))

    # Domain Controller node
    dc_host = assessment.get("dc_host", "DC")
    nodes.append(_node("dc", f"DC: {dc_host}", "dc", x=400, y=300))
    edges.append(_edge("attacker", "dc", "Reconhecimento LDAP", color="#3b82f6"))

    y_offset = 0

    # SPN nodes (Kerberoasting path)
    spns = assessment.get("spns", [])[:6]  # max 6 to keep graph readable
    for i, spn in enumerate(spns):
        acct = spn.get("account", f"SPN-{i}")
        is_priv = spn.get("privileged", False)
        nid = f"spn_{i}"
        label = f"{'⚡ ' if is_priv else ''}SPN: {acct}"
        nodes.append(_node(nid, label, "spn", x=800, y=y_offset + i * 100))
        edges.append(_edge("dc", nid, "T1558.003 Kerberoasting", color="#f43f5e", animated=is_priv))
        if is_priv:
            edges.append(_edge(nid, "dc", "→ Domain Admin", color="#f43f5e", animated=True))
        y_offset += 0

    # AS-REP nodes
    asrep = assessment.get("asrep_users", [])[:4]
    for i, user in enumerate(asrep):
        acct = user.get("account", f"ASREP-{i}")
        nid = f"asrep_{i}"
        nodes.append(_node(nid, f"AS-REP: {acct}", "asrep", x=800, y=len(spns)*100 + i * 100))
        edges.append(_edge("dc", nid, "T1558.004 AS-REP Roasting", color="#f97316", animated=True))

    # Unconstrained delegation nodes
    deleg = assessment.get("unconstrained_delegation", [])[:3]
    for i, host in enumerate(deleg):
        name = host.get("name", f"HOST-{i}")
        nid = f"deleg_{i}"
        nodes.append(_node(nid, f"Delegation: {name}", "delegation", x=1200, y=i * 120))
        edges.append(_edge("dc", nid, "T1078.002 Delegation Abuse", color="#84cc16"))
        edges.append(_edge(nid, "dc", "→ TGT Capture", color="#84cc16", animated=True))

    # Risk node
    risk = assessment.get("risk_score", 0)
    risk_color = "#ef4444" if risk >= 70 else "#f97316" if risk >= 40 else "#22c55e"
    nodes.append(_node("risk", f"Risco: {risk}/100", "user",
                        {"risk_score": risk, "critical": assessment.get("critical_findings", [])},
                        x=600, y=max(len(spns), len(asrep)) * 100 + 150))

    # Summary edge
    if spns or asrep or deleg:
        edges.append(_edge("attacker", "risk", "Impacto total", color=risk_color, animated=True))

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "risk_score": risk,
            "kerberoastable_accounts": len(assessment.get("spns", [])),
            "asrep_roastable": len(assessment.get("asrep_users", [])),
            "unconstrained_delegation_hosts": len(assessment.get("unconstrained_delegation", [])),
            "domain_users_total": len(assessment.get("domain_users", [])),
            "critical_findings": assessment.get("critical_findings", []),
            "dc_host": dc_host,
        },
        "data_source": "real_ldap" if assessment.get("spns") or assessment.get("asrep_users") else "demo",
    }


def build_demo_graph() -> dict:
    """Return a demo graph when no AD credentials are configured."""
    demo_assessment = {
        "dc_host": "DC01.corp.local",
        "spns": [
            {"account": "svc_sql", "spn": "MSSQLSvc/sql01.corp.local:1433", "privileged": False},
            {"account": "svc_backup", "spn": "BackupSvc/backup01.corp.local", "privileged": False},
            {"account": "krbtgt", "spn": "krbtgt/CORP.LOCAL", "privileged": True},
        ],
        "asrep_users": [
            {"account": "john.doe", "dn": "CN=John Doe,OU=Users,DC=corp,DC=local"},
            {"account": "svc_web", "dn": "CN=svc_web,OU=Service Accounts,DC=corp,DC=local"},
        ],
        "unconstrained_delegation": [
            {"name": "FILE01$", "dn": "CN=FILE01,OU=Computers,DC=corp,DC=local"},
        ],
        "domain_users": [],
        "risk_score": 78,
        "critical_findings": ["krbtgt tem SPN — Golden Ticket possível", "2 contas sem pre-auth Kerberos"],
    }
    result = build_attack_graph(demo_assessment)
    result["data_source"] = "demo"
    result["demo_notice"] = "Configure credenciais AD em /api/ad-attacks para dados reais via LDAP"
    return result
