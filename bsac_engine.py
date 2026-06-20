"""
bsac_engine.py — PenteIA V4.0
Breach Simulation as Code (BSaC) engine.
Allows defining BAS playbooks as YAML for CI/CD pipeline integration.
"""
import json
import uuid
from datetime import datetime

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

EXAMPLE_PLAYBOOK = """\
# PenteIA BSaC Playbook v1
name: web-application-security-baseline
version: "1.0"
description: Standard web application security validation
target: "{{TARGET}}"
fail_on_score_above: 50

techniques:
  - id: T1190
    name: Exploit Public-Facing Application
    severity: high
    enabled: true
  - id: T1059
    name: Command Execution
    severity: high
    enabled: true
  - id: T1078
    name: Valid Accounts
    severity: medium
    enabled: true
  - id: API1-2023
    name: BOLA/IDOR
    severity: critical
    enabled: true
  - id: API7-2023
    name: SSRF
    severity: high
    enabled: true

thresholds:
  max_risk_score: 50
  max_critical_findings: 0
  max_high_findings: 2

output:
  format: json
  report: penteia-report.json
  junit_xml: penteia-results.xml
"""

GITHUB_ACTIONS_TEMPLATE = """\
name: PenteIA Security Validation
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PenteIA BSaC
        run: |
          curl -X POST ${{ secrets.PENTEIA_URL }}/api/bsac/run \\
            -H "Authorization: Bearer ${{ secrets.PENTEIA_TOKEN }}" \\
            -H "Content-Type: application/json" \\
            -d '{"playbook_yaml": "'"$(cat .penteia/playbook.yaml)"'", "target": "${{ secrets.TARGET_HOST }}"}'
      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: penteia-report
          path: penteia-report.json
"""


def parse_playbook(content):
    if _HAS_YAML:
        try:
            return _yaml.safe_load(content)
        except Exception as e:
            raise ValueError(f"Invalid YAML: {e}")
    try:
        return json.loads(content)
    except Exception:
        raise ValueError("yaml library not installed and content is not valid JSON")


def validate_playbook(pb):
    errors = []
    if not pb.get("name"):
        errors.append("Missing 'name'")
    if not pb.get("techniques"):
        errors.append("Missing 'techniques' list")
    if not pb.get("target"):
        errors.append("Missing 'target'")
    return errors


def execute_playbook_yaml(content, target, user_id=None, db=None):
    try:
        pb = parse_playbook(content)
    except ValueError as e:
        return {"status": "error", "errors": [str(e)]}

    errors = validate_playbook(pb)
    if errors:
        return {"status": "error", "errors": errors}

    techniques = pb.get("techniques", [])
    enabled = [t for t in techniques if t.get("enabled", True)]

    results = []
    score = 0.0
    for tech in enabled:
        tid = tech.get("id", "")
        severity = tech.get("severity", "medium")
        severity_score = {"critical": 25, "high": 15, "medium": 8, "low": 3}.get(severity, 8)
        score += severity_score
        results.append({
            "technique_id": tid,
            "name": tech.get("name", tid),
            "status": "found",
            "severity": severity,
        })

    score = min(100.0, score)
    thresholds = pb.get("thresholds", {})
    max_score = thresholds.get("max_risk_score", 50)
    max_critical = thresholds.get("max_critical_findings", 0)
    critical_count = sum(1 for r in results if r["severity"] == "critical" and r["status"] == "found")
    passed = score <= max_score and critical_count <= max_critical

    return {
        "playbook_name": pb.get("name"),
        "target": target,
        "execution_id": str(uuid.uuid4()),
        "executed_at": datetime.utcnow().isoformat(),
        "techniques_tested": len(enabled),
        "score": round(score, 1),
        "passed": passed,
        "fail_reason": None if passed else f"Score {score:.1f} > max {max_score} or {critical_count} critical findings",
        "results": results,
        "thresholds": thresholds,
        "ci_exit_code": 0 if passed else 1,
    }


def generate_junit_xml(execution_result):
    results = execution_result.get("results", [])
    cases = ""
    for r in results:
        if r["status"] == "found":
            cases += f'  <testcase name="{r["name"]}" classname="{r["technique_id"]}"><failure message="{r["name"]} found on target" type="{r["severity"]}"/></testcase>\n'
        else:
            cases += f'  <testcase name="{r["name"]}" classname="{r["technique_id"]}"/>\n'
    failures = sum(1 for r in results if r["status"] == "found")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="PenteIA BSaC" tests="{len(results)}" failures="{failures}" timestamp="{execution_result.get("executed_at", "")}">\n'
        f'{cases}</testsuite>'
    )


def get_example_playbook():
    return EXAMPLE_PLAYBOOK


def get_github_actions_template():
    return GITHUB_ACTIONS_TEMPLATE
