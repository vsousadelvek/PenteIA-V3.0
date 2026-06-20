"""
api_security_engine.py — PenteIA V4.0
OWASP API Security Top 10 (2023) testing and simulation.
"""
import re
import json

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

OWASP_API_TOP10 = [
    {
        "id": "API1-2023",
        "name": "Broken Object Level Authorization (BOLA/IDOR)",
        "severity": "critical",
        "cvss": 9.8,
        "description": "API endpoints accept object IDs without verifying user owns the object.",
        "example": "GET /api/users/123/orders — replace 123 with 456 and access other user orders",
        "test_payloads": [
            "Replace numeric ID with sequential numbers: 1, 2, 3, 100",
            "Replace UUID with other user UUID from leaked data",
            "Add suffix: /api/users/me/../123",
        ],
        "detection_rules": ["Log all object ID accesses with user context", "Alert on bulk sequential ID enumeration"],
        "mitigations": ["Authorization check: user.id == resource.owner_id on every request", "Use random UUIDs instead of sequential integers"],
    },
    {
        "id": "API2-2023",
        "name": "Broken Authentication",
        "severity": "critical",
        "cvss": 9.1,
        "description": "Weak auth mechanisms: no brute-force protection, weak JWT secrets, tokens never expire.",
        "example": "JWT signed with 'secret' or 'password' — crackable in seconds",
        "test_payloads": [
            "JWT with alg:none attack",
            "Brute force weak JWT secret with jwt-cracker",
            "Reuse expired tokens (no expiry check)",
            "Try default credentials: admin/admin, admin/password",
        ],
        "detection_rules": ["Rate limit auth endpoints", "Alert on token manipulation (alg:none, kid injection)"],
        "mitigations": ["Strong JWT secrets (256-bit random)", "Short token expiry (15 min access, 7d refresh)", "Account lockout after 5 failures"],
    },
    {
        "id": "API3-2023",
        "name": "Broken Object Property Level Authorization",
        "severity": "high",
        "cvss": 8.1,
        "description": "APIs expose more object properties than needed. Attacker sends mass assignment to change role, balance, etc.",
        "example": "PUT /api/user {name: 'hacker', role: 'admin'} — privilege escalation",
        "test_payloads": [
            "Add 'role': 'admin' to update request",
            "Add 'is_admin': true, 'credit_balance': 999999",
            "Add 'email': 'attacker@evil.com' to change victim email",
        ],
        "detection_rules": ["Log unexpected fields in request body", "Alert on role/permission field modification"],
        "mitigations": ["Allowlist only expected fields per endpoint", "Input validation schema", "Output filtering"],
    },
    {
        "id": "API4-2023",
        "name": "Unrestricted Resource Consumption",
        "severity": "high",
        "cvss": 7.5,
        "description": "No rate limiting, no payload size limits, no query complexity limits. Leads to DoS or financial abuse.",
        "example": "GraphQL: query with 1000 nested objects exhausts server memory",
        "test_payloads": [
            "Send 1000 requests/second to expensive endpoint",
            "Upload 1GB file to file upload endpoint",
            "GraphQL deeply nested query",
            "Request 10000 items: ?limit=10000",
        ],
        "detection_rules": ["Rate limiting per IP/user", "Request size limits", "GraphQL query depth/complexity limit"],
        "mitigations": ["Rate limit all endpoints", "Max payload size 1MB", "GraphQL max depth 5, max complexity 1000"],
    },
    {
        "id": "API5-2023",
        "name": "Broken Function Level Authorization",
        "severity": "high",
        "cvss": 8.8,
        "description": "Admin endpoints accessible to regular users. Hidden endpoints discovered via path enumeration.",
        "example": "GET /api/admin/users accessible without admin role check",
        "test_payloads": [
            "Access /api/admin/*, /api/internal/*, /api/v1/admin/*",
            "Change HTTP method: GET to DELETE on read-only endpoints",
            "Add X-Original-URI, X-Rewrite-URL headers to bypass middleware",
        ],
        "detection_rules": ["Log 403 responses by authenticated users to admin paths", "Alert on method override headers"],
        "mitigations": ["RBAC check on every admin endpoint", "Default deny on all admin routes"],
    },
    {
        "id": "API6-2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "severity": "medium",
        "cvss": 7.2,
        "description": "Core business flows (checkout, transfer, vote) can be abused at scale without detection.",
        "example": "Buy 1000 items in flash sale bypassing per-user limit via parallel requests",
        "test_payloads": [
            "Send 100 parallel requests to /api/checkout",
            "Use multiple accounts to bypass per-account limits",
            "Race condition: two simultaneous transfer requests",
        ],
        "detection_rules": ["Business logic rate limiting", "Velocity checks per user per time window"],
        "mitigations": ["Idempotency keys on transactions", "Business logic rate limits", "Fraud detection layer"],
    },
    {
        "id": "API7-2023",
        "name": "Server Side Request Forgery (SSRF)",
        "severity": "high",
        "cvss": 8.6,
        "description": "API fetches URLs from user input without validation, allowing internal network access.",
        "example": "POST /api/fetch {url: 'http://169.254.169.254/latest/meta-data/'} — AWS metadata access",
        "test_payloads": [
            "http://169.254.169.254/latest/meta-data/ (AWS IMDS)",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost:6379/ (Redis)",
            "http://internal-service.local/admin",
            "file:///etc/passwd",
        ],
        "detection_rules": ["Block requests to RFC-1918 ranges and cloud metadata IPs", "Log all outbound HTTP from API layer"],
        "mitigations": ["Allowlist valid external domains", "Block 169.254.x.x, 10.x, 172.16-31.x, 192.168.x.x", "Disable redirects in HTTP client"],
    },
    {
        "id": "API8-2023",
        "name": "Security Misconfiguration",
        "severity": "medium",
        "cvss": 6.5,
        "description": "Unnecessary HTTP methods, missing security headers, CORS *, verbose error messages, debug mode.",
        "example": "CORS: Access-Control-Allow-Origin: * with credentials=true",
        "test_payloads": [
            "Try OPTIONS to enumerate allowed methods",
            "Check CORS: Origin: https://evil.com — does response reflect it?",
            "Missing headers: X-Content-Type-Options, HSTS, CSP",
            "Verbose errors: stack traces in 500 responses",
        ],
        "detection_rules": ["Security header scan", "CORS policy validation"],
        "mitigations": ["Specific CORS allowlist", "Security headers (HSTS, CSP, X-Frame-Options)", "Generic error messages in prod"],
    },
    {
        "id": "API9-2023",
        "name": "Improper Inventory Management",
        "severity": "medium",
        "cvss": 6.5,
        "description": "Old API versions still accessible, undocumented endpoints, shadow APIs from integrations.",
        "example": "/api/v1/users still accessible when v3 is current — v1 has no auth",
        "test_payloads": [
            "Enumerate: /api/v1/, /api/v2/, /api/beta/, /api/internal/",
            "Check /swagger.json, /openapi.json, /api-docs",
            "Look for JS bundles referencing internal API paths",
        ],
        "detection_rules": ["API gateway: block deprecated versions", "Monitor traffic to old API versions"],
        "mitigations": ["API versioning strategy with sunset dates", "Single API gateway", "Remove unused endpoints"],
    },
    {
        "id": "API10-2023",
        "name": "Unsafe Consumption of APIs (3rd Party)",
        "severity": "medium",
        "cvss": 6.8,
        "description": "Trusting 3rd party API responses without validation. Attacker compromises partner API to attack your system.",
        "example": "Your app trusts payment gateway response without signature validation",
        "test_payloads": [
            "Test if webhook signature is validated",
            "Replay old webhook events",
            "Inject malicious data into 3rd party integration",
        ],
        "detection_rules": ["Validate signatures on all webhook/API responses", "TLS pinning for critical integrations"],
        "mitigations": ["Validate all 3rd party responses", "Webhook signature validation (HMAC)", "Schema validation on external responses"],
    },
]


def list_vulnerabilities():
    return OWASP_API_TOP10


def get_vulnerability(vid):
    return next((v for v in OWASP_API_TOP10 if v["id"] == vid), None)


def scan_endpoint(base_url, endpoint, method="GET", headers=None, test_bola=True, test_auth=True, test_ssrf=True):
    findings = []
    tested = []
    headers = headers or {}

    if not _HAS_REQUESTS:
        return {"error": "requests library not available", "findings": [], "tests_run": []}

    full_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"

    if test_bola:
        tested.append("API1-BOLA")
        id_pattern = re.search(r'/(\d+)(?:/|$)', endpoint)
        if id_pattern:
            original_id = id_pattern.group(1)
            test_id = str(int(original_id) + 1)
            test_url = full_url.replace(f"/{original_id}", f"/{test_id}")
            try:
                r = _requests.get(test_url, headers=headers, timeout=5, allow_redirects=False)
                if r.status_code == 200:
                    findings.append({
                        "vuln_id": "API1-2023", "severity": "critical",
                        "endpoint": test_url, "evidence": f"HTTP 200 with id={test_id} (original={original_id})",
                        "detail": "Possible BOLA: incremented ID returned data",
                    })
            except Exception:
                pass

    if test_auth:
        tested.append("API2-Auth")
        import base64
        fake_jwt = (
            base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=") + "." +
            base64.b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip("=") + "."
        )
        try:
            r = _requests.request(method, full_url, headers={**headers, "Authorization": f"Bearer {fake_jwt}"}, timeout=5)
            if r.status_code == 200:
                findings.append({
                    "vuln_id": "API2-2023", "severity": "critical",
                    "endpoint": full_url, "evidence": "alg:none JWT accepted",
                    "detail": "Broken authentication: server accepts unsigned JWTs",
                })
        except Exception:
            pass

    if test_ssrf:
        tested.append("API7-SSRF")
        for payload in [{"url": "http://169.254.169.254/latest/meta-data/"}, {"url": "http://localhost:6379/"}]:
            try:
                r = _requests.post(full_url, json=payload, headers=headers, timeout=3)
                if r.status_code in (200, 201) and ("ami-id" in r.text or "redis" in r.text.lower()):
                    findings.append({
                        "vuln_id": "API7-2023", "severity": "high",
                        "endpoint": full_url, "evidence": f"SSRF probe to {payload['url']} returned data",
                        "detail": "Server Side Request Forgery confirmed",
                    })
            except Exception:
                pass

    try:
        r = _requests.get(base_url, timeout=5)
        missing = [h for h in ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"] if h not in r.headers]
        if missing:
            findings.append({
                "vuln_id": "API8-2023", "severity": "medium",
                "endpoint": base_url, "evidence": f"Missing: {', '.join(missing)}",
                "detail": "Security misconfiguration: missing HTTP security headers",
            })
    except Exception:
        pass

    return {
        "base_url": base_url,
        "endpoint": endpoint,
        "tests_run": tested,
        "findings_count": len(findings),
        "findings": findings,
        "risk_level": (
            "critical" if any(f["severity"] == "critical" for f in findings) else
            "high" if any(f["severity"] == "high" for f in findings) else
            "medium" if findings else "low"
        ),
    }
