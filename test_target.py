#!/usr/bin/env python3
"""
PenteIA - Site de Teste Avançado (porta 8080)
Simula aplicação web corporativa moderna com:
  - Rate limiting por IP (429)
  - WAF básico (bloqueia SQLi, XSS, path traversal)
  - JWT simulado em endpoints protegidos
  - Security headers (CSP, HSTS, X-Frame-Options, etc.)
  - CSRF token em formulários
  - Múltiplas rotas HTML + REST API v1/v2
NAO usar em producao - apenas ambiente de teste autorizado.
"""
import json
import time
import random
import threading
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict

# ─── Rate limiting ────────────────────────────────────────────────────────────
# max requests per window (seconds)
RATE_LIMIT  = {
    'global': (60, 10),   # 60 req / 10s
    'login':  (5,  30),   # 5 req / 30s
    'api':    (30, 10),   # 30 req / 10s
}
_rate_buckets = defaultdict(list)  # ip -> [timestamp, ...]
_rate_lock    = threading.Lock()

def is_rate_limited(ip, zone='global'):
    max_req, window = RATE_LIMIT[zone]
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets[f"{zone}:{ip}"]
        # remove old entries
        _rate_buckets[f"{zone}:{ip}"] = [t for t in bucket if now - t < window]
        bucket = _rate_buckets[f"{zone}:{ip}"]
        if len(bucket) >= max_req:
            return True
        _rate_buckets[f"{zone}:{ip}"].append(now)
    return False

# ─── WAF patterns ────────────────────────────────────────────────────────────
import re
WAF_PATTERNS = [
    re.compile(r"(?i)(union\s+select|drop\s+table|insert\s+into|exec\s*\(|xp_cmdshell)"),
    re.compile(r"(?i)(<script|javascript:|onerror=|onload=|alert\s*\()"),
    re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)"),
    re.compile(r"(?i)(\/etc\/passwd|\/proc\/self|cmd\.exe|powershell)"),
    re.compile(r"(?i)(base64_decode|eval\(|system\(|passthru\()"),
]

def waf_check(path, headers, body=""):
    target = path + body
    for p in WAF_PATTERNS:
        if p.search(target):
            return True
    ua = headers.get("User-Agent", "")
    if any(tool in ua.lower() for tool in ["sqlmap", "nikto", "nessus", "openvas"]):
        return True
    return False

# ─── JWT (simulado) ──────────────────────────────────────────────────────────
FAKE_SECRET = "corp-tech-secret-key-2026"
DEMO_TOKENS = {
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.demo": {"sub": "admin", "role": "admin"},
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMDEiLCJyb2xlIjoidXNlciJ9.demo":  {"sub": "user01", "role": "user"},
}

def parse_token(headers):
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        return DEMO_TOKENS.get(token)
    return None

# ─── HTML pages ──────────────────────────────────────────────────────────────
CSRF_TOKEN = hashlib.sha256(b"pentest-csrf-demo-2026").hexdigest()[:32]

PAGES = {
    "/": """<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="{csrf}">
<title>CorpTech Solutions</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#f4f4f4;color:#161616}}
nav{{background:#161616;color:white;padding:0 32px;height:48px;display:flex;align-items:center;justify-content:space-between}}
nav .logo{{color:#78a9ff;font-weight:700}}
nav ul{{list-style:none;display:flex;gap:20px}}
nav ul a{{color:#c6c6c6;text-decoration:none;font-size:.9em}}
.hero{{background:linear-gradient(135deg,#0f62fe,#001d6c);color:white;padding:80px 32px;text-align:center}}
.hero h1{{font-size:2.5em;font-weight:300;margin-bottom:16px}}
.hero p{{color:#a6c8ff;max-width:600px;margin:0 auto}}
.container{{max-width:1100px;margin:0 auto;padding:40px 32px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}}
.card{{background:white;border:1px solid #e0e0e0;padding:24px;border-radius:4px}}
.card h3{{margin-bottom:8px}}
.card p{{color:#6f6f6f;font-size:.9em;line-height:1.6}}
footer{{background:#262626;color:#a8a8a8;padding:32px;text-align:center;font-size:.85em}}
</style></head><body>
<nav><span class="logo">CorpTech Solutions</span>
<ul><li><a href="/about">Empresa</a></li><li><a href="/products">Produtos</a></li>
<li><a href="/contact">Contato</a></li><li><a href="/login">Login</a></li></ul></nav>
<div class="hero">
<h1>Tecnologia Empresarial de <strong>Alto Desempenho</strong></h1>
<p>Plataforma integrada com segurança ISO 27001, SOC 2 Type II e conformidade LGPD.</p>
</div>
<div class="container">
<div class="grid">
<div class="card"><h3>ERP Corporativo</h3><p>Gestao integrada de financas, RH e producao com API REST.</p></div>
<div class="card"><h3>CRM Premium</h3><p>Pipeline de vendas com analytics e Machine Learning integrado.</p></div>
<div class="card"><h3>Cloud Storage</h3><p>Armazenamento AES-256 com CDN global e 99.99% de uptime SLA.</p></div>
</div></div>
<footer>CorpTech Solutions LTDA &copy; 2026 | CNPJ: 12.345.678/0001-90 | Sao Paulo, SP</footer>
</body></html>""",

    "/login": """<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="UTF-8"><title>Login - CorpTech</title>
<style>body{{font-family:'Segoe UI',sans-serif;background:#f4f4f4;display:flex;justify-content:center;align-items:center;min-height:100vh}}
.box{{background:white;border:1px solid #e0e0e0;padding:40px;width:360px;border-radius:4px}}
h2{{margin-bottom:24px;color:#161616;font-weight:600}}
label{{display:block;font-size:.85em;color:#525252;margin-bottom:4px}}
input{{width:100%;padding:10px;border:1px solid #e0e0e0;border-radius:2px;font-size:.9em;margin-bottom:16px}}
input:focus{{outline:none;border-color:#0f62fe}}
button{{width:100%;background:#0f62fe;color:white;border:none;padding:12px;font-size:.95em;cursor:pointer;border-radius:2px}}
.hint{{margin-top:16px;font-size:.8em;color:#6f6f6f;text-align:center}}
.security-note{{background:#e8f1ff;border-left:3px solid #0f62fe;padding:10px 14px;font-size:.8em;color:#0043ce;margin-bottom:20px;border-radius:2px}}
</style></head><body>
<div class="box">
<h2>Acessar Sistema</h2>
<div class="security-note">Conexao protegida com TLS 1.3 | Sessao com MFA ativo</div>
<form action="/api/v1/auth/login" method="POST">
<input type="hidden" name="_csrf" value="{csrf}">
<label>Email corporativo</label>
<input type="email" name="email" placeholder="usuario@empresa.com.br" required>
<label>Senha</label>
<input type="password" name="password" placeholder="•••••••••••" required>
<button type="submit">Entrar</button>
<div class="hint">Esqueceu a senha? <a href="/reset" style="color:#0f62fe">Recuperar acesso</a></div>
</form></div></body></html>""",

    "/about": """<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Sobre - CorpTech</title>
<style>body{{font-family:'Segoe UI',sans-serif;max-width:800px;margin:40px auto;padding:0 20px;background:#f4f4f4}}
.card{{background:white;border:1px solid #e0e0e0;padding:24px;margin:16px 0;border-radius:4px}}</style></head><body>
<h1>Sobre a CorpTech Solutions</h1>
<div class="card"><p>Fundada em 2015, a CorpTech Solutions atua no mercado de tecnologia empresarial com foco em ERP, CRM e Cloud.</p>
<p style="margin-top:12px">Nossa equipe de 320 profissionais atende mais de 2.400 clientes em 18 paises.</p></div>
<div class="card"><h2 style="margin-bottom:8px">Certificacoes</h2>
<ul style="padding-left:20px;color:#525252">
<li>ISO 27001:2022 — Seguranca da Informacao</li>
<li>SOC 2 Type II — Controles de Seguranca</li>
<li>LGPD — Lei Geral de Protecao de Dados</li>
<li>PCI DSS Level 1 — Processamento de Pagamentos</li>
</ul></div>
</body></html>""",

    "/products": """<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Produtos - CorpTech</title>
<style>body{{font-family:'Segoe UI',sans-serif;max-width:900px;margin:40px auto;padding:0 20px;background:#f4f4f4}}
.card{{background:white;border:1px solid #e0e0e0;padding:24px;margin:16px 0;border-radius:4px}}
.price{{font-size:1.5em;font-weight:700;color:#0f62fe}}</style></head><body>
<h1>Nossos Produtos</h1>
<div class="card"><h2>ERP Corporativo</h2><p class="price">R$ 9.990/mes</p>
<p style="color:#6f6f6f;margin-top:8px">Sistema de gestao empresarial completo. Modulos: Financas, RH, Estoque, Producao, Compras. API REST com 200+ integrações.</p></div>
<div class="card"><h2>CRM Premium</h2><p class="price">R$ 4.990/mes</p>
<p style="color:#6f6f6f;margin-top:8px">Gestao de relacionamento com clientes, pipeline de vendas, automacao de marketing e relatorios com BI integrado.</p></div>
<div class="card"><h2>Cloud Storage Enterprise</h2><p class="price">R$ 2.490/mes</p>
<p style="color:#6f6f6f;margin-top:8px">Armazenamento corporativo ilimitado com criptografia AES-256, backup automatico multi-regiao e CDN global.</p></div>
</body></html>""",

    "/contact": """<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Contato - CorpTech</title>
<style>body{{font-family:'Segoe UI',sans-serif;max-width:600px;margin:40px auto;padding:0 20px;background:#f4f4f4}}
.card{{background:white;border:1px solid #e0e0e0;padding:28px;border-radius:4px}}
label{{display:block;font-size:.85em;color:#525252;margin-bottom:4px}}
input,textarea,select{{width:100%;padding:10px;border:1px solid #e0e0e0;border-radius:2px;font-size:.9em;margin-bottom:16px}}
button{{background:#0f62fe;color:white;border:none;padding:10px 24px;cursor:pointer;border-radius:2px}}</style></head><body>
<h1 style="margin-bottom:20px">Fale Conosco</h1>
<div class="card">
<form action="/api/v1/contact" method="POST">
<input type="hidden" name="_csrf" value="{csrf}">
<label>Nome completo</label><input type="text" name="nome" placeholder="Seu nome" required>
<label>Email corporativo</label><input type="email" name="email" placeholder="seu@empresa.com" required>
<label>Produto de interesse</label>
<select name="produto"><option>ERP Corporativo</option><option>CRM Premium</option><option>Cloud Storage</option></select>
<label>Mensagem</label><textarea name="msg" rows="4" placeholder="Como podemos ajudar?"></textarea>
<button type="submit">Enviar mensagem</button>
</form></div></body></html>""",

    "/dashboard": None,  # handled dynamically (requires token)

    "/robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /api/internal/\nDisallow: /backup/\nDisallow: /.env\nDisallow: /config/\nAllow: /\n",

    "/sitemap.xml": """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>http://localhost:8080/</loc><priority>1.0</priority></url>
<url><loc>http://localhost:8080/about</loc><priority>0.8</priority></url>
<url><loc>http://localhost:8080/products</loc><priority>0.8</priority></url>
<url><loc>http://localhost:8080/contact</loc><priority>0.6</priority></url>
<url><loc>http://localhost:8080/login</loc><priority>0.5</priority></url>
</urlset>""",
}

DASHBOARD_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Dashboard - CorpTech</title>
<style>body{{font-family:'Segoe UI',sans-serif;max-width:1000px;margin:40px auto;padding:0 20px;background:#1a1a2e;color:white}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin:24px 0}}
.card{{background:#16213e;padding:20px;border-radius:4px;border:1px solid #0f3460}}
.metric{{font-size:2.2em;font-weight:700;color:#78a9ff}}
.label{{color:#a8a8a8;font-size:.85em;margin-top:4px}}
.header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}}
.badge{{background:#0f62fe;padding:4px 12px;border-radius:12px;font-size:.8em}}
</style></head><body>
<div class="header"><h1>Dashboard Executivo</h1><span class="badge">Bem-vindo, {user}</span></div>
<div class="grid">
<div class="card"><div class="metric">2.441</div><div class="label">Usuarios Ativos</div></div>
<div class="card"><div class="metric">R$ 48,2k</div><div class="label">Receita Hoje</div></div>
<div class="card"><div class="metric">99.97%</div><div class="label">Uptime</div></div>
<div class="card"><div class="metric">1.847</div><div class="label">Pedidos no Mes</div></div>
<div class="card"><div class="metric">8ms</div><div class="label">Latencia Media API</div></div>
<div class="card"><div class="metric">0</div><div class="label">Incidentes Criticos</div></div>
</div>
<p style="color:#555;font-size:.8em;text-align:center">Sessao expira em 30 min | Role: {role}</p>
</body></html>"""

# ─── API routes ──────────────────────────────────────────────────────────────
_start_time    = time.time()
_request_count = 0
_lock          = threading.Lock()

class TargetHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def version_string(self):
        return "nginx/1.25.3"

    def date_time_string(self, timestamp=None):
        return super().date_time_string(timestamp)

    def get_ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0])

    def security_headers(self):
        self.send_header("Server", "nginx/1.25.3")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body_str, status=200):
        body = body_str.format(csrf=CSRF_TOKEN).encode("utf-8") if "{csrf}" in body_str else body_str.encode("utf-8") if isinstance(body_str, str) else body_str
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_429(self, zone='global'):
        retry = 30 if zone == 'login' else 10
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Retry-After", str(retry))
        self.security_headers()
        body = json.dumps({"error": "Too Many Requests", "message": f"Rate limit excedido. Tente novamente em {retry}s.", "code": 429}).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_waf_block(self):
        self.send_response(403)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.security_headers()
        body = json.dumps({"error": "Forbidden", "message": "Requisicao bloqueada pelo WAF", "code": 403, "waf": "blocked"}).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global _request_count
        ip   = self.get_ip()
        path = urlparse(self.path).path

        # Global rate limit
        if is_rate_limited(ip, 'global'):
            self.send_429('global')
            return

        # WAF — decodifica path + query separadamente
        _parsed = urlparse(self.path)
        _decoded = unquote(_parsed.path) + ("?" + unquote(_parsed.query) if _parsed.query else "")
        if waf_check(_decoded, self.headers):
            self.send_waf_block()
            return

        with _lock:
            _request_count += 1

        # Dashboard — requer JWT
        if path == "/dashboard":
            token_data = parse_token(self.headers)
            if not token_data:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            html = DASHBOARD_HTML.format(user=token_data["sub"], role=token_data["role"])
            self.send_html(html)
            return

        if path in PAGES:
            content = PAGES[path]
            if content is None:
                self.send_html("<html><body>Error</body></html>", 500)
            elif path in ("/robots.txt", "/sitemap.xml"):
                body = content.encode("utf-8")
                self.send_response(200)
                ct = "text/plain" if path == "/robots.txt" else "application/xml"
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.security_headers()
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_html(content)
            return

        # API routes
        if path == "/api/v1/status":
            if is_rate_limited(ip, 'api'):
                self.send_429('api')
                return
            self.send_json({"status": "ok", "version": "1.0.0",
                            "uptime": int(time.time() - _start_time),
                            "env": "production", "requests_handled": _request_count})
        elif path == "/api/v1/health":
            self.send_json({"healthy": True, "db": "connected", "cache": "connected", "queue": "idle"})
        elif path == "/api/v1/users":
            if is_rate_limited(ip, 'api'):
                self.send_429('api')
                return
            token = parse_token(self.headers)
            if not token:
                self.send_json({"error": "Unauthorized", "message": "Token de autenticacao necessario", "code": 401}, 401)
                return
            if token["role"] != "admin":
                self.send_json({"error": "Forbidden", "message": "Apenas administradores", "code": 403}, 403)
                return
            self.send_json({"users": [
                {"id": 1, "name": "admin", "email": "admin@corptech.com.br", "role": "admin"},
                {"id": 2, "name": "user01", "email": "user01@corptech.com.br", "role": "user"},
                {"id": 3, "name": "user02", "email": "user02@corptech.com.br", "role": "user"},
            ], "total": 3})
        elif path == "/api/v1/products":
            self.send_json({"products": [
                {"id": 1, "name": "ERP", "price": 9990, "currency": "BRL"},
                {"id": 2, "name": "CRM", "price": 4990, "currency": "BRL"},
                {"id": 3, "name": "Cloud Storage", "price": 2490, "currency": "BRL"},
            ]})
        elif path == "/api/v2/status":
            self.send_json({"status": "ok", "version": "2.0.0", "features": ["auth", "mfa", "api", "dashboard"]})
        elif path == "/api/v2/metrics":
            if is_rate_limited(ip, 'api'):
                self.send_429('api')
                return
            token = parse_token(self.headers)
            if not token:
                self.send_json({"error": "Unauthorized", "code": 401}, 401)
                return
            self.send_json({"requests_total": 94821 + _request_count, "errors_total": 47,
                            "avg_latency_ms": 8, "uptime_s": int(time.time() - _start_time)})
        elif path == "/api/v2/config":
            self.send_json({"error": "Unauthorized", "message": "Admin only", "code": 401}, 401)
        elif path == "/api/v1/slow":
            time.sleep(random.uniform(2, 6))
            self.send_json({"status": "ok", "note": "endpoint lento para testes de timeout"})
        elif path == "/api/v1/large":
            payload = {"data": "x" * 50000, "size": "50KB"}
            self.send_json(payload)
        elif path.startswith("/admin") or path.startswith("/backup") or path.startswith("/config"):
            token = parse_token(self.headers)
            if not token:
                self.send_json({"error": "Unauthorized", "message": "Autenticacao necessaria", "code": 401}, 401)
            elif token["role"] != "admin":
                self.send_json({"error": "Forbidden", "message": "Apenas administradores", "code": 403}, 403)
            else:
                self.send_json({"status": "ok", "section": path})
        elif path.startswith("/api/internal"):
            self.send_json({"error": "Forbidden", "code": 403}, 403)
        else:
            self.send_json({"error": "Not Found", "path": path, "code": 404}, 404)

    def do_POST(self):
        global _request_count
        ip   = self.get_ip()
        path = urlparse(self.path).path

        zone = 'login' if 'login' in path or 'auth' in path else 'api'
        if is_rate_limited(ip, zone):
            self.send_429(zone)
            return

        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

        _parsed = urlparse(self.path)
        _decoded = unquote(_parsed.path) + ("?" + unquote(_parsed.query) if _parsed.query else "")
        if waf_check(_decoded, self.headers, raw_body):
            self.send_waf_block()
            return

        with _lock:
            _request_count += 1

        if path in ("/api/v1/auth/login", "/api/v1/login"):
            # Simula check de credenciais — sempre falha (demo)
            time.sleep(random.uniform(0.3, 0.8))  # timing delay anti-brute
            self.send_json({"error": "Invalid credentials", "message": "Email ou senha incorretos", "code": 401}, 401)
        elif path == "/api/v1/auth/register":
            self.send_json({"error": "Registration closed", "message": "Novos cadastros somente via convite", "code": 403}, 403)
        elif path == "/api/v1/contact":
            self.send_json({"success": True, "message": "Mensagem recebida! Nossa equipe entrara em contato em ate 24h."})
        elif path.startswith("/api/"):
            self.send_json({"status": "ok", "received": True, "timestamp": int(time.time())})
        else:
            self.send_json({"error": "Not Found"}, 404)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.security_headers()
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Origin", "https://app.corptech.com.br")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
        self.end_headers()

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 8080
    server = HTTPServer((HOST, PORT), TargetHandler)
    print(f"\n  PenteIA - Site de Teste Avancado (v2)")
    print(f"  URL: http://localhost:{PORT}")
    print(f"")
    print(f"  Seguranca ativa:")
    print(f"    Rate limiting: 60 req/10s global | 5 req/30s login | 30 req/10s API")
    print(f"    WAF: bloqueia SQLi, XSS, path traversal, tools conhecidas")
    print(f"    JWT: /dashboard e /api/v1/users exigem token")
    print(f"    Security headers: CSP, HSTS, X-Frame-Options, etc.")
    print(f"")
    print(f"  Tokens de teste:")
    print(f"    Admin: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.demo")
    print(f"    User:  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMDEiLCJyb2xlIjoidXNlciJ9.demo")
    print(f"")
    print(f"  Endpoints publicos: / /about /products /contact /login")
    print(f"    /api/v1/status  /api/v1/health  /api/v1/products  /api/v2/status")
    print(f"  Endpoints protegidos (JWT): /dashboard /api/v1/users /api/v2/metrics")
    print(f"  Endpoints lentos: /api/v1/slow (2-6s)")
    print(f"  CTRL+C para parar\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor parado.")
