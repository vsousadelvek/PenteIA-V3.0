# PenteIA v4.0 — Plataforma de BAS & Red Team com IA

> **Breach & Attack Simulation (BAS) de nível enterprise com inteligência artificial, cobertura MITRE ATT&CK completa e stack nativa para o mercado brasileiro.**

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-Proprietary-red)

---

## Visão Geral

PenteIA v4.0 é uma plataforma completa de **Breach & Attack Simulation** (BAS) com:

- **248 endpoints REST** cobrindo toda a cadeia de ataque e defesa
- **7 módulos de engine** modulares e extensíveis
- **Frontend React 18 + TailwindCSS** com 40+ páginas funcionais
- **AI-powered** via Claude Haiku (Anthropic) para geração de cenários
- **Suporte nativo ao mercado brasileiro** — LGPD, BACEN, NF-e, DREX, Gov.br
- **Produção com Docker** — nginx proxy + API FastAPI + volumes persistentes

---

## Módulos Principais

### Rounds de Desenvolvimento

| Round | Módulos |
|-------|---------|
| R1-R2 | BAS Core, MITRE ATT&CK, Recon, DDoS, C2, Evasion, Phishing |
| R3 | APT Emulation, Cloud Identity, SOC Validation, MSSP, AI Scenarios, KEV Feed |
| R4 | AD Attacks, Real Execution Engine, Billing, Scheduler, Purple Team |
| R5 | K8s Security, API Security (OWASP), OT/ICS, Threat Intel (TIP), BSaC/CI-CD, CISO Dashboard |

### Engines Backend

| Arquivo | Descrição |
|---------|-----------|
| `app_fastapi_v2.py` | App principal FastAPI — 248 endpoints, JWT auth |
| `ext_router_v5.py` | AD Attacks, Real Execution, MSSP, Agents |
| `ext_router_v6.py` | Billing, Playbook Builder, Purple Team, Scheduler |
| `ext_router_v7.py` | K8s, API Security, OT/ICS, TIP, BSaC, CISO Dashboard |
| `k8s_engine.py` | 10 técnicas K8s/Container (MITRE ATT&CK for Containers) |
| `api_security_engine.py` | OWASP API Security Top 10 (2023) + scanner ativo |
| `ot_ics_engine.py` | 5 técnicas ICS-ATTACK (Modbus, OPC-UA, TRITON) |
| `tip_engine.py` | Clientes MISP, OpenCTI, AlienVault OTX |
| `bsac_engine.py` | Playbooks YAML, validação, JUnit XML para CI/CD |
| `ciso_dashboard_engine.py` | Tokens SHA-256, dashboard público por token |
| `ad_attack_engine.py` | Kerberoasting, DCSync, Pass-the-Hash, BloodHound |
| `ai_module.py` | Integração Claude Haiku para cenários IA |
| `apt_engine.py` | Emulação de grupos APT (Lazarus, APT28, etc.) |

---

## Requisitos

```
Python 3.11+
Node.js 20+
Docker 24+ + Docker Compose v2
```

---

## Quick Start (Desenvolvimento)

```bash
# 1. Clonar
git clone https://github.com/vsousadelvek/PenteIA-V3.0.git
cd PenteIA-V3.0

# 2. Configurar variáveis
cp .env.example .env
# Editar .env e adicionar ANTHROPIC_API_KEY

# 3. Backend
pip install -r requirements.txt
uvicorn app_fastapi_v2:app --host 0.0.0.0 --port 8000 --reload

# 4. Frontend
cd frontend
npm install
npm run dev   # http://localhost:5173
```

**Login padrão:** `admin` / `admin123`

---

## Deploy Produção (Docker)

```bash
# Configurar .env com SECRET_KEY e ANTHROPIC_API_KEY obrigatórios
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
echo "ANTHROPIC_API_KEY=sk-ant-api03-..." >> .env

# Build e start
docker compose -f docker-compose.prod.yml up -d --build

# Acessar em http://seu-servidor/
```

### Arquitetura Docker (Produção)

```
Internet
    │
    ▼
[nginx :80]          ← Frontend React (estático)
    │
    ├── /             → serve dist/ (SPA)
    └── /api/         → proxy → [FastAPI :8000]
                                     │
                                 [SQLite /data/]
                                 [volumes persistentes]
```

**Segurança do container:**
- Usuário não-root (`appuser` uid 1001)
- `no-new-privileges: true`
- API não exposta externamente (somente via nginx)
- HEALTHCHECK nativo
- Limites de CPU/memória

---

## Suite de Testes

```bash
# Testar todos os endpoints (248) contra servidor local
python test_all_endpoints.py

# Contra Docker
python test_all_endpoints.py --base-url http://localhost

# Com verbose
python test_all_endpoints.py --verbose --fail-fast
```

Cobertura: Auth, BAS, ATT&CK, APT, AD Attacks, K8s, OWASP API, OT/ICS, TIP, BSaC, CISO, MSSP, AI Scenarios, Scheduler, Purple Team, Compliance BR, Billing, Integrations.

---

## Funcionalidades por Módulo

### BAS & MITRE ATT&CK
- Playbooks customizáveis + execução simulada/real
- Matriz ATT&CK interativa com cobertura por técnica
- Benchmark por setor (financeiro, saúde, governo, varejo)
- Purple Team — correlação ataque x defesa

### K8s & Container Security
- 10 técnicas: container escape, service account abuse, etcd access, kubelet API, RBAC escalation, hostPID, lateral movement DNS
- Categorias: `k8s` (clusters) e `container` (Docker)

### API Security — OWASP Top 10 (2023)
- API1 a API10 com CVSS, payloads de teste, regras de detecção
- Scanner ativo: BOLA (IDOR), JWT alg:none, SSRF, security headers
- Teste seguro sem dependência de `requests`

### OT / ICS / SCADA
- ICS-ATTACK: Modbus command injection, OPC-UA, default credentials, setpoint manipulation
- Contexto nacional: energia elétrica, óleo & gás, tratamento de água, manufatura
- Referências reais: Ucrânia 2015/2016, Oldsmar 2021, TRITON 2017

### Threat Intelligence Platform (TIP)
- Conectores: MISP, OpenCTI (GraphQL), AlienVault OTX
- Enriquecimento de IOCs por técnica ATT&CK
- Configuração multi-plataforma por tenant

### Breach Simulation as Code (BSaC)
- Playbooks em YAML com thresholds configuráveis
- Integração CI/CD — exit code 0/1 para pipelines
- Export JUnit XML (GitLab CI, GitHub Actions, Jenkins)
- Template GitHub Actions pronto para uso

### CISO Live Dashboard
- Tokens SHA-256 com expiração configurável
- Dashboard público por URL (sem login) para stakeholders
- Risk score, tendência, top riscos

### Brasil — Exclusivos
- NF-e / SPED / DREX / Pix / Gov.br attack scenarios
- Compliance: LGPD (ANPD), BACEN, normas setoriais
- Notificação ANPD automatizada por simulação

### AD Attacks
- Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash
- BloodHound-style attack paths
- Mimikatz, Rubeus, Impacket integrados

### Integrações
- SentinelOne, Microsoft Defender, CrowdStrike
- Wazuh, Microsoft Sentinel
- Jira tickets automáticos, Slack/Teams alertas
- Tenable/Qualys import

---

## Variáveis de Ambiente

| Variável | Obrigatório | Descrição |
|----------|-------------|-----------|
| `SECRET_KEY` | **Sim** | Chave JWT (mín. 32 chars) |
| `ANTHROPIC_API_KEY` | Sim (AI) | Claude Haiku para cenários IA |
| `TOKEN_EXPIRE_MINUTES` | Não | Padrão: 1440 (24h) |
| `CORS_ORIGINS` | Não | Padrão: localhost |
| `HTTP_PORT` | Não | Porta nginx (padrão: 80) |
| `DOMAIN` | Não | Domínio de produção |

---

## Estrutura

```
PenteIA-V4.0/
├── app_fastapi_v2.py        # App principal FastAPI
├── ext_router_v5.py         # AD, Execution, MSSP
├── ext_router_v6.py         # Billing, Purple, Scheduler
├── ext_router_v7.py         # K8s, OWASP, OT, TIP, BSaC, CISO
├── k8s_engine.py
├── api_security_engine.py
├── ot_ics_engine.py
├── tip_engine.py
├── bsac_engine.py
├── ciso_dashboard_engine.py
├── ad_attack_engine.py
├── ai_module.py
├── apt_engine.py
├── [+ 20 outros engines]
├── requirements.txt
├── Dockerfile.api           # Produção hardened
├── docker-compose.prod.yml  # Stack completa de produção
├── test_all_endpoints.py    # Suite de testes 100%
└── frontend/
    ├── src/
    │   ├── pages/           # 40+ páginas React
    │   └── components/      # UI components
    ├── nginx.conf           # Proxy /api/ → backend
    └── Dockerfile
```

---

## Credenciais Padrão

> **Altere imediatamente em produção!**

- Admin: `admin` / `admin123`
- API: gere via `/api/keys`

---

## Licença

Propriedade de [sec365.com.br](https://sec365.com.br) — uso interno e clientes autorizados.
