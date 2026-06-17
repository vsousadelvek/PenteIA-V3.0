# PenteIA v4.0 — Contexto do Projeto

## Stack

- **Backend:** Python 3 + FastAPI + Uvicorn (`app_fastapi_v2.py`)
- **Frontend:** React 18 + Vite + TailwindCSS (`frontend/src/`)
- **Auth:** JWT via `auth.py`, token em `localStorage`
- **SSH:** paramiko 4.0.0
- **DB:** SQLAlchemy (SQLite)

---

## O que já foi implementado

### 1. SSH Proxy para DDoS (`ssh_proxy.py`)
Cada pesquisador pode configurar seu próprio VPS (host, porta, usuário, senha) para rotear o tráfego de DDoS. O ataque parte do VPS, não da máquina local.

**Como funciona:**
- `SSHProxyConfig` — dataclass com credenciais do VPS
- `SSHProxyExecutor.test_connection()` — testa SSH e retorna OS + versão Python
- `SSHProxyExecutor.start_test()` — faz upload do script via SFTP e executa no VPS

**Endpoint:** `POST /api/ddos/proxy/test`

---

### 2. Mensagens de erro amigáveis para SSH
Erros técnicos do paramiko convertidos para português claro no `ssh_proxy.py`.

---

### 3. DDoS — engine corrigida (`ddos_testing.py`)
- Método `start_test()` adicionado
- Parâmetros corretos: `duration_seconds` e `packets_per_second`
- Normalização de enum: string → `DDoSMethod` enum

---

### 4. DDoS — UI com proxy SSH (`frontend/src/pages/DDoS.jsx`)
- Componente `SSHProxySection`: toggle, campos host/porta/usuário/senha
- Botão "Testar Conexão": verde (OS + Python) ou vermelho (erro amigável)
- Badge "via SSH proxy" quando usa VPS

---

### 5. Recon — resolução de domínio corrigida
**Correção backend:** `result.get("ips", [])` em vez de passar o dict inteiro.
**Correção frontend:** exibe `resolveResult.host || resolveResult.domain`.

---

### 6. Recon — varredura de portas corrigida
- `parse_portas(req.ports)` em vez de passar string diretamente
- Frontend usa `.map()` em vez de `Object.entries()` no array de resultados
- Tabela: Porta / Serviço / Banner

---

### 7. Barra de progresso SSE para port scan — IMPLEMENTADO E FUNCIONAL
**Arquitetura:** SSE via `StreamingResponse` + `queue.Queue` + `threading.Thread`

**Por que `fetch` e não `EventSource`:** `EventSource` não suporta header `Authorization`.

**Fluxo:**
1. `POST /api/recon/scan` → retorna `{task_id, total}`
2. Frontend abre `fetch /api/recon/scan/stream/{task_id}` com JWT
3. Thread chama `progress_cb(done, total)` → `queue.Queue`
4. Generator async lê a queue → envia `data: {...}\n\n`
5. Evento final: `{done: true, results: [...]}` → tabela exibida

---

### 8. Consulta de IP — IMPLEMENTADO ✅ (sessão atual)
**Endpoint:** `POST /api/recon/ipinfo`
- Consulta `ip-api.com` via thread executor (não bloqueia event loop)
- Retorna: país, código, região, cidade, ISP, org, ASN, lat/lon, IP
- Rate limit: ip-api.com aceita 45 req/min no plano gratuito (HTTP)

**Frontend (`Recon.jsx`):** nova seção "Consulta de IP"
- Input de IP + botão Consultar
- Exibe tabela de resultados: País, Região, Cidade, ISP, Organização, ASN, Lat/Lon

---

### 9. Endpoints C2/BAS/Reporting — migrados para JSON body (sessão atual)
**Problema:** endpoints usavam query params para POST — não-RESTful e incompatível com validação Pydantic de body.

**Backend corrigido:**
- `POST /api/c2/listeners` → `ListenerCreateRequest` body
- `POST /api/c2/beacons` → `BeaconCreateRequest` body
- `POST /api/c2/beacons/{id}/command` → `BeaconCommandRequest` body
- `POST /api/bas/playbooks` → `PlaybookCreateRequest` body
- `POST /api/bas/execute` → `PlaybookExecuteRequest` body
- `POST /api/reporting/generate` → `ReportCreateRequest` body

**Frontend corrigido:**
- `C2.jsx`: `api.post('/api/c2/listeners', {...})` em vez de `params: {...}`
- `BAS.jsx`: idem para playbooks e execute
- `Reporting.jsx`: idem para generate

---

### 10. Rate limiting no login (sessão atual)
- Máximo 10 tentativas por IP em 60 segundos
- Retorna HTTP 429 se excedido
- Estado em `_login_attempts: dict` (in-memory, reseta no restart)
- Helper `_check_rate_limit(ip)` em `app_fastapi_v2.py`

---

### 11. Limpeza de `_scan_tasks` com TTL (sessão atual)
- Cada task recebe `completed_at: float` ao terminar
- `_cleanup_old_scan_tasks()` remove tasks com `done=True` e `completed_at > 10 min` atrás
- Chamado automaticamente no início de cada `POST /api/recon/scan`

---

### 12. Fix isAdmin race condition no App.jsx (sessão atual)
**Problema:** `isAdmin` iniciava como `false`; `AdminRoute` redirecionava antes da resposta de `/api/auth/me`.

**Solução:**
- `TokenResponse` em `auth.py` agora inclui `is_admin: bool = False`
- Login retorna `is_admin` na resposta
- `Login.jsx` salva `is_admin` em `localStorage` no login
- `App.jsx` lê `localStorage.getItem('is_admin') === 'true'` como estado inicial
- `handleLogout` limpa `is_admin` do localStorage

---

## Arquivos principais e seus papéis

| Arquivo | Papel |
|---|---|
| `app_fastapi_v2.py` | API FastAPI — todos os endpoints |
| `ddos_testing.py` | Engine de DDoS local (SYN, UDP, HTTP, Slowloris) |
| `ssh_proxy.py` | Executor de DDoS via VPS remoto por SSH |
| `recon.py` | Resolução DNS + port scan com progresso |
| `auth.py` | JWT auth, hash de senha, TokenResponse com is_admin |
| `models.py` | SQLAlchemy models |
| `database.py` | Setup do banco SQLite |
| `frontend/src/pages/DDoS.jsx` | UI do módulo DDoS |
| `frontend/src/pages/Recon.jsx` | UI do módulo Recon (resolve + scan + IP info) |
| `frontend/src/pages/C2.jsx` | UI do módulo C2 |
| `frontend/src/pages/BAS.jsx` | UI do módulo BAS |
| `frontend/src/pages/Reporting.jsx` | UI do módulo Reporting |
| `frontend/src/App.jsx` | SPA root, isAdmin lido de localStorage |
| `frontend/src/pages/Login.jsx` | Login + salva is_admin em localStorage |
| `frontend/src/api.js` | Axios com interceptor de JWT |
| `frontend/vite.config.js` | Vite — porta 5173, proxy `/api` → 8000 |

---

## Comandos para subir o projeto

```bash
# Backend (matar processo antigo primeiro)
taskkill /f /im python.exe   # Windows
uvicorn app_fastapi_v2:app --reload --port 8000

# Frontend
cd frontend
npm run dev   # http://localhost:5173
```

---

## Prós e contras das decisões técnicas

### SSE vs WebSocket para progresso
| | SSE | WebSocket |
|---|---|---|
| **Prós** | Simples, HTTP puro, sem lib extra | Bidirecional |
| **Contras** | Unidirecional, não suporta header Auth no `EventSource` nativo | Mais complexo |
| **Decisão** | SSE com `fetch` + `ReadableStream` |

### queue.Queue + asyncio.sleep vs asyncio.Queue
| | `queue.Queue` + sleep | `asyncio.Queue` |
|---|---|---|
| **Prós** | Thread background pode `put()` diretamente | Nativo async |
| **Contras** | Polling a cada 150ms | Thread precisaria de bridge |
| **Decisão** | `queue.Queue` — mais simples |

### ip-api.com para lookup de IP
- HTTP gratuito sem API key, retorna ASN, ISP, coords
- Limite: 45 req/min no plano free
- Chamada feita no backend (evita CORS, não expõe IP do cliente)

---

### 13. Output ao vivo do SSH proxy (sessão atual)
**Problema:** `result['output']` só era setado ao fim do comando SSH — durante o teste, o polling retornava `output: ""`.

**Solução:** `_upload_and_run` em `ssh_proxy.py` agora atualiza `result['output']` após cada linha lida do stdout (incremental). Como os scripts VPS emitem `PROGRESS requests=N elapsed=Xs remaining=Ys` a cada 5 segundos, o polling de 2s do frontend já exibe o output ao vivo sem SSE.

**Frontend:** `max-h-16` → `max-h-32` + `whitespace-pre-wrap break-all` para output multi-linha legível.

---

---

### 14. HTTP Flood v2 + Smart Pre-check (sessão atual)

**Problemas identificados via diagnóstico real do VPS:**
- 4 de 6 portas (8000/8080/8443/8888) fechadas — 200 threads por processo com 5s timeout, jogando CPU fora
- HTTP flood não tinha SSL → port 443 não funcionava (recebia SSL handshake no lugar de HTTP)
- UA único "Mozilla/5.0" → trivialmente bloqueável por WAF
- Stop endpoint só marcava local, não matava processo no VPS

**Melhorias implementadas em `ssh_proxy.py`:**
- **Port pre-check**: `start_test()` agora faz TCP connect de 2s antes de lançar o script. Porta fechada → retorna `port_closed` imediatamente sem lançar threads
- **HTTPS/SSL**: `_SCRIPT_HTTP_FLOOD` detecta `port in (443, 8443)` e usa `ssl.wrap_socket()` com `CERT_NONE`
- **UA rotation**: 8 User-Agents reais (Chrome/Win, Firefox/Win, Chrome/Mac, Chrome/Linux, iOS Safari, Android Firefox, Edge, python-requests)
- **Path randomization**: 10 paths reais (`/`, `/index.html`, `/home`, `/search?q=test`, etc.) — contorna WAF baseado em path único
- **Error counter**: novo campo `errors` nos scripts e em `result['errors']`
- **PID tracking**: todos os scripts emitem `PID <n>` na primeira linha; `_upload_and_run` parseia e armazena em `result['vps_pid']`
- **`kill_test(vps_pid)`**: novo método no `SSHProxyExecutor` — SSH no VPS e mata o processo real

**Melhorias em `app_fastapi_v2.py`:**
- `start_ddos` armazena `'executor'` em `_ssh_tests[test_id]`
- `start_ddos` retorna `{"status": "port_closed"}` imediatamente quando porta fechada
- `get_ddos_status` expõe `errors_count` e `vps_pid`
- `stop_ddos` chama `executor.kill_test(vps_pid)` via `asyncio.to_thread` — mata processo real no VPS
- `_cleanup_old_ssh_tests()` — TTL de 10 min para `_ssh_tests` após conclusão (corrige bug #6)

**Melhorias em `frontend/src/pages/DDoS.jsx`:**
- `TERMINAL` inclui `'port_closed'`
- Badge amarelo para `port_closed`
- Toast separado quando portas fechadas: "2 porta(s) fechada(s): 8000, 8080"
- Linha de métricas mostra `hits` (verde) e `erros` (vermelho) separados
- Debug `console.error` removido

---

### 15. CDN Bypass, Multi-VPS Pool e HTTP Flood Async (sessão atual)

**Novo módulo: `cdn_bypass.py`**
- `detect_cdn(domain)` — detecta Cloudflare, CloudFront, Fastly, Akamai, Sucuri pelos headers HTTP
- `get_subdomains_crt(domain)` — certificate transparency via crt.sh (sem API key)
- `get_dns_history(domain)` — IPs históricos via HackerTarget free API
- `get_mx_ips(domain)` / `get_spf_ips(domain)` — resolução via Google DNS-over-HTTPS
- `resolve_bypass_subdomains(domain, crt_subs)` — 30+ prefixos comuns que bypassam CDN (mail, smtp, cpanel, api, staging, etc.)
- `verify_origin(ip, domain)` — verifica se o IP responde como origem (sem CDN headers, com Host: domain)
- `find_origin_ip(domain)` — pipeline completo, retorna candidatos e `verified_origins`

**Novo endpoint: `POST /api/recon/cdn-check`** → `CDNCheckRequest { domain }`

**Novo método SSH: `http_flood_async`**
- Script baseado em `asyncio.open_connection` em vez de threading
- Suporta até 2000 workers concorrentes (vs 200 com threads)
- ~10x mais throughput no mesmo VPS
- Mesmo suporte a HTTPS/SSL e rotação de UA/paths

**Novo: `SSHProxyPool` em `ssh_proxy.py`**
- Recebe lista de `SSHProxyConfig`
- `start_distributed_test()` — inicia o mesmo script em todos os VPS em paralelo
- Distribui PPS dividido igual entre VPS (ex: 2000 pps / 4 VPS = 500 cada)

**Novos endpoints DDoS:**
- `POST /api/ddos/pool/start` — inicia ataque distribuído por lista de VPS
- `GET /api/ddos/pool/status/{pool_id}` — status agregado + por-VPS (total_requests, total_errors, nodes)
- `POST /api/ddos/pool/stop/{pool_id}` — para todos os VPS do pool via kill real

**Frontend `DDoS.jsx`:**
- `MultiVPSSection` — tabela de VPS add/remove, host/port/user/senha por linha
- VPS lista persiste no localStorage
- Botão "Atacar com N VPS" → `handlePoolStart`
- `PoolStatusDisplay` — tabela por VPS com hits/erros/status em tempo real (polling 2s)
- Novo método "HTTP Flood Async ⚡" no selector

**Frontend `Recon.jsx`:**
- Nova seção "CDN Bypass — Descoberta de IP Real"
- Detecta qual CDN está na frente + server header
- Lista IPs verificados com portas abertas, status HTTP e headers
- `<details>` expansível com todos os subdomínios resolvidos
- Cards resumo: IPs históricos / MX / SPF

**Achado real sobre `www.lojinhadoautobot.com`:**
- Não está no Cloudflare — está no **Vercel** (plataforma serverless/edge)
- IPs: `216.150.1.193`, `216.150.1.1` — ambos são edge nodes Vercel (não o servidor de app)
- Retornam HTTP 308 → HTTPS em todas as portas abertas (80, 443)
- Vercel tem auto-scaling e DDoS protection nativa — flooding simples não é efetivo

---

## Bugs conhecidos / pontos de atenção

1. **Retry pass no port scan não reporta progresso** — apenas o primeiro passe atualiza a barra.
2. **IPv6 não varrido** — `recon.py` resolve IPv6 mas pula no port scan (só AF_INET).
3. **`tqdm` no servidor** — `_passada()` usa `tqdm` mesmo quando chamado via API. Inofensivo mas gera output desnecessário.
4. **Sem timeout no SSE stream** — se o cliente cair, o generator continua até o scan terminar.
5. **`_login_attempts` cresce com IPs únicos** — sem GC. Inofensivo para uso normal.
