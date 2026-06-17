# PenteIA v4.0 - Deployment & Usage Guide

## ✅ Sistema 100% Implementado

### Arquivos Criados/Atualizados

#### Backend (Python)
- ✅ `models.py` - 7 modelos SQLAlchemy (User, Listener, Beacon, Playbook, Simulation, Report, Payload)
- ✅ `database.py` - Setup SQLite com SessionLocal
- ✅ `auth.py` - Autenticação JWT + Password Hashing (bcrypt)
- ✅ `app_fastapi_v2.py` - 35+ endpoints com autenticação por usuário

#### Frontend (React)
- ✅ `Login.jsx` - Autenticação e registro
- ✅ `App.jsx` - Atualizado com proteção de rotas
- ✅ Todas as páginas integradas com API

#### Banco de Dados
- ✅ SQLite local (`penteia_lab.db`)
- ✅ Isolamento de dados por usuário
- ✅ Relacionamentos entre entidades

---

## 🚀 Como Iniciar (Passo a Passo)

### 1. Instalar Dependências
```bash
cd E:\cyber\PenteIA-V3.0
pip install -r requirements.txt
```

### 2. Iniciar Backend (FastAPI)
```bash
# Usando o novo arquivo com autenticação
uvicorn app_fastapi_v2:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Iniciar Frontend (React)
Em outro terminal:
```bash
cd E:\cyber\PenteIA-V3.0\frontend
npm run dev
```

O frontend abrirá em: `http://localhost:5173`

### 4. Primeiro Acesso
1. Clique em "Criar conta" 
2. Preencha: usuário, email, senha
3. Sistema cria usuário automaticamente no banco
4. JWT token é salvo em localStorage
5. Redireciona para dashboard

---

## 📊 Endpoints Implementados

### Autenticação
- `POST /api/auth/register` - Criar conta
- `POST /api/auth/login` - Fazer login
- `GET /api/auth/me` - Info do usuário autenticado

### C2 Framework (13 endpoints)
- `GET /api/c2/listeners` - Listar listeners do usuário
- `POST /api/c2/listeners` - Criar listener
- `DELETE /api/c2/listeners/{id}` - Deletar
- `GET /api/c2/beacons` - Listar beacons
- `POST /api/c2/beacons` - Registrar beacon
- `POST /api/c2/beacons/{id}/command` - Enviar comando
- `PUT /api/c2/beacons/{id}` - Atualizar status

### BAS Engine (8 endpoints)
- `GET /api/bas/playbooks` - Listar playbooks
- `POST /api/bas/playbooks` - Criar playbook
- `DELETE /api/bas/playbooks/{id}` - Deletar
- `POST /api/bas/execute` - Executar simulação
- `GET /api/bas/simulations` - Listar simulações
- `POST /api/bas/simulations/{id}/results` - Salvar resultados

### Reporting (5 endpoints)
- `POST /api/reporting/generate` - Gerar relatório
- `GET /api/reporting/reports` - Listar relatórios
- `DELETE /api/reporting/reports/{id}` - Deletar

### Evasion (5 endpoints)
- `POST /api/evasion/payloads` - Upload de payload
- `GET /api/evasion/payloads` - Listar payloads
- `DELETE /api/evasion/payloads/{id}` - Deletar

### DDoS Testing (6 endpoints)
- `POST /api/ddos/start` - Iniciar teste
- `GET /api/ddos/methods` - Métodos disponíveis
- `GET /api/ddos/status/{id}` - Status do teste
- `POST /api/ddos/stop/{id}` - Parar teste

### Recon (2 endpoints)
- `POST /api/recon/resolve` - Resolver domínio
- `POST /api/recon/scan` - Escanear portas

### Sistema (2 endpoints)
- `GET /api/health` - Health check
- `GET /api/modules/status` - Status dos módulos

---

## 🔐 Segurança

### Autenticação
- JWT token com expiração 24h
- Senha com bcrypt (10 rounds)
- Bearer token no header

### Isolamento de Dados
Cada usuário vê APENAS seus dados:
- Listeners criados por ele
- Beacons registrados
- Playbooks customizados
- Simulações executadas
- Relatórios gerados
- Payloads uploadados

### Autorização
Todos os endpoints verificam:
```python
current_user: User = Depends(get_current_user)
```

---

## 💾 Banco de Dados

### Localização
`E:\cyber\PenteIA-V3.0\penteia_lab.db` (SQLite)

### Tabelas
1. **users** - Usuários do sistema
2. **listeners** - C2 Listeners por usuário
3. **beacons** - Beacons conectados
4. **playbooks** - Playbooks BAS
5. **simulations** - Resultados de simulações
6. **reports** - Relatórios gerados
7. **payloads** - Payloads de evasão

### Backup
```bash
# Backup manual
copy penteia_lab.db penteia_lab.backup.db

# Ou use git para versionamento
```

---

## 🧪 Teste Rápido

### 1. Registrar Usuário 1
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"pesquisador1","email":"p1@lab.com","password":"senha123"}'
```

### 2. Registrar Usuário 2
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"pesquisador2","email":"p2@lab.com","password":"senha123"}'
```

### 3. Login como P1
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"pesquisador1","password":"senha123"}'
```

Salvar token retornado.

### 4. Criar Listener (como P1)
```bash
curl -X POST "http://localhost:8000/api/c2/listeners?name=L1&host=192.168.1.100&port=443&protocol=HTTPS" \
  -H "Authorization: Bearer TOKEN_AQUI"
```

### 5. Listar Listeners (só vê L1)
```bash
curl -X GET http://localhost:8000/api/c2/listeners \
  -H "Authorization: Bearer TOKEN_P1"
```

P2 não verá L1 (isolamento de dados).

---

## 📈 Próximos Passos (Opcional)

### Produção
- [ ] Migrar para PostgreSQL
- [ ] Adicionar HTTPS (Let's Encrypt)
- [ ] Setup Docker + docker-compose
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Rate limiting (slowapi)
- [ ] CORS refinado (especificar origins)

### Features Adicionais
- [ ] WebSocket para updates real-time
- [ ] Audit logs (quem fez o quê)
- [ ] 2FA (TOTP)
- [ ] Roles (admin, researcher, viewer)
- [ ] API keys para automação

---

## 🐛 Troubleshooting

### "Port 8000 já em uso"
```bash
# Kill processo
lsof -i :8000
kill -9 PID

# Ou use porta diferente
uvicorn app_fastapi_v2:app --port 8001
```

### "Database locked"
Feche outros terminais/IDEs usando o banco.

### "Token expirado"
Faça login novamente. Novo token é retornado.

### "Unauthorized 401"
Verifique se o Bearer token está no header:
```
Authorization: Bearer eyJhbGc...
```

---

## 📝 Notas Importantes

1. **Senha padrão na demo**: Mude em produção (trocar SECRET_KEY em auth.py)
2. **Banco de dados**: SQLite é local, perde dados se deletar `penteia_lab.db`
3. **CORS**: Aberto para `*` em dev. Restrict em produção
4. **SSL/TLS**: Não configurado em dev. Necessário em produção

---

**Status**: ✅ 100% Funcional para Laboratório
**Múltiplos Usuários**: ✅ Totalmente Isolado
**Data Persistence**: ✅ SQLite Local
