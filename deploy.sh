#!/bin/bash
# ============================================================
# PenteIA V4.0 — Deploy Script
# Uso: bash deploy.sh
# Requerimentos: Docker 24+, Docker Compose v2, git
# ============================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  PenteIA V4.0 — Deploy de Produção${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── 1. Checar Docker ─────────────────────────────────────────
echo -e "${YELLOW}[1/7] Verificando Docker...${NC}"
if ! command -v docker &>/dev/null; then
    echo -e "${RED}Docker não encontrado. Instalando...${NC}"
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker $USER
fi
docker --version
docker compose version
echo -e "${GREEN}✓ Docker OK${NC}"

# ── 2. Configurar .env ───────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/7] Configurando variáveis de ambiente...${NC}"
if [ ! -f .env ]; then
    cp .env.example .env
    SECRET=$(openssl rand -hex 32)
    sed -i "s/troque-por-uma-chave-secreta-forte-aqui/$SECRET/" .env
    echo -e "${GREEN}✓ .env criado com SECRET_KEY aleatória${NC}"
    echo ""
    echo -e "${RED}ATENÇÃO: Adicione sua ANTHROPIC_API_KEY no arquivo .env${NC}"
    echo -e "  ${CYAN}nano .env${NC}"
    read -p "Pressione ENTER após adicionar a chave (ou CTRL+C para cancelar)..."
else
    echo -e "${GREEN}✓ .env já existe${NC}"
fi

# Validar que ANTHROPIC_API_KEY está preenchida
if grep -q "^ANTHROPIC_API_KEY=sk-ant" .env; then
    echo -e "${GREEN}✓ ANTHROPIC_API_KEY presente${NC}"
else
    echo -e "${YELLOW}⚠ ANTHROPIC_API_KEY não configurada — AI Scenarios ficará inativo${NC}"
fi

# ── 3. Criar estrutura de dados ──────────────────────────────
echo ""
echo -e "${YELLOW}[3/7] Criando estrutura de diretórios...${NC}"
mkdir -p uploads evidence logs
chmod 755 uploads evidence logs
echo -e "${GREEN}✓ Diretórios criados${NC}"

# ── 4. Build das imagens ─────────────────────────────────────
echo ""
echo -e "${YELLOW}[4/7] Buildando imagens Docker...${NC}"
docker compose -f docker-compose.prod.yml build --no-cache
echo -e "${GREEN}✓ Build concluído${NC}"

# ── 5. Subir serviços ────────────────────────────────────────
echo ""
echo -e "${YELLOW}[5/7] Iniciando serviços...${NC}"
docker compose -f docker-compose.prod.yml up -d
echo -e "${GREEN}✓ Serviços iniciados${NC}"

# ── 6. Aguardar healthcheck ──────────────────────────────────
echo ""
echo -e "${YELLOW}[6/7] Aguardando API ficar pronta...${NC}"
MAX_WAIT=60
WAITED=0
until curl -sf http://localhost:8000/api/health > /dev/null 2>&1; do
    if [ $WAITED -ge $MAX_WAIT ]; then
        echo -e "${RED}✗ Timeout: API não respondeu em ${MAX_WAIT}s${NC}"
        echo "Logs da API:"
        docker compose -f docker-compose.prod.yml logs api --tail=30
        exit 1
    fi
    echo -n "."
    sleep 2
    WAITED=$((WAITED+2))
done
echo ""
echo -e "${GREEN}✓ API respondendo${NC}"

# ── 7. Teste rápido ──────────────────────────────────────────
echo ""
echo -e "${YELLOW}[7/7] Executando teste de sanidade...${NC}"
HEALTH=$(curl -sf http://localhost:8000/api/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "ok")
echo -e "${GREEN}✓ Health: ${HEALTH}${NC}"

TOKEN=$(curl -sf -X POST http://localhost:8000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','FAIL'))" 2>/dev/null || echo "FAIL")

if [[ "$TOKEN" == FAIL* ]]; then
    echo -e "${RED}✗ Login falhou${NC}"
else
    echo -e "${GREEN}✓ Login admin OK${NC}"
fi

# ── Resumo ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  DEPLOY CONCLUÍDO!${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Frontend:  ${CYAN}http://$(curl -sf ifconfig.me 2>/dev/null || echo 'SEU-IP')${NC}"
echo -e "  API:       ${CYAN}http://localhost:8000/api/health${NC}"
echo -e "  Docs:      ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  Login:     ${CYAN}admin / admin123${NC}"
echo ""
echo -e "${RED}  IMPORTANTE: Troque a senha admin em Configurações!${NC}"
echo ""
echo -e "  Logs:      ${CYAN}docker compose -f docker-compose.prod.yml logs -f${NC}"
echo -e "  Parar:     ${CYAN}docker compose -f docker-compose.prod.yml down${NC}"
echo -e "  Testes:    ${CYAN}python3 test_all_endpoints.py --base-url http://localhost:8000${NC}"
echo ""
