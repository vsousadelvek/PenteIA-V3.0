#!/bin/bash
#
# setup_dvwa.sh - Sobe um ambiente DVWA (Damn Vulnerable Web Application) em Docker
# para uso como alvo de TESTE do PenteIA.
#
# Uso:
#   chmod +x setup_dvwa.sh
#   ./setup_dvwa.sh
#
# Após subir, acesse: http://localhost/  (login: admin / senha: password)
# Para parar:  docker stop dvwa  &&  docker rm dvwa
#
# AVISO: o DVWA é intencionalmente vulnerável. NUNCA o exponha à internet.

set -e

CONTAINER_NAME="dvwa"
IMAGE="vulnerables/web-dvwa"
PORT="80"

echo "===== PenteIA - Setup do ambiente de teste DVWA ====="

if ! command -v docker >/dev/null 2>&1; then
    echo "[!] Docker não encontrado. Instale o Docker primeiro: https://docs.docker.com/get-docker/"
    exit 1
fi

# Remove um container anterior com o mesmo nome, se existir
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "[*] Removendo container '${CONTAINER_NAME}' existente..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
fi

echo "[*] Baixando a imagem ${IMAGE} (pode demorar na primeira vez)..."
docker pull "${IMAGE}"

echo "[*] Iniciando o DVWA na porta ${PORT}..."
docker run -d -p ${PORT}:80 --name "${CONTAINER_NAME}" "${IMAGE}"

echo ""
echo "[+] DVWA iniciado com sucesso!"
echo "    URL:    http://localhost/"
echo "    Login:  admin"
echo "    Senha:  password"
echo ""
echo "    1) Acesse a URL acima e clique em 'Create / Reset Database'."
echo "    2) Em 'DVWA Security', selecione o nível 'Low'."
echo "    3) Rode o coletor:  python data_collector.py"
echo ""
echo "    Para parar:  docker stop ${CONTAINER_NAME} && docker rm ${CONTAINER_NAME}"
