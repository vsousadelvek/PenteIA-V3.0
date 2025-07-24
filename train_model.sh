#!/bin/bash

echo "===== PenteIA - Assistente de Treinamento de Modelo ====="
echo ""

echo "Escolha uma opção:"
echo "1. Coletar dados e treinar modelo real"
echo "2. Treinar modelo com dados existentes"
echo "3. Usar modelo de demonstração"
echo "4. Sair"
echo ""
read -p "Escolha uma opção (1-4): " escolha

case $escolha in
    1)
        echo ""
        echo "=== COLETANDO DADOS PARA TREINAMENTO ==="
        echo ""
        python collect_vulns.py
        echo ""
        echo "=== TREINANDO MODELO ==="
        echo ""
        python treinar_modelo_real.py
        ;;
    2)
        echo ""
        echo "=== TREINANDO MODELO COM DADOS EXISTENTES ==="
        echo ""
        python treinar_modelo_real.py
        ;;
    3)
        echo ""
        echo "=== CRIANDO MODELO DE DEMONSTRAÇÃO ==="
        echo ""
        python criar_modelo_demo.py
        ;;
    4)
        echo "Saindo..."
        exit 0
        ;;
    *)
        echo "Opção inválida."
        ;;
esac

echo ""
echo "Operação concluída."
echo ""
read -p "Pressione ENTER para sair..."
