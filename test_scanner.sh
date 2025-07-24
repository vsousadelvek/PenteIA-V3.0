#!/bin/bash

echo "===== PenteIA Scanner - Ferramenta de Teste ====="
echo ""

while true; do
    echo "Selecione um alvo para testar:"
    echo "1. DVWA Local (http://localhost/DVWA/)"
    echo "2. OWASP Juice Shop (http://localhost:3000/)"
    echo "3. WebGoat (http://localhost:8080/WebGoat/)"
    echo "4. URL personalizada"
    echo "5. Sair"
    echo ""
    read -p "Escolha uma opção (1-5): " escolha

    case $escolha in
        1)
            echo ""
            echo "Testando DVWA..."
            python scanner.py --url http://localhost/DVWA/ --auth auth_dvwa.json
            break
            ;;
        2)
            echo ""
            echo "Testando OWASP Juice Shop..."
            python scanner.py --url http://localhost:3000/ --config exemplos/config_juiceshop.json
            break
            ;;
        3)
            echo ""
            echo "Testando WebGoat..."
            python scanner.py --url http://localhost:8080/WebGoat/ --config exemplos/config_webgoat.json
            break
            ;;
        4)
            echo ""
            read -p "Digite a URL completa para testar: " url
            echo ""
            read -p "Deseja usar autenticação? (S/N): " auth

            if [[ $auth == "S" || $auth == "s" ]]; then
                python scanner.py --url "$url" --auth auth_dvwa.json
            else
                python scanner.py --url "$url"
            fi
            break
            ;;
        5)
            echo "Saindo..."
            exit 0
            ;;
        *)
            echo "Opção inválida. Tente novamente."
            ;;
    esac
done

echo ""
echo "Teste concluído."
echo ""
read -p "Pressione ENTER para sair..."
