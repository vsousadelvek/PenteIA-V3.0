#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script para baixar e processar dados de vulnerabilidades web

Este script automatiza o download de dados de vulnerabilidades públicas
das seguintes fontes:
- OWASP ModSecurity Core Rule Set (CRS)
- PayloadsAllTheThings (SQL Injection, XSS, Command Injection, etc.)

Os dados são processados e salvos para uso no treinamento de modelos.
"""

import os
import re
import sys
import yaml
import json
import time
import shutil
import requests
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from tqdm import tqdm
from colorama import init, Fore, Style
from urllib.parse import urlparse

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
DOWNLOAD_DIR = "dados_externos"
CACHE_DIR = os.path.join(DOWNLOAD_DIR, "cache")
OUTPUT_DIR = "dados_treinamento"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "dados_vulnerabilidades.csv")

# URLs para download
REPOS = {
    "OWASP ModSecurity CRS": {
        "base_url": "https://github.com/coreruleset/coreruleset",
        "repo": "coreruleset/coreruleset",
        "ref": "main",
        "test_path": "tests/regression/tests",
        "rules": [
            "REQUEST-920-PROTOCOL-ENFORCEMENT",
            "REQUEST-921-PROTOCOL-ATTACK",
            "REQUEST-930-APPLICATION-ATTACK-LFI",
            "REQUEST-931-APPLICATION-ATTACK-RFI",
            "REQUEST-932-APPLICATION-ATTACK-RCE",
            "REQUEST-933-APPLICATION-ATTACK-PHP",
            "REQUEST-941-APPLICATION-ATTACK-XSS",
            "REQUEST-942-APPLICATION-ATTACK-SQLI",
            "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION",
            "REQUEST-944-APPLICATION-ATTACK-JAVA"
        ]
    },
    "PayloadsAllTheThings-SQLi": {
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md"
    },
    "PayloadsAllTheThings-XSS": {
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md"
    },
    "PayloadsAllTheThings-Command": {
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md"
    },
    "PayloadsAllTheThings-LFI": {
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/README.md"
    },
    "PayloadsAllTheThings-NoSQLi": {
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/README.md"
    },
    "PayloadsAllTheThings-XPATH": {
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XPATH%20Injection/README.md"
    }
}

def configurar_parser():
    """
    Configura o parser de argumentos de linha de comando
    """
    parser = argparse.ArgumentParser(description='Downloader de dados de vulnerabilidades para treinamento')
    parser.add_argument('--skip-download', '-s', action='store_true', help='Pular download e usar cache')
    parser.add_argument('--force', '-f', action='store_true', help='Forçar download mesmo com cache')
    parser.add_argument('--output', '-o', type=str, default=OUTPUT_FILE, help='Arquivo de saída')
    parser.add_argument('--source', type=str, choices=list(REPOS.keys()) + ['all'], default='all',
                        help='Fonte específica para download (default: todas)')
    return parser

def baixar_arquivo(url, destino, descricao=None):
    """
    Baixa um arquivo da web e salva no destino especificado
    """
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()

        # Obtém o tamanho do arquivo
        total_length = int(response.headers.get('content-length', 0))

        # Cria o diretório de destino se não existir
        os.makedirs(os.path.dirname(destino), exist_ok=True)

        # Faz o download com barra de progresso
        with open(destino, 'wb') as f:
            if total_length > 0:
                desc = descricao if descricao else os.path.basename(url)
                with tqdm(total=total_length, unit='B', unit_scale=True, desc=desc) as pbar:
                    for chunk in response.iter_content(chunk_size=4096):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
            else:
                f.write(response.content)

        return True
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao baixar {url}: {str(e)}")
        return False

def _extrair_payload_do_teste(test):
    """Extrai um payload textual de um teste de regressão do CRS."""
    try:
        entrada = test['stages'][0]['input']
    except Exception:
        try:
            # Formato alternativo: test['input']
            entrada = test['input']
        except Exception:
            return None
    if not isinstance(entrada, dict):
        return None
    # Campos que costumam conter o vetor de ataque
    for chave in ('data', 'uri', 'payload'):
        valor = entrada.get(chave)
        if isinstance(valor, str) and valor.strip():
            return valor.strip()
    return None


def baixar_owasp_crs(config, skip_cache=False):
    """
    Baixa os testes de regressão do OWASP ModSecurity CRS usando a API do GitHub
    para LISTAR os arquivos de cada regra (em vez de adivinhar nomes de arquivo).
    """
    print(f"{Fore.BLUE}[*] Baixando OWASP ModSecurity CRS (via GitHub API)...")

    cache_dir = os.path.join(CACHE_DIR, "owasp-crs")
    os.makedirs(cache_dir, exist_ok=True)

    resultados = []
    arquivos_processados = 0
    MAX_ARQUIVOS_POR_REGRA = 200  # limite de segurança

    repo = config.get("repo", "coreruleset/coreruleset")
    ref = config.get("ref", "main")
    api_base = f"https://api.github.com/repos/{repo}/contents"

    # Caminhos candidatos onde ficam os testes de regressão (a estrutura mudou entre versões)
    candidatos_path = [p.rstrip("/") for p in [
        config.get("test_path", ""),
        "tests/regression/tests",
        "regression-tests/tests",
    ] if p]

    headers_api = {"Accept": "application/vnd.github+json",
                   "User-Agent": "PenteIA-Downloader"}

    for rule in config['rules']:
        rule_dir = os.path.join(cache_dir, rule)
        os.makedirs(rule_dir, exist_ok=True)

        # 1) Lista os arquivos da regra
        listados = None
        for base_path in candidatos_path:
            api_url = f"{api_base}/{base_path}/{rule}?ref={ref}"
            try:
                r = requests.get(api_url, timeout=30, headers=headers_api)
                if r.status_code == 200:
                    listados = r.json()
                    break
                elif r.status_code == 403:
                    print(f"{Fore.YELLOW}[!] Limite de requisições da API do GitHub atingido. "
                          f"Pulando o restante do CRS.")
                    return resultados
            except Exception:
                continue

        if not listados or not isinstance(listados, list):
            print(f"{Fore.YELLOW}[!] Não foi possível listar testes de {rule}; pulando.")
            continue

        # 2) Filtra os arquivos YAML
        yaml_files = [it for it in listados
                      if isinstance(it, dict) and it.get("name", "").endswith((".yaml", ".yml"))]
        baixados_regra = 0

        for it in tqdm(yaml_files[:MAX_ARQUIVOS_POR_REGRA], desc=f"{rule}", ncols=80, leave=False):
            file_name = it["name"]
            file_path = os.path.join(rule_dir, file_name)
            download_url = it.get("download_url")

            # Usa cache quando possível
            if not (os.path.exists(file_path) and not skip_cache):
                if not download_url or not baixar_arquivo(download_url, file_path):
                    continue

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
            except Exception:
                continue

            if data and isinstance(data, dict) and 'tests' in data:
                tipo = detectar_tipo_vulnerabilidade(rule)
                for test in data['tests']:
                    payload = _extrair_payload_do_teste(test)
                    if payload:
                        resultados.append({
                            'payload': payload,
                            'tipo': tipo,
                            'fonte': 'owasp-crs',
                            'regra': rule
                        })
            baixados_regra += 1
            arquivos_processados += 1

        print(f"{Fore.GREEN}[+] {rule}: {baixados_regra} arquivos processados")

    print(f"{Fore.GREEN}[+] OWASP CRS: {arquivos_processados} arquivos, {len(resultados)} payloads extraídos")
    return resultados

def baixar_payloadsallthethings(fonte, config, skip_cache=False):
    """
    Baixa PayloadsAllTheThings
    """
    print(f"{Fore.BLUE}[*] Baixando {fonte}...")

    url = config['url']
    tipo = fonte.replace('PayloadsAllTheThings-', '').lower()

    # Define o tipo de vulnerabilidade com base no nome do repositório
    if 'sqli' in tipo.lower():
        tipo_vuln = 'sqli'
    elif 'xss' in tipo.lower():
        tipo_vuln = 'xss'
    elif 'command' in tipo.lower() or 'rce' in tipo.lower():
        tipo_vuln = 'cmd_injection'
    elif 'nosql' in tipo.lower():
        tipo_vuln = 'nosqli'
    elif 'lfi' in tipo.lower() or 'directory' in tipo.lower():
        tipo_vuln = 'lfi_rfi'
    elif 'xpath' in tipo.lower():
        tipo_vuln = 'xpath'
    else:
        tipo_vuln = 'outros'

    # Define o arquivo de cache
    cache_dir = os.path.join(CACHE_DIR, "payloads")
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{tipo}.md")

    # Verifica se o arquivo já existe no cache
    if os.path.exists(cache_file) and not skip_cache:
        return processar_markdown_payloads(cache_file, tipo_vuln, fonte)

    # Baixa o arquivo
    if baixar_arquivo(url, cache_file, fonte):
        return processar_markdown_payloads(cache_file, tipo_vuln, fonte)

    return []

def processar_markdown_payloads(arquivo, tipo, fonte):
    """
    Processa um arquivo markdown para extrair payloads
    """
    resultados = []
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            conteudo = f.read()

        # Expressão regular para encontrar blocos de código
        blocos = re.findall(r'```(?:[\w]*)[\r\n]([\s\S]*?)```', conteudo)
        linhas = conteudo.split('\n')

        # Processa blocos de código
        for bloco in blocos:
            # Divide o bloco em linhas
            for linha in bloco.split('\n'):
                linha = linha.strip()
                # Pula linhas de comentário ou vazias
                if not linha or linha.startswith('#') or linha.startswith('//') or '# ' in linha[:3]:
                    continue

                # Adiciona o payload à lista de resultados
                resultados.append({
                    'payload': linha,
                    'tipo': tipo,
                    'fonte': fonte,
                    'regra': 'payload-manual'
                })

        # Processa também linhas com exemplos de payloads que não estão em blocos de código
        for i, linha in enumerate(linhas):
            linha = linha.strip()
            if linha.startswith('- `') and '`' in linha[3:]:
                payload = linha[3:].split('`', 1)[0]
                resultados.append({
                    'payload': payload,
                    'tipo': tipo,
                    'fonte': fonte,
                    'regra': 'payload-inline'
                })

        print(f"{Fore.GREEN}[+] {fonte}: {len(resultados)} payloads extraídos")
        return resultados

    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao processar {arquivo}: {str(e)}")
        return []

def detectar_tipo_vulnerabilidade(regra):
    """
    Detecta o tipo de vulnerabilidade com base no nome da regra
    """
    regra = regra.lower()

    if 'sqli' in regra:
        return 'sqli'
    elif 'xss' in regra:
        return 'xss'
    elif 'rce' in regra or 'command' in regra:
        return 'cmd_injection'
    elif 'lfi' in regra:
        return 'lfi_rfi'
    elif 'rfi' in regra:
        return 'lfi_rfi'
    elif 'nosql' in regra:
        return 'nosqli'
    elif 'xpath' in regra:
        return 'xpath'
    else:
        return 'outros'

def salvar_resultados(resultados, arquivo_saida):
    """
    Salva os resultados em um arquivo CSV
    """
    try:
        # Cria o diretório de saída se não existir
        os.makedirs(os.path.dirname(arquivo_saida), exist_ok=True)

        # Converte para DataFrame
        df = pd.DataFrame(resultados)

        # Remove duplicatas
        df = df.drop_duplicates(subset=['payload'])

        # Adiciona uma coluna com contexto para simulação
        df['contexto'] = 'Vulnerabilidade detectada'

        # Adiciona label (1 = vulnerável)
        df['label'] = 1

        # Adiciona texto simulado para compatibilidade com o formato de treinamento
        df['text'] = df.apply(lambda row: f"URL: example.com/?q={row['payload']}\nResponse: {row['contexto']}", axis=1)

        # Seleciona e renomeia colunas para compatibilidade
        df_final = df[['text', 'label', 'tipo', 'payload', 'fonte']]
        df_final = df_final.rename(columns={'tipo': 'tipo_payload'})

        # Salva em CSV
        df_final.to_csv(arquivo_saida, index=False)

        print(f"{Fore.GREEN}[+] Resultados salvos em {arquivo_saida}")
        print(f"{Fore.GREEN}[+] Total de payloads únicos: {len(df_final)}")

        # Estatísticas por tipo
        print(f"\n{Fore.BLUE}[*] Estatísticas por tipo de vulnerabilidade:")
        tipo_counts = df_final['tipo_payload'].value_counts()
        for tipo, count in tipo_counts.items():
            print(f"  - {tipo}: {count} payloads")

        return True
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao salvar resultados: {str(e)}")
        return False

def main():
    """
    Função principal
    """
    print(f"{Fore.CYAN}===== PenteIA - Download de Dados de Vulnerabilidades =====")
    print(f"{Fore.YELLOW}Este script baixa e processa dados de vulnerabilidades para treinamento.\n")

    # Processa argumentos de linha de comando
    parser = configurar_parser()
    args = parser.parse_args()

    # Cria diretórios necessários
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Lista de fontes para download
    fontes = [args.source] if args.source != 'all' else list(REPOS.keys())

    # Resultados combinados
    resultados_combinados = []

    try:
        # Para cada fonte
        for fonte in fontes:
            if fonte == 'OWASP ModSecurity CRS':
                resultados = baixar_owasp_crs(REPOS[fonte], skip_cache=args.force)
                resultados_combinados.extend(resultados)
            elif fonte.startswith('PayloadsAllTheThings'):
                resultados = baixar_payloadsallthethings(fonte, REPOS[fonte], skip_cache=args.force)
                resultados_combinados.extend(resultados)

        # Salva os resultados
        if resultados_combinados:
            salvar_resultados(resultados_combinados, args.output)
            print(f"\n{Fore.GREEN}[+] Download e processamento concluídos com sucesso!")
        else:
            print(f"\n{Fore.YELLOW}[!] Nenhum dado foi baixado ou processado.")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operação interrompida pelo usuário.")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro durante o processamento: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
