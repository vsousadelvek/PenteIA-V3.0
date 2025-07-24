#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PenteIA - Scanner de Vulnerabilidades com IA

Este script utiliza um modelo de inteligência artificial treinado para detectar
vulnerabilidades em aplicações web através da análise de respostas HTTP.

###############################################################################
#                               AVISO ÉTICO                                    #
###############################################################################
# Este software deve ser usado APENAS para fins éticos e legais.              #
# Use SOMENTE em sistemas que você tem PERMISSÃO EXPLÍCITA para testar.       #
# O uso indevido desta ferramenta pode violar leis e regulamentos.            #
# Os autores não se responsabilizam pelo uso indevido ou ilegal desta         #
# ferramenta. Ao usar este software, você assume total responsabilidade       #
# pelas suas ações.                                                           #
###############################################################################
"""

import os
import sys
import time
import json
import random
import argparse
import warnings
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin, urlunparse, urlencode

import numpy as np
import requests
from bs4 import BeautifulSoup
import tensorflow as tf
from colorama import init, Fore, Style
from tqdm import tqdm

# Inicializa colorama para cores no terminal
init(autoreset=True)

# Constantes globais
MAX_LENGTH = 2000
PROBABILITY_THRESHOLD = 0.8
TEMP_FOLDER = "temp_scan"
SESSION = requests.Session()
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PenteIA-Scanner/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3"
}

def load_config():
    """Carrega a configuração com os payloads de teste"""
    try:
        # Primeiro tenta carregar do config.json
        with open("config.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        # Se não encontrar, usa configuração padrão
        return {
            "payloads": {
                "sqli": [
                    "' or 1=1--",
                    "1' UNION SELECT 1,2,3--",
                    "admin' --"
                ],
                "xss": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(2)>",
                    "<svg onload=alert('XSS')>"
                ],
                "cmd_injection": [
                    "127.0.0.1; ls",
                    "$(whoami)",
                    "`id`"
                ],
                "nosqli": [
                    "{'$gt':''}",
                    "email={\"$regex\":\"admin\"}&password[\"$ne\"]="
                ]
            },
            "headers": HEADERS,
            "timeout": 10
        }

def load_artefacts():
    """Carrega o modelo treinado e o tokenizer"""
    try:
        print(f"{Fore.BLUE}[*] Carregando modelo e tokenizer...")

        # Verifica se os arquivos existem
        model_path = os.path.join("modelos", "penteia_model.h5")
        tokenizer_path = os.path.join("modelos", "tokenizer.json")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Modelo não encontrado em {model_path}")

        if not os.path.exists(tokenizer_path):
            raise FileNotFoundError(f"Tokenizer não encontrado em {tokenizer_path}")

        # Suprime avisos do TensorFlow
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model = tf.keras.models.load_model(model_path)

        # Carrega o tokenizer
        with open(tokenizer_path, 'r') as f:
            tokenizer_config = json.load(f)

        # Recria o tokenizer a partir da configuração
        tokenizer = tf.keras.preprocessing.text.tokenizer_from_json(json.dumps(tokenizer_config))

        print(f"{Fore.GREEN}[+] Modelo e tokenizer carregados com sucesso!")
        return model, tokenizer

    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao carregar o modelo ou tokenizer: {str(e)}")
        print(f"{Fore.YELLOW}[!] Verifique se você treinou o modelo e se os arquivos estão no diretório 'modelos/'")
        sys.exit(1)

def preprocess_text(text, tokenizer, max_length=MAX_LENGTH):
    """Pré-processa o texto HTML para classificação"""
    # Converte para string, caso seja None ou outro tipo
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)

    # Tokeniza o texto
    sequences = tokenizer.texts_to_sequences([text])

    # Aplica padding para garantir tamanho uniforme
    padded_sequences = tf.keras.preprocessing.sequence.pad_sequences(
        sequences,
        maxlen=max_length,
        padding='post',
        truncating='post'
    )

    return padded_sequences

def extract_links_and_forms(html, base_url):
    """Extrai todos os links e formulários da página HTML"""
    links = []
    forms = []

    try:
        soup = BeautifulSoup(html, 'html.parser')

        # Extrai todos os links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            # Ignora links de âncora, javascript e mailto
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue

            # Normaliza URL relativa para absoluta
            full_url = urljoin(base_url, href)

            # Adiciona apenas se for do mesmo domínio
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                links.append(full_url)

        # Extrai todos os formulários
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }

            # Extrai os campos do formulário
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_type = input_field.get('type', '')
                input_name = input_field.get('name', '')

                # Ignora botões e campos sem nome
                if not input_name or input_type in ['submit', 'button', 'image']:
                    continue

                input_value = input_field.get('value', '')
                form_data['inputs'].append({
                    'name': input_name,
                    'value': input_value,
                    'type': input_type
                })

            forms.append(form_data)

        return links, forms

    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao analisar HTML: {str(e)}")
        return [], []

def generate_test_urls(url, payloads):
    """Gera URLs de teste com os payloads"""
    test_urls = []
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Se não há parâmetros, retorna a URL original
    if not query_params:
        return [url]

    # Para cada parâmetro, testa cada payload
    for param, values in query_params.items():
        for payload in payloads:
            # Cria uma cópia dos parâmetros originais
            new_params = parse_qs(parsed_url.query)
            # Substitui o valor do parâmetro atual pelo payload
            new_params[param] = [payload]

            # Reconstrói a URL com o novo parâmetro
            new_query = urlencode(new_params, doseq=True)
            new_parsed = parsed_url._replace(query=new_query)
            test_urls.append(urlunparse(new_parsed))

    return test_urls

def test_form_with_payloads(form, payloads, session):
    """Testa um formulário com os payloads fornecidos"""
    results = []
    action_url = form['action']
    method = form['method']

    # Para cada campo do formulário, testa cada payload
    for input_field in form['inputs']:
        field_name = input_field['name']

        # Ignora campos hidden, podem ser tokens CSRF
        if input_field['type'] == 'hidden':
            continue

        for payload in payloads:
            # Cria dados do formulário com valores padrão
            form_data = {}
            for inp in form['inputs']:
                if inp['name'] != field_name:
                    form_data[inp['name']] = inp['value']
                else:
                    form_data[inp['name']] = payload

            try:
                # Envia a requisição com o payload
                if method == 'post':
                    response = session.post(action_url, data=form_data, headers=HEADERS, timeout=10)
                else:  # GET
                    response = session.get(action_url, params=form_data, headers=HEADERS, timeout=10)

                results.append({
                    'url': action_url,
                    'method': method,
                    'field': field_name,
                    'payload': payload,
                    'status_code': response.status_code,
                    'content_length': len(response.text),
                    'response_text': response.text
                })

            except Exception as e:
                print(f"{Fore.YELLOW}[!] Erro ao testar formulário {action_url}: {str(e)}")

    return results

def classify_vulnerability(text, model, tokenizer, url, payload=""):
    """Classifica o texto para detectar vulnerabilidades"""
    # Pré-processa o texto
    processed_text = preprocess_text(text, tokenizer)

    # Faz a predição
    prediction = model.predict(processed_text)[0][0]

    # Classifica a gravidade com base na probabilidade
    if prediction >= PROBABILITY_THRESHOLD:
        if prediction >= 0.95:
            severity = f"{Fore.RED}CRÍTICA"
        elif prediction >= 0.9:
            severity = f"{Fore.MAGENTA}ALTA"
        else:
            severity = f"{Fore.YELLOW}MÉDIA"

        # Tenta determinar o tipo de vulnerabilidade
        vuln_type = "Desconhecida"
        if "SQL syntax" in text or "mysql" in text.lower() or "union select" in payload.lower():
            vuln_type = "SQL Injection"
        elif "<script>" in payload or "onerror" in payload or "alert(" in payload:
            vuln_type = "Cross-Site Scripting (XSS)"
        elif "127.0.0.1" in payload and ("ls" in payload or "cat" in payload):
            vuln_type = "Command Injection"
        elif "$gt" in payload or "$ne" in payload:
            vuln_type = "NoSQL Injection"

        return {
            "vulnerable": True,
            "probability": float(prediction),
            "severity": severity,
            "type": vuln_type,
            "url": url,
            "payload": payload
        }

    return {"vulnerable": False, "probability": float(prediction)}

def display_banner():
    """Exibe o banner do scanner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║ {Fore.GREEN}██████╗ ███████╗███╗   ██╗████████╗███████╗██╗ █████╗     {Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██║██╔══██╗    {Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ██║███████║    {Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██║██╔══██║    {Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}██║     ███████╗██║ ╚████║   ██║   ███████╗██║██║  ██║    {Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝╚═╝  ╚═╝    {Fore.CYAN}║
{Fore.CYAN}║ {Fore.YELLOW}SCANNER DE VULNERABILIDADES COM INTELIGÊNCIA ARTIFICIAL   {Fore.CYAN}║
{Fore.CYAN}║ {Fore.YELLOW}v1.0                                                      {Fore.CYAN}║
{Fore.CYAN}╚═══════════════════════════════════════════════════════════════════════╝
{Fore.RED}⚠️  PARA USO ÉTICO E AUTORIZADO APENAS - USE COM RESPONSABILIDADE
"""
    print(banner)

def scan_page(url, model, tokenizer, config):
    """Escaneia uma página em busca de vulnerabilidades"""
    try:
        print(f"\n{Fore.BLUE}[*] Iniciando escaneamento da URL: {url}")
        print(f"{Fore.BLUE}[*] Acessando a página...")

        # Faz a requisição inicial para a página
        response = SESSION.get(url, headers=HEADERS, timeout=config.get('timeout', 10))
        response.raise_for_status()

        # Extrai links e formulários
        print(f"{Fore.BLUE}[*] Analisando estrutura da página...")
        links, forms = extract_links_and_forms(response.text, url)
        print(f"{Fore.GREEN}[+] Encontrados {len(links)} links e {len(forms)} formulários")

        # Lista para armazenar resultados
        vulnerabilities = []
        total_tests = 0

        # Testa a própria URL principal com payloads
        all_payloads = []
        for category, payloads in config['payloads'].items():
            all_payloads.extend(payloads)

        test_urls = generate_test_urls(url, all_payloads)
        total_tests += len(test_urls)

        print(f"{Fore.BLUE}[*] Testando {len(test_urls)} variações da URL principal...")
        for test_url in tqdm(test_urls, desc="URLs", leave=False):
            try:
                test_response = SESSION.get(test_url, headers=HEADERS, timeout=config.get('timeout', 10))
                # Identifica o payload utilizado
                payload = urlparse(test_url).query.split('=')[1] if '=' in urlparse(test_url).query else ""

                # Classifica a resposta
                result = classify_vulnerability(test_response.text, model, tokenizer, test_url, payload)
                if result["vulnerable"]:
                    vulnerabilities.append(result)
                    # Exibe alerta imediato
                    print(f"\n{result['severity']} VULNERABILIDADE DETECTADA!")
                    print(f"  URL: {test_url}")
                    print(f"  Tipo: {result['type']}")
                    print(f"  Confiança: {result['probability']*100:.2f}%")
                    print(f"  Payload: {payload}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Erro ao testar {test_url}: {str(e)}")

        # Testa até 5 links encontrados na página
        sample_links = random.sample(links, min(5, len(links)))
        print(f"{Fore.BLUE}[*] Testando {len(sample_links)} links encontrados na página...")

        for link in tqdm(sample_links, desc="Links", leave=False):
            test_urls = generate_test_urls(link, all_payloads)
            total_tests += len(test_urls)

            for test_url in test_urls:
                try:
                    test_response = SESSION.get(test_url, headers=HEADERS, timeout=config.get('timeout', 10))
                    # Identifica o payload utilizado
                    payload = urlparse(test_url).query.split('=')[1] if '=' in urlparse(test_url).query else ""

                    # Classifica a resposta
                    result = classify_vulnerability(test_response.text, model, tokenizer, test_url, payload)
                    if result["vulnerable"]:
                        vulnerabilities.append(result)
                        # Exibe alerta imediato
                        print(f"\n{result['severity']} VULNERABILIDADE DETECTADA!")
                        print(f"  URL: {test_url}")
                        print(f"  Tipo: {result['type']}")
                        print(f"  Confiança: {result['probability']*100:.2f}%")
                        print(f"  Payload: {payload}")
                except Exception as e:
                    pass  # Silencia erros em links secundários

        # Testa formulários
        print(f"{Fore.BLUE}[*] Testando {len(forms)} formulários...")

        for form in tqdm(forms, desc="Formulários", leave=False):
            form_results = test_form_with_payloads(form, all_payloads, SESSION)
            total_tests += len(form_results)

            for result_data in form_results:
                # Classifica a resposta
                result = classify_vulnerability(
                    result_data['response_text'],
                    model,
                    tokenizer,
                    f"{result_data['url']} ({result_data['method']} - {result_data['field']})",
                    result_data['payload']
                )

                if result["vulnerable"]:
                    vulnerabilities.append(result)
                    # Exibe alerta imediato
                    print(f"\n{result['severity']} VULNERABILIDADE DETECTADA!")
                    print(f"  Formulário: {result_data['url']} (método {result_data['method']})")
                    print(f"  Campo: {result_data['field']}")
                    print(f"  Tipo: {result['type']}")
                    print(f"  Confiança: {result['probability']*100:.2f}%")
                    print(f"  Payload: {result_data['payload']}")

        # Exibe resumo
        print(f"\n{Fore.GREEN}[+] Escaneamento concluído!")
        print(f"{Fore.BLUE}[*] Total de testes realizados: {total_tests}")
        print(f"{Fore.BLUE}[*] Vulnerabilidades encontradas: {len(vulnerabilities)}")

        # Salva relatório
        if vulnerabilities:
            save_report(url, vulnerabilities, total_tests)

        return vulnerabilities

    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao escanear a página {url}: {str(e)}")
        return []

def save_report(url, vulnerabilities, total_tests):
    """Salva o relatório de vulnerabilidades em um arquivo JSON"""
    try:
        # Cria o diretório de relatórios se não existir
        os.makedirs("relatorios", exist_ok=True)

        # Nome do arquivo baseado na URL e timestamp
        domain = urlparse(url).netloc.replace(".", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"relatorios/penteia_scan_{domain}_{timestamp}.json"

        # Prepara o relatório
        report = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "total_tests": total_tests,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

        # Salva o relatório em JSON
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"{Fore.GREEN}[+] Relatório salvo em: {filename}")

    except Exception as e:
        print(f"{Fore.YELLOW}[!] Erro ao salvar relatório: {str(e)}")

def main():
    """Função principal"""
    # Configura o parser de argumentos
    parser = argparse.ArgumentParser(description='PenteIA Scanner - Detector de vulnerabilidades com IA')
    parser.add_argument('--url', '-u', required=True, help='URL alvo para escaneamento')
    parser.add_argument('--auth', '-a', help='Arquivo JSON com credenciais de autenticação')
    parser.add_argument('--threshold', '-t', type=float, default=0.8, help='Limiar de probabilidade (0.0-1.0)')
    parser.add_argument('--config', '-c', help='Arquivo de configuração personalizado')

    # Analisa os argumentos
    args = parser.parse_args()

    # Ajusta o limiar global
    global PROBABILITY_THRESHOLD
    PROBABILITY_THRESHOLD = args.threshold

    # Exibe o banner
    display_banner()

    # Carrega a configuração
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    else:
        config = load_config()

    # Carrega o modelo e o tokenizer
    model, tokenizer = load_artefacts()

    # Autenticação se necessário
    if args.auth:
        try:
            with open(args.auth, 'r') as f:
                auth_config = json.load(f)

            print(f"{Fore.BLUE}[*] Autenticando no alvo...")

            # Processo de autenticação básico
            auth_url = auth_config.get("login_url")
            auth_data = {
                auth_config.get("username_field", "username"): auth_config.get("username"),
                auth_config.get("password_field", "password"): auth_config.get("password")
            }

            response = SESSION.post(auth_url, data=auth_data, headers=HEADERS)

            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Autenticação bem-sucedida!")
            else:
                print(f"{Fore.YELLOW}[!] A autenticação pode ter falhado. Código: {response.status_code}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro durante a autenticação: {str(e)}")
            print(f"{Fore.YELLOW}[!] Continuando sem autenticação...")

    # Inicia o escaneamento
    start_time = time.time()
    vulnerabilities = scan_page(args.url, model, tokenizer, config)
    end_time = time.time()

    # Exibe o resumo final
    print(f"\n{Fore.BLUE}═════════════════════ RESUMO FINAL ═════════════════════")
    print(f"{Fore.GREEN}[+] URL escaneada: {args.url}")
    print(f"{Fore.GREEN}[+] Tempo de execução: {end_time - start_time:.2f} segundos")
    print(f"{Fore.GREEN}[+] Total de vulnerabilidades: {len(vulnerabilities)}")

    if vulnerabilities:
        print(f"\n{Fore.YELLOW}Vulnerabilidades encontradas:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n{Fore.YELLOW}[{i}] {vuln['type']} - {vuln['severity']}")
            print(f"  {Fore.BLUE}URL: {vuln['url']}")
            print(f"  {Fore.BLUE}Payload: {vuln['payload']}")
            print(f"  {Fore.BLUE}Confiança: {vuln['probability']*100:.2f}%")
    else:
        print(f"\n{Fore.GREEN}[+] Nenhuma vulnerabilidade detectada com o limiar atual ({PROBABILITY_THRESHOLD*100:.0f}%)")

    print(f"\n{Fore.BLUE}═════════════════════════════════════════════════════════")
    print(f"{Fore.YELLOW}Utilize os resultados com responsabilidade e apenas para fins éticos.")
    print(f"{Fore.YELLOW}Recomendamos validar manualmente todas as vulnerabilidades encontradas.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Escaneamento interrompido pelo usuário.")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro inesperado: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        print(f"\n{Fore.GREEN}[+] Encerrando PenteIA Scanner. Obrigado por utilizar!")
