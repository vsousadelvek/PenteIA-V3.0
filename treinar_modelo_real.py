#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Treinamento do modelo PenteIA (motor scikit-learn).

Este script lê os dados rotulados produzidos pelo pipeline (coleta/processamento/
geração sintética), treina um classificador de texto (TF-IDF + Regressão Logística)
e salva o modelo pronto para uso pelo scanner.

Saídas:
- modelos/penteia_model.joblib   -> pipeline scikit-learn (vetorização + classificador)
- modelos/model_meta.json        -> metadados (versão, métricas, limiar padrão, etc.)

Observação: a versão anterior usava TensorFlow/Keras (LSTM). O motor foi migrado
para scikit-learn para rodar em CPU, sem dependências pesadas e compatível com
versões recentes do Python.
"""

import os
import sys
import json
import argparse
from datetime import datetime

import numpy as np
import pandas as pd

# Garante saída UTF-8 no terminal (evita erros no console do Windows / cp1252)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Imports opcionais (apenas para gráficos)
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    PLOTS_HABILITADOS = True
except Exception:
    PLOTS_HABILITADOS = False

# ------------------------------------------------------------------------------
# Configurações
# ------------------------------------------------------------------------------
MODEL_VERSION = "3.0-sklearn"
MODEL_DIR = "modelos"
MODEL_PATH = os.path.join(MODEL_DIR, "penteia_model.joblib")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")
RESULT_DIR = "resultados"

# Arquivos candidatos de treinamento, em ordem de preferência.
CANDIDATE_DATA_FILES = [
    os.path.join("dados_treinamento", "dados_processados.csv"),
    os.path.join("dados_treinamento", "dados_combinados.csv"),
    os.path.join("dados_treinamento", "training_data.csv"),
]
EXEMPLO_DATA_FILE = os.path.join("exemplos", "dados_exemplo.csv")

# Limiar padrão de decisão usado pelo scanner (probabilidade -> vulnerável)
DEFAULT_THRESHOLD = 0.8

# Parâmetros do vetorizador
MAX_FEATURES = 50000
NGRAM_RANGE = (1, 2)


def criar_diretorios():
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs("dados_treinamento", exist_ok=True)
    os.makedirs(RESULT_DIR, exist_ok=True)
    print("[+] Diretórios verificados")


def criar_dados_exemplo():
    """Cria um pequeno conjunto de exemplo caso não exista nenhum dado de treino."""
    print("[*] Nenhum dado de treino encontrado. Criando dados de exemplo...")
    os.makedirs("exemplos", exist_ok=True)
    os.makedirs("dados_treinamento", exist_ok=True)

    data = {
        "text": [
            "Erro de sintaxe SQL: SELECT * FROM users WHERE id = '' OR '1'='1'",
            "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            "<script>alert('XSS');</script> foi encontrado na resposta",
            "Command executed: ls -la /etc/passwd",
            "O usuário não tem permissão para acessar /etc/passwd",
            "Login bem-sucedido. Bem-vindo administrador!",
            "A senha foi alterada com sucesso.",
            "O nome do produto é: Apple",
            "Nenhum resultado encontrado para sua busca.",
            "Bem-vindo ao nosso site! Por favor, faça login para continuar.",
            "404 - Página não encontrada",
            "Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result",
            "uncaught exception: TypeError: Cannot read property 'value' of null",
            "UNION SELECT user,password FROM users-- foi executado com sucesso",
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            "Error: Unclosed quotation mark after the character string",
            "root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin",
            "<img src=x onerror=alert(1)> foi renderizado",
            "MongoDB query error: operator $ne cannot be at top-level",
            "O arquivo ../../../etc/passwd foi acessado e exibido",
        ],
        "label": [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1],
        "tipo_payload": [
            "sqli", "sqli", "xss", "cmd_injection", "cmd_injection",
            "normal", "normal", "normal", "normal", "normal",
            "normal", "sqli", "normal", "sqli", "cmd_injection",
            "sqli", "cmd_injection", "xss", "nosqli", "lfi_rfi",
        ],
    }
    df = pd.DataFrame(data)
    df.to_csv(EXEMPLO_DATA_FILE, index=False)
    df.to_csv(CANDIDATE_DATA_FILES[0], index=False)
    print(f"[+] Dados de exemplo criados em {EXEMPLO_DATA_FILE}")
    return df


def carregar_dados(caminho_especifico=None):
    """Carrega o dataset de treinamento a partir do primeiro arquivo disponível."""
    print("\n[1/4] Carregando dados de treinamento...")

    candidatos = []
    if caminho_especifico:
        candidatos.append(caminho_especifico)
    candidatos.extend(CANDIDATE_DATA_FILES)
    candidatos.append(EXEMPLO_DATA_FILE)

    for caminho in candidatos:
        if caminho and os.path.exists(caminho):
            try:
                df = pd.read_csv(caminho)
                if "text" in df.columns and "label" in df.columns and len(df) > 0:
                    print(f"[+] Dados carregados de: {caminho} ({len(df)} registros)")
                    return df
                else:
                    print(f"[!] {caminho} não tem colunas 'text'/'label'. Ignorando.")
            except Exception as e:
                print(f"[!] Erro ao ler {caminho}: {e}")

    # Nada encontrado -> cria exemplo
    return criar_dados_exemplo()


def preparar_dados(df):
    """Limpa e divide os dados em treino/teste."""
    print("\n[2/4] Preparando dados...")

    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)

    # Remove textos triviais
    df = df[df["text"].str.len() >= 5]

    if df.empty:
        print("[!] ERRO: nenhum registro válido após a limpeza.")
        sys.exit(1)

    contagem = df["label"].value_counts().to_dict()
    print(f"    Distribuição de classes: {contagem}")

    if len(df["label"].unique()) < 2:
        print("[!] ERRO: o dataset precisa conter as duas classes (0 e 1) para treinar.")
        print("    Gere mais dados com synthetic_data_generator.py ou collect_vulns.py.")
        sys.exit(1)

    # Converte para tipos nativos (evita arrays Arrow do pandas >= 3.0 que o sklearn não indexa)
    texts = df["text"].astype(str).tolist()
    labels = np.asarray(df["label"].astype(int).tolist(), dtype=int)

    # stratify só é possível se cada classe tiver pelo menos 2 amostras
    estratificar = labels if min(np.bincount(labels)) >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=estratificar
    )
    print(f"[+] {len(X_train)} amostras de treino, {len(X_test)} de teste")
    return X_train, X_test, y_train, y_test


def criar_pipeline():
    """Cria o pipeline TF-IDF + Regressão Logística."""
    print("\n[3/4] Construindo o modelo (TF-IDF + Regressão Logística)...")
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=NGRAM_RANGE,
            max_features=MAX_FEATURES,
            sublinear_tf=True,
            min_df=1,
        )),
        ("clf", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            C=4.0,
        )),
    ])
    return pipeline


def treinar_e_avaliar(pipeline, X_train, X_test, y_train, y_test):
    """Treina e avalia o modelo."""
    print("\n[4/4] Treinando o modelo...")
    pipeline.fit(X_train, y_train)
    print("[+] Treinamento concluído")

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"\n=== Avaliação ===")
    print(f"Acurácia: {acc * 100:.2f}%")
    try:
        print("\nRelatório de classificação:")
        print(classification_report(y_test, y_pred, zero_division=0))
        print("Matriz de confusão:")
        print(confusion_matrix(y_test, y_pred))
    except Exception as e:
        print(f"[!] Não foi possível gerar relatório detalhado: {e}")

    return acc


def salvar_modelo(pipeline, acc, n_amostras):
    """Salva o pipeline e os metadados."""
    joblib.dump(pipeline, MODEL_PATH)

    meta = {
        "version": MODEL_VERSION,
        "model_type": "tfidf+logistic_regression",
        "engine": "scikit-learn",
        "trained_at": datetime.now().isoformat(),
        "n_samples": int(n_amostras),
        "accuracy": float(round(acc, 4)),
        "default_threshold": DEFAULT_THRESHOLD,
        "ngram_range": list(NGRAM_RANGE),
        "max_features": MAX_FEATURES,
        "input": "text",
        "output": "probabilidade de vulnerabilidade (classe 1)",
    }
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=4, ensure_ascii=False)

    print(f"\n[+] Modelo salvo em: {MODEL_PATH}")
    print(f"[+] Metadados salvos em: {META_PATH}")


def gerar_grafico(acc):
    if not PLOTS_HABILITADOS:
        return
    try:
        os.makedirs(RESULT_DIR, exist_ok=True)
        plt.figure(figsize=(5, 4))
        plt.bar(["Acurácia"], [acc * 100], color="#0078D7")
        plt.ylim(0, 100)
        plt.ylabel("%")
        plt.title("Acurácia do Modelo PenteIA")
        plt.tight_layout()
        caminho = os.path.join(RESULT_DIR, "acuracia.png")
        plt.savefig(caminho)
        plt.close()
        print(f"[+] Gráfico salvo em {caminho}")
    except Exception as e:
        print(f"[!] Não foi possível gerar gráfico: {e}")


def main():
    parser = argparse.ArgumentParser(description="Treinamento do modelo PenteIA (scikit-learn)")
    parser.add_argument("--input", "-i", help="Arquivo CSV de treino (colunas: text,label)")
    parser.add_argument("--engine", "-e", choices=["sklearn", "lstm"], default="sklearn",
                        help="Motor de IA: 'sklearn' (TF-IDF+LR, padrão) ou 'lstm' (BiLSTM+Attention)")
    parser.add_argument("--epochs", type=int, default=8, help="Épocas de treino (apenas --engine lstm)")
    parser.add_argument("--memoria_limitada", action="store_true",
                        help="(compatibilidade) reduz max_features para economizar memória")
    args = parser.parse_args()

    print("\n==== PenteIA - Treinamento de Modelo (scikit-learn) ====\n")

    if args.memoria_limitada:
        global MAX_FEATURES
        MAX_FEATURES = 10000
        print(f"[*] Modo memória limitada: max_features = {MAX_FEATURES}")

    criar_diretorios()

    try:
        df = carregar_dados(args.input)

        if args.engine == "lstm":
            # ---- Motor neural: BiLSTM + Attention (PyTorch, CPU) ----
            print("\n[*] Motor selecionado: BiLSTM + Attention (PyTorch)")
            try:
                from modelo_lstm_attention import treinar_lstm, salvar_lstm
            except Exception as e:
                print(f"[!] Não foi possível carregar o motor LSTM (PyTorch instalado?): {e}")
                sys.exit(1)

            # Limpeza mínima e verificação de classes
            df = df.dropna(subset=["text", "label"]).copy()
            df["text"] = df["text"].astype(str)
            df["label"] = df["label"].astype(int)
            df = df[df["text"].str.len() >= 5]
            if len(df["label"].unique()) < 2:
                print("[!] ERRO: o dataset precisa conter as duas classes (0 e 1).")
                sys.exit(1)

            textos = df["text"].tolist()
            labels = df["label"].tolist()
            print(f"[+] Treinando com {len(textos)} amostras "
                  f"(classes: {df['label'].value_counts().to_dict()})")

            modelo, acc = treinar_lstm(textos, labels, epochs=args.epochs)
            salvar_lstm(modelo, acc, len(df))
            print(f"\n[+] Acurácia (validação): {acc * 100:.2f}%")
            print(f"[+] Modelo salvo em: modelos/penteia_lstm.pt")
            gerar_grafico(acc)
        else:
            # ---- Motor padrão: scikit-learn (TF-IDF + Regressão Logística) ----
            X_train, X_test, y_train, y_test = preparar_dados(df)
            pipeline = criar_pipeline()
            acc = treinar_e_avaliar(pipeline, X_train, X_test, y_train, y_test)
            salvar_modelo(pipeline, acc, len(df))
            gerar_grafico(acc)

        print("\n✅ MODELO TREINADO COM SUCESSO!")
        print(f"   Agora rode o scanner, por exemplo:")
        print(f"   python scanner.py --url http://localhost/DVWA/ --auth auth_dvwa.json")

    except KeyboardInterrupt:
        print("\n[!] Treinamento interrompido pelo usuário.")
    except Exception as e:
        print(f"\n[!] Erro durante o treinamento: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
