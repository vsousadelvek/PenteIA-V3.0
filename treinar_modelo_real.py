#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script para treinar um modelo real para o PenteIA Scanner
Este script coleta dados, processa-os e treina um modelo de IA
para detectar vulnerabilidades em aplicações web.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
import tensorflow as tf

# Limitar o uso de memória do TensorFlow
import gc

# Detectar versão do TensorFlow
tf_version = tf.__version__
print(f"\n[INFO] Versão do TensorFlow: {tf_version}")

# Configuração para detectar e usar GPU se disponível
gpus = tf.config.experimental.list_physical_devices('GPU')
if gpus:
    print(f"✓ {len(gpus)} GPU(s) detectada(s)")
    for gpu in gpus:
        try:
            tf.config.experimental.set_memory_growth(gpu, True)
            print(f"  - Uso de memória dinâmica ativado para GPU: {gpu}")
        except Exception as e:
            print(f"  - Erro ao configurar GPU: {e}")
else:
    print("✓ Usando CPU para treinamento")
    # Configurações otimizadas para CPU
    tf.config.threading.set_intra_op_parallelism_threads(4)  # Corresponde aos seus 4 núcleos
    tf.config.threading.set_inter_op_parallelism_threads(2)
    tf.config.set_soft_device_placement(True)

    # Limitar memória do TensorFlow (apenas definir política)
    # Não podemos usar set_memory_growth para CPU
    print("✓ Configuração de CPU otimizada para i3 com 20GB RAM")

import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Embedding, LSTM, SpatialDropout1D, Bidirectional, GlobalMaxPooling1D
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

# NOTA: O erro 'TensorFlowTrainer.fit() got an unexpected keyword argument 'workers'' ocorre
# porque algumas versões do TensorFlow não suportam certos parâmetros de otimização como
# 'workers', 'use_multiprocessing' e 'max_queue_size' no método fit().
# Esta versão do script foi modificada para ser compatível com qualquer versão do TF.

# Configurações otimizadas para balancear desempenho e uso de memória
MAX_LENGTH = 500    # Aumentado para melhorar precisão (sequências maiores)
MAX_WORDS = 10000   # Aumentado para melhor vocabulário
BATCH_SIZE = 32      # Aumentado para acelerar treinamento
EPOCHS = 20         # Mantido
EMBEDDING_DIM = 128  # Aumentado para melhorar representação
DROPOUT_RATE = 0.3  # Mantido
LEARNING_RATE = 0.001  # Mantido
VALIDATION_SPLIT = 0.2  # Mantido
EARLY_STOPPING_PATIENCE = 3  # Mantido

TRAINING_DATA_FILE = "dados_treinamento/dados_processados.csv"
MODEL_PATH = "modelos/penteia_model.h5"
TOKENIZER_PATH = "modelos/tokenizer.json"

def criar_diretorios():
    """Cria os diretórios necessários"""
    os.makedirs("modelos", exist_ok=True)
    os.makedirs("dados_treinamento", exist_ok=True)
    os.makedirs("resultados", exist_ok=True)
    print("✓ Diretórios criados ou verificados")

def coletar_dados():
    """Coleta dados de vulnerabilidades"""
    print("\n[1/5] Coletando dados para treinamento...")

    # Verifica se já existem dados processados
    if os.path.exists(TRAINING_DATA_FILE):
        print(f"✓ Dados já existem em {TRAINING_DATA_FILE}")
        return pd.read_csv(TRAINING_DATA_FILE)

    # Verifica se o data_collector.py existe
    if not os.path.exists("data_collector.py"):
        print("[!] ERRO: data_collector.py não encontrado.")
        print("[!] Você precisa ter dados para treinar o modelo.")

        # Tenta usar exemplos de dados pré-processados
        print("[*] Verificando se existem dados de exemplo...")
        exemplo_path = "exemplos/dados_exemplo.csv"
        if os.path.exists(exemplo_path):
            print(f"✓ Usando dados de exemplo de {exemplo_path}")
            import shutil
            os.makedirs(os.path.dirname(TRAINING_DATA_FILE), exist_ok=True)
            shutil.copy(exemplo_path, TRAINING_DATA_FILE)
            return pd.read_csv(TRAINING_DATA_FILE)
        else:
            sys.exit(1)

    # Executa o coletor de dados para obter exemplos
    import subprocess
    print("[*] Executando data_collector.py para coletar dados...")
    result = subprocess.run([sys.executable, "data_collector.py", "--auto"], 
                          capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] ERRO ao executar data_collector.py: {result.stderr}")
        sys.exit(1)

    # Verifica se os dados foram coletados
    if os.path.exists(TRAINING_DATA_FILE):
        print(f"✓ Dados coletados em {TRAINING_DATA_FILE}")
        return pd.read_csv(TRAINING_DATA_FILE)
    else:
        print("[!] ERRO: Dados não foram coletados corretamente.")
        sys.exit(1)

def processar_dados(df):
    """Processa os dados para treinamento"""
    print("\n[2/5] Processando dados...")

    # Verificar colunas necessárias
    required_cols = ['text', 'label']
    if not all(col in df.columns for col in required_cols):
        print(f"[!] ERRO: Colunas necessárias não encontradas no dataset. Colunas disponíveis: {df.columns.tolist()}")
        print("[!] O dataset deve conter pelo menos 'text' e 'label'.")
        sys.exit(1)

    # Remover valores nulos
    df = df.dropna(subset=['text', 'label'])

    # Converter texto para string
    df['text'] = df['text'].astype(str)

    # Converter label para inteiro
    df['label'] = df['label'].astype(int)

    # Verificar distribuição de classes
    class_counts = df['label'].value_counts()
    print(f"Distribuição de classes:\n{class_counts}")

    if 1 not in class_counts or 0 not in class_counts:
        print("[!] AVISO: Dataset desbalanceado. Certifique-se de ter exemplos de ambas as classes.")

    # Dividir em treino e teste
    texts = df['text'].values
    labels = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print(f"✓ Dados processados: {len(X_train)} amostras de treino, {len(X_test)} amostras de teste")

    return X_train, X_test, y_train, y_test

def criar_tokenizer(X_train):
    """Cria e treina o tokenizer"""
    print("\n[3/5] Criando tokenizer...")

    # Criar tokenizer
    tokenizer = Tokenizer(num_words=MAX_WORDS)
    tokenizer.fit_on_texts(X_train)

    # Salvar tokenizer
    tokenizer_json = tokenizer.to_json()
    with open(TOKENIZER_PATH, 'w') as f:
        f.write(tokenizer_json)

    print(f"✓ Tokenizer criado e salvo em {TOKENIZER_PATH}")
    return tokenizer

def preparar_sequencias(X_train, X_test, tokenizer):
    """Prepara as sequências para treinamento"""
    print("\n[4/5] Preparando sequências de texto...")

    # Converter textos para sequências
    X_train_seq = tokenizer.texts_to_sequences(X_train)
    X_test_seq = tokenizer.texts_to_sequences(X_test)

    # Aplicar padding
    X_train_pad = pad_sequences(X_train_seq, maxlen=MAX_LENGTH, padding='post', truncating='post')
    X_test_pad = pad_sequences(X_test_seq, maxlen=MAX_LENGTH, padding='post', truncating='post')

    print(f"✓ Sequências preparadas com comprimento máximo {MAX_LENGTH}")
    return X_train_pad, X_test_pad

def criar_modelo():
    """Cria o modelo adaptado às características do sistema"""
    print("\n[5/5] Criando modelo adaptado às características do sistema...")

    # Importar SimpleRNN explicitamente para usar como alternativa ao LSTM
    from tensorflow.keras.layers import SimpleRNN

    # Verificar memória disponível e obter recomendações
    try:
        mem_available, configs = verificar_memoria()
    except Exception as e:
        print(f"[!] Erro ao verificar memória: {e}")
        mem_available, configs = None, None

    # Aplicar configurações recomendadas ou usar as padrões
    usar_simpleRNN = False
    lstm_units = 64  # Unidades padrão para LSTM
    dense_units = 32  # Unidades padrão para camada densa

    if configs:
        # Se temos recomendações de memória, usar valores ajustados
        usar_simpleRNN = not configs['use_lstm']

        # Ajustar tamanho das camadas com base na memória
        if mem_available and mem_available > 6.0:
            lstm_units = 96
            dense_units = 64
        elif mem_available and mem_available > 3.0:
            lstm_units = 64
            dense_units = 32
        else:
            lstm_units = 32
            dense_units = 16

        print(f"[+] Modelo ajustado para {lstm_units} unidades LSTM e {dense_units} unidades densas")
    else:
        # Sem recomendações, decidir baseado em valor padrão
        if mem_available is None or mem_available < 4.0:
            usar_simpleRNN = True
            print("[!] Usando SimpleRNN para economizar memória")
            lstm_units = 32
            dense_units = 16

    # Modelo adaptativo
    model = Sequential()
    model.add(Embedding(MAX_WORDS, EMBEDDING_DIM, input_length=MAX_LENGTH))
    model.add(SpatialDropout1D(DROPOUT_RATE))

    # Escolher entre SimpleRNN (mais leve) ou LSTM (melhor performance)
    if usar_simpleRNN:
        print(f"[+] Usando SimpleRNN com {lstm_units} unidades")
        model.add(SimpleRNN(lstm_units, dropout=DROPOUT_RATE))
    else:
        print(f"[+] Usando LSTM com {lstm_units} unidades")
        # LSTM otimizado com parâmetros apropriados
        model.add(LSTM(lstm_units, dropout=DROPOUT_RATE, recurrent_dropout=0.1, return_sequences=False))

    # Camadas densas ajustadas
    model.add(Dense(dense_units, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))

    # Otimizador com taxa de aprendizado explícita
    optimizer = tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE)

    # Compilar modelo
    model.compile(
        loss='binary_crossentropy',
        optimizer=optimizer,
        metrics=['accuracy']
    )

    # Imprimir resumo do modelo para verificar uso de memória
    print("\nResumo do modelo:")
    model.summary()

    print("✓ Modelo adaptado criado e compilado")
    return model

def treinar_modelo(model, X_train_pad, y_train, X_test_pad, y_test):
    """Treina o modelo com gerenciamento de memória aprimorado para i3 com 20GB RAM"""
    print("\n[*] Iniciando treinamento do modelo com otimização de memória...")
    print(f"    - Tamanho do batch: {BATCH_SIZE}")
    print(f"    - Comprimento máximo das sequências: {MAX_LENGTH}")

    # Callbacks otimizados
    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=3,
        restore_best_weights=True,
        verbose=1
    )

    checkpoint = ModelCheckpoint(
        MODEL_PATH,
        monitor='val_accuracy',
        save_best_only=True,
        mode='max',
        verbose=1
    )

    # Callback personalizado para notificação de progresso
    class ProgressCallback(tf.keras.callbacks.Callback):
        def on_epoch_end(self, epoch, logs=None):
            if epoch > 0 and epoch % 5 == 0:
                # A cada 5 épocas, exibir métricas de forma mais destacada
                print(f"\n[PROGRESSO] Época {epoch}/{EPOCHS} concluída")
                if logs:
                    print(f"  - Acurácia: {logs.get('accuracy', 0):.4f}")
                    print(f"  - Acurácia val: {logs.get('val_accuracy', 0):.4f}")
                    print(f"  - Loss: {logs.get('loss', 0):.4f}")
                    print(f"  - Val loss: {logs.get('val_loss', 0):.4f}")
                # Verificar memória atual
                try:
                    import psutil
                    mem = psutil.virtual_memory()
                    print(f"  - Memória em uso: {mem.percent}%")
                except:
                    pass

    progress_callback = ProgressCallback()

    # Reduzir ainda mais o volume de dados de validação
    val_size = min(len(X_test_pad), 500)  # Ainda menor: 500 amostras
    X_val = X_test_pad[:val_size]
    y_val = y_test[:val_size]
    print(f"    - Usando {val_size} amostras para validação")

    # Liberar memória que não precisamos mais
    del X_test_pad
    limpar_memoria()

    # Verificar se estamos usando GPU
    using_gpu = len(tf.config.list_physical_devices('GPU')) > 0

    # Ajustar batch_size dinamicamente para GPU se disponível
    current_batch_size = BATCH_SIZE
    if using_gpu:
        print(f"[+] GPU detectada. Otimizando batch_size para GPU.")
        try:
            # Tentar obter informação de memória da GPU
            gpu_devices = tf.config.list_physical_devices('GPU')
            if gpu_devices:
                # Aumentar batch size para GPUs com mais memória
                current_batch_size = min(BATCH_SIZE * 2, 128)  # Até 128 para GPUs boas
                print(f"[+] Batch size otimizado para GPU: {current_batch_size}")
        except:
            # Se não conseguir informação, usar valor padrão
            pass

    # Treinar modelo com estratégia adaptativa
    print(f"[+] Iniciando treinamento com batch_size={current_batch_size}...")
    try:
        # Treinar modelo (com parâmetros compatíveis)
        history = model.fit(
            X_train_pad, y_train,
            validation_data=(X_val, y_val),
            epochs=EPOCHS,
            batch_size=current_batch_size,
            callbacks=[early_stopping, checkpoint, progress_callback],
            verbose=1
            # Sem parâmetros incompatíveis
        )

        print("\n✓ Treinamento concluído com sucesso!")

    except Exception as e:
        print(f"\n[!] Erro durante o treinamento: {e}")
        print("[*] Tentando estratégia adaptativa...")

        # Estratégia adaptativa - reduzir batch size gradualmente
        batch_sizes = [current_batch_size//2, current_batch_size//4, 8, 4]
        success = False

        for reduced_batch in batch_sizes:
            if reduced_batch < 4 or reduced_batch >= current_batch_size:
                continue  # Evitar tamanhos inválidos

            print(f"    - Tentando com batch_size={reduced_batch}")

            # Limpar memória antes de tentar novamente
            limpar_memoria()

            try:
                history = model.fit(
                    X_train_pad, y_train,
                    validation_data=(X_val, y_val),
                    epochs=EPOCHS,
                    batch_size=reduced_batch,
                    callbacks=[early_stopping, checkpoint, progress_callback],
                    verbose=1
                )
                success = True
                print(f"✓ Treinamento bem-sucedido com batch_size={reduced_batch}")
                break
            except Exception as inner_e:
                print(f"[!] Falha com batch_size={reduced_batch}: {inner_e}")

        if not success:
            print("[!] Todas as estratégias falharam. Tentando configuração mínima...")
            try:
                # Configuração mínima absoluta como último recurso
                history = model.fit(
                    X_train_pad, y_train,
                    validation_data=(X_val, y_val),
                    epochs=5,  # Reduzir épocas
                    batch_size=1,  # Mínimo possível
                    callbacks=[checkpoint],  # Apenas checkpoint
                    verbose=1
                )
            except Exception as final_e:
                print(f"[!] Falha fatal no treinamento: {final_e}")
                print("[!] Não foi possível treinar o modelo com os recursos disponíveis.")
                return None  # Retornar None para indicar falha

    # Limpar memória após treinamento
    limpar_memoria()

    # Carregar melhor modelo para avaliação
    try:
        model = tf.keras.models.load_model(MODEL_PATH)
        print("\n[*] Melhor modelo carregado do checkpoint")
    except Exception as e:
        print(f"\n[!] Aviso: Não foi possível carregar o melhor modelo: {e}")
        print("    Continuando com o modelo atual")

    # Recuperar objetos que liberamos
    X_test_pad = X_val  # Usamos apenas os dados de validação para avaliar
    y_test = y_val

    # Avaliar modelo com dados de validação para economizar memória
    print("\n[*] Avaliando modelo...")
    try:
        scores = model.evaluate(X_test_pad, y_test, 
                             batch_size=8,  # Batch menor para avaliação 
                             verbose=1)
        print(f"\n✓ Avaliação concluída! Acurácia: {scores[1]*100:.2f}%")
    except Exception as e:
        print(f"\n[!] Erro durante a avaliação: {e}")
        print("    Avaliação ignorada para salvar o modelo")
        # Mesmo com erro, o modelo já foi salvo pelo checkpoint
        scores = [0, 0]  # Valores padrão para continuar o fluxo

    # Tenta gerar gráficos apenas se o matplotlib estiver disponível
    try:
        # Tenta criar diretório de resultados se não existir
        import os
        os.makedirs('resultados', exist_ok=True)

        # Verifica se o matplotlib está instalado
        import matplotlib

        # Gera gráficos simplificados para economizar memória
        plt.figure(figsize=(8, 4))
        plt.plot(history.history['accuracy'])
        plt.plot(history.history['val_accuracy'])
        plt.title('Acurácia do Modelo')
        plt.ylabel('Acurácia')
        plt.xlabel('Época')
        plt.legend(['Treino', 'Validação'], loc='lower right')
        plt.tight_layout()
        plt.savefig('resultados/acuracia.png')
        plt.close()

        print("✓ Gráfico de acurácia salvo em 'resultados/acuracia.png'")
    except Exception as e:
        print(f"[!] Não foi possível gerar gráficos: {e}")
        print("    Isso não afeta o modelo treinado.")

    # Confirma que modelo foi salvo com sucesso
    if os.path.exists(MODEL_PATH):
        print(f"\n✓ Modelo salvo com sucesso em {MODEL_PATH}")
    else:
        print(f"\n[!] AVISO: Modelo não encontrado em {MODEL_PATH}")
        # Tenta salvar modelo novamente
        try:
            model.save(MODEL_PATH)
            print(f"✓ Modelo salvo manualmente em {MODEL_PATH}")
        except Exception as e:
            print(f"[!] Erro ao salvar modelo: {e}")

    return history

def criar_dados_exemplo():
    """Cria dados de exemplo caso não existam dados reais"""
    print("[*] Criando dados de exemplo para treinamento...")

    # Garantir que o diretório existe
    os.makedirs("exemplos", exist_ok=True)
    os.makedirs(os.path.dirname(TRAINING_DATA_FILE), exist_ok=True)

    # Dados de exemplo
    data = {
        'text': [
            "Erro de sintaxe SQL: SELECT * FROM users WHERE id = '' OR '1'='1'",
            "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1",
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
            "exec(/bin/sh -c 'cat /etc/passwd') executado",
            "Error: Unclosed quotation mark after the character string",
            "Você se conectou como: root@localhost",
            "<img src=x onerror=alert(1)> foi renderizado",
            "mongodb query error: operator $ne cannot be at top-level",
            "O arquivo ../../../etc/passwd foi acessado"
        ],
        'label': [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1],
        'tipo_payload': [
            'sqli', 'sqli', 'xss', 'cmd_injection', 'cmd_injection', 
            'normal', 'normal', 'normal', 'normal', 'normal', 
            'normal', 'sqli', 'normal', 'sqli', 'cmd_injection', 
            'sqli', 'sqli', 'xss', 'nosqli', 'path_traversal'
        ]
    }

    # Criar DataFrame
    df = pd.DataFrame(data)

    # Salvar em CSV
    exemplo_path = "exemplos/dados_exemplo.csv"
    df.to_csv(exemplo_path, index=False)

    # Copiar para diretório de treinamento
    df.to_csv(TRAINING_DATA_FILE, index=False)

    print(f"✓ Dados de exemplo criados e salvos em {exemplo_path} e {TRAINING_DATA_FILE}")
    return df

def limpar_memoria():
    """Limpa a memória para evitar vazamentos e otimizar uso de RAM"""
    import gc
    import tensorflow as tf
    import os

    # Força coleta de lixo Python
    gc.collect()

    # Limpa backend do TensorFlow (sessões, grafos, etc)
    tf.keras.backend.clear_session()

    # Em sistemas Windows, podemos chamar o garbage collector mais agressivamente
    if os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetProcessWorkingSetSize(-1, -1)

    print("✓ Memória limpa e otimizada")


def verificar_memoria():
    """Verifica e imprime informações sobre a memória disponível,
    retornando recomendações de configuração otimizadas"""
    import os

    try:
        # Tentar importar psutil para informações detalhadas
        import psutil

        # Obter informações de memória
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024

        # Obter memória total do sistema
        system_memory = psutil.virtual_memory()
        total_memory_gb = system_memory.total / 1024 / 1024 / 1024
        available_memory_gb = system_memory.available / 1024 / 1024 / 1024
        memory_percent = system_memory.percent
    except Exception as e:
        print(f"[!] Erro ao obter informações de memória: {e}")
        # Retornar valores padrão conservadores
        return 4.0, {
            'max_length': 300,
            'batch_size': 16,
            'embedding_dim': 64,
            'max_words': 5000,
            'use_lstm': True
        }

        print(f"\n[INFO] Uso de memória:")
        print(f"  - Processo atual: {memory_mb:.2f} MB")
        print(f"  - Memória total do sistema: {total_memory_gb:.2f} GB")
        print(f"  - Memória disponível: {available_memory_gb:.2f} GB")
        print(f"  - Uso de memória do sistema: {memory_percent}%")

        # Calcular recomendações com base na memória disponível
        configs = {}

        # Sistemas com memória abundante (>8GB disponível)
        if available_memory_gb > 8.0:
            print("[+] Memória abundante detectada. Usando configurações de alta performance.")
            configs = {
                'max_length': 600,
                'batch_size': 64,
                'embedding_dim': 128,
                'max_words': 15000,
                'use_lstm': True
            }
        # Sistemas com boa memória (4-8GB disponível)
        elif available_memory_gb > 4.0:
            print("[+] Boa quantidade de memória detectada. Usando configurações balanceadas.")
            configs = {
                'max_length': 500,
                'batch_size': 32,
                'embedding_dim': 128,
                'max_words': 10000,
                'use_lstm': True
            }
        # Sistemas com memória moderada (2-4GB disponível)
        elif available_memory_gb > 2.0:
            print("[+] Memória moderada detectada. Usando configurações otimizadas.")
            configs = {
                'max_length': 350,
                'batch_size': 24,
                'embedding_dim': 96,
                'max_words': 8000,
                'use_lstm': True
            }
        # Sistemas com pouca memória (1-2GB disponível)
        elif available_memory_gb > 1.0:
            print("[!] Pouca memória disponível. Usando configurações conservadoras.")
            configs = {
                'max_length': 250,
                'batch_size': 16,
                'embedding_dim': 64,
                'max_words': 5000,
                'use_lstm': False
            }
        # Sistemas com memória crítica (<1GB disponível)
        else:
            print("[!] AVISO: Memória crítica. Usando configurações mínimas.")
            print("    Considere fechar outros programas para melhorar performance.")
            configs = {
                'max_length': 150,
                'batch_size': 8,
                'embedding_dim': 32,
                'max_words': 3000,
                'use_lstm': False
            }

        return available_memory_gb, configs
    except ImportError:
        print("[!] Módulo psutil não encontrado. Instale com: pip install psutil")
        print("    Verificação detalhada de memória não disponível.")
        return None, None
    except Exception as e:
        print(f"[!] Erro ao verificar memória: {e}")
        return None, None


def main():
    """Função principal"""
    print("\n==== PenteIA - Treinamento de Modelo Real ====\n")
    print("Versão otimizada para sistemas com restrições de memória")

    # Criar diretórios necessários
    criar_diretorios()

    # Verificar memória disponível e obter recomendações automáticas
    try:
        import psutil
    except ImportError:
        print("[!] Módulo psutil não encontrado. Recomendamos instalar para melhor gerenciamento de memória.")
        print("    Execute: pip install psutil")
    else:
        mem_available, configs = verificar_memoria()

        # Aplicar configurações recomendadas se disponíveis
        if configs:
            # Definir variáveis a serem modificadas como globais
            global MAX_LENGTH, BATCH_SIZE, MAX_WORDS, EMBEDDING_DIM
            old_max_length = MAX_LENGTH
            old_batch_size = BATCH_SIZE
            old_max_words = MAX_WORDS
            old_embedding_dim = EMBEDDING_DIM

            # Ajustar parâmetros automaticamente
            MAX_LENGTH = configs['max_length']
            BATCH_SIZE = configs['batch_size']
            MAX_WORDS = configs['max_words']
            EMBEDDING_DIM = configs['embedding_dim']

            print(f"\n[+] Configurações otimizadas aplicadas automaticamente:")
            print(f"    - MAX_LENGTH: {old_max_length} → {MAX_LENGTH}")
            print(f"    - BATCH_SIZE: {old_batch_size} → {BATCH_SIZE}")
            print(f"    - MAX_WORDS: {old_max_words} → {MAX_WORDS}")
            print(f"    - EMBEDDING_DIM: {old_embedding_dim} → {EMBEDDING_DIM}")
        elif mem_available is not None and mem_available < 4.0:
            # Fallback para o comportamento anterior
            global MAX_LENGTH, BATCH_SIZE
            old_max_length = MAX_LENGTH
            old_batch_size = BATCH_SIZE

            # Ajustar parâmetros automaticamente
            MAX_LENGTH = min(MAX_LENGTH, 300)  # Reduzir ainda mais
            BATCH_SIZE = min(BATCH_SIZE, 8)    # Reduzir ainda mais

            print(f"\n[!] AVISO: Pouca memória disponível (menos de 4GB).")
            print(f"    Ajustando parâmetros manualmente:")
            print(f"    - MAX_LENGTH: {old_max_length} → {MAX_LENGTH}")
            print(f"    - BATCH_SIZE: {old_batch_size} → {BATCH_SIZE}")

    try:
        # Coletar dados
        df = coletar_dados()
        limpar_memoria()

        if df is None or df.empty:
            print("[!] Nenhum dado encontrado, criando dados de exemplo...")
            df = criar_dados_exemplo()

        # Processar dados
        X_train, X_test, y_train, y_test = processar_dados(df)
        limpar_memoria()  # Limpar após processamento

        # Não precisamos mais do DataFrame original
        del df
        limpar_memoria()

        tokenizer = criar_tokenizer(X_train)
        limpar_memoria()  # Limpar após tokenização

        # Preparar sequências
        X_train_pad, X_test_pad = preparar_sequencias(X_train, X_test, tokenizer)
        # Não precisamos mais dos textos originais
        del X_train, X_test
        limpar_memoria()

        # Verificar memória novamente antes de criar o modelo
        verificar_memoria()

        # Criar e treinar modelo
        model = criar_modelo()
        history = treinar_modelo(model, X_train_pad, y_train, X_test_pad, y_test)

        # Remover marcador de modelo de demonstração se existir
        demo_marker = os.path.join("modelos", ".demo_model")
        if os.path.exists(demo_marker):
            os.remove(demo_marker)

        print("\n✅ MODELO REAL TREINADO COM SUCESSO!")
        print(f"   Modelo salvo em: {MODEL_PATH}")
        print(f"   Tokenizer salvo em: {TOKENIZER_PATH}")
        print("\n   Agora você pode executar o scanner com:")
        print("   python scanner.py --url https://exemplo.com --config scanner_config.json")

    except KeyboardInterrupt:
        print("\n[!] Treinamento interrompido pelo usuário.")
    except Exception as e:
        print(f"\n[!] Erro durante o treinamento: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()