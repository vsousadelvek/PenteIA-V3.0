#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script para processar os dados brutos coletados e criar um dataset de treinamento rotulado.
Este script lê os arquivos CSV gerados pelo data_collector.py e aplica heurísticas para rotular os dados.
"""
from logging import Logger

import pandas as pd
import os
import glob
import re
import logging
import numpy as np
import json
from datetime import datetime
from collections import Counter

# Garante saída UTF-8 no terminal (evita erros no console do Windows / cp1252)
import sys as _sys
try:
    _sys.stdout.reconfigure(encoding="utf-8")
    _sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Imports opcionais para visualizações
try:
    import matplotlib
    matplotlib.use('Agg')  # Não-interativo, apenas para salvar arquivos
    import matplotlib.pyplot as plt
    import seaborn as sns
    VISUALIZACOES_HABILITADAS = True
except ImportError:
    VISUALIZACOES_HABILITADAS = False

# Constantes e configurações globais
SENSIBILIDADE_DETECCAO = 1.0  # Multiplica limiares para ajustar sensibilidade
VERSAO = "1.1"                # Versão do processador

# Configuração de logging
def configurar_logging():
    """Configura o sistema de logging"""
    os.makedirs('logs', exist_ok=True)
    log_filename = f'logs/processor_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger()

logger: Logger = configurar_logging()

def encontrar_arquivo_mais_recente(diretorio='resultados', padrao='raw_data_*.csv'):
    """Encontra o arquivo de dados mais recente no diretório especificado"""
    # Procura primeiro pelo arquivo completo (sem sufixo _resumo)
    arquivos_completos = glob.glob(os.path.join(diretorio, 'raw_data_*[0-9].csv'))
    arquivos = arquivos_completos

    # Se não encontrar arquivos completos, procura por todos os tipos
    if not arquivos:
        arquivos = glob.glob(os.path.join(diretorio, padrao))

    if not arquivos:
        logger.error(f"Nenhum arquivo encontrado com o padrão {padrao} em {diretorio}")
        return None

    # Ordena por data de modificação (mais recente primeiro)
    arquivo_mais_recente = max(arquivos, key=os.path.getmtime)
    logger.info(f"Arquivo mais recente encontrado: {arquivo_mais_recente}")
    return arquivo_mais_recente

def rotular_dados(row):
    """Rotula os dados com base em heurísticas avançadas para detectar vulnerabilidades"""
    # Variáveis para facilitar a lógica
    sucesso = False
    motivo = []

    # ========== CASO 1: Arquivo resumo (sem html_resposta) ==========
    if 'html_resposta' not in row:
        # Verificar se sucesso_exploracao está marcado como True
        if 'sucesso_exploracao' in row and row['sucesso_exploracao'] == True:
            sucesso = True
            motivo.append('sucesso_exploracao=True')

        # Verificar se há indicadores de sucesso
        if 'indicadores' in row and isinstance(row['indicadores'], str) and row['indicadores'].strip():
            sucesso = True
            motivo.append(f'indicadores={row["indicadores"]}')

        # Verificar tempo de resposta anômalo
        if 'tempo_resposta' in row and isinstance(row['tempo_resposta'], (int, float)):
            # Tempos muito longos em SQLi podem indicar operações pesadas no banco
            if row.get('tipo_payload') == 'sqli' and row['tempo_resposta'] > 1.5:
                sucesso = True
                motivo.append(f'tempo_resposta={row["tempo_resposta"]:.2f}s')

        # Verificar tamanho da resposta anômalo
        if 'tamanho_resposta' in row and isinstance(row['tamanho_resposta'], (int, float)):
            if row.get('tipo_payload') == 'sqli':
                # Respostas muito grandes em SQLi podem indicar dump de dados
                if row['tamanho_resposta'] > 3000:
                    sucesso = True
                    motivo.append(f'tamanho_resposta={row["tamanho_resposta"]} bytes')
            elif row.get('tipo_payload') == 'cmd_injection':
                # Comando bem sucedido geralmente retorna conteúdo adicional
                if row['tamanho_resposta'] > 1000:
                    sucesso = True
                    motivo.append(f'tamanho_resposta={row["tamanho_resposta"]} bytes')

        # Verificar status code
        if 'status_code' in row:
            # Status 500 em SQLi frequentemente indica erro de sintaxe SQL
            if row.get('tipo_payload') == 'sqli' and row['status_code'] == 500:
                sucesso = True
                motivo.append('status_code=500')

        # Verificar payload específico
        if 'payload_usado' in row and isinstance(row['payload_usado'], str):
            payload = row['payload_usado'].lower()

            # SQLi com UNION ou OR 1=1 tendem a ser efetivos
            if row.get('tipo_payload') == 'sqli' and ('union select' in payload or "' or 1=1" in payload):
                if 'tamanho_resposta' in row and row['tamanho_resposta'] > 2000:
                    sucesso = True
                    motivo.append(f'payload_efetivo={payload}')

            # Comandos que listam arquivos ou usuários são bons indicadores
            if row.get('tipo_payload') == 'cmd_injection' and ('cat /etc/passwd' in payload or 'ls -la' in payload):
                if 'tamanho_resposta' in row and row['tamanho_resposta'] > 1000:
                    sucesso = True
                    motivo.append(f'comando_suspeito={payload}')

        # Registramos os motivos da detecção para análise
        if sucesso and hasattr(logger, 'info'):
            logger.info(f"Vulnerabilidade detectada: {row.get('url_testada', 'URL desconhecida')} - Motivos: {', '.join(motivo)}")

        return 1 if sucesso else 0

    # ========== CASO 2: Arquivo completo (com html_resposta) ==========

    # Se a resposta HTML está disponível mas é nula
    if pd.isna(row['html_resposta']) or not isinstance(row['html_resposta'], str):
        return 0

    # Converte para minúsculas para facilitar a comparação
    html_resposta = row['html_resposta'].lower()
    payload = str(row.get('payload_usado', '')).lower()
    tipo_payload = row.get('tipo_payload', '').lower()

    # Indicadores de sucesso para SQL Injection (expandidos)
    indicadores_sqli = [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "error in your sql",
        "mysql_fetch",
        "mysql_num_rows",
        "ora-",
        "syntax error",
        "unclosed quotation mark",
        "sql syntax",
        "incorrect syntax",
        "mysql_error",
        "sql error",
        "unexpected end of sql",
        "sql command not properly ended",
        "sqlstate=",
        "database error",
        "odbc driver",
        "pg_query",
        "quoted string not properly terminated",
        "db_query_error",
        "database query failed",
        "error:", # Muitos bancos retornam mensagens com esse prefixo
        "unexpected token",
        "unexpected character",
        "valid mysql result", # Indicador positivo de DVWA
        "login: password:", # Resultado de dump bem-sucedido
        "id:name:", # Estrutura típica de resultados em DVWA
        "first name:surname:", # Estrutura típica de resultados em DVWA
        "id password", # Estrutura típica de saída de dados de usuário
        "select * from", # SQL refletido na saída
        "[user id]",
        "[password]"
    ]

    # Indicadores de sucesso para XSS (expandidos)
    indicadores_xss = [
        "<script>",
        "</script>",
        "alert(",
        "onerror=",
        "onload=",
        "javascript:alert",
        "onmouseover=",
        "onfocus=",
        "onclick=",
        "onmouseout=",
        "ondblclick=",
        "eval(",
        "document.cookie",
        "document.domain",
        "document.location",
        "<img src=",
        "<svg",
        "<iframe",
        "<style",
        "<input",
        "<body",
        "<a href="
    ]

    # Indicadores de sucesso para Command Injection (expandidos)
    indicadores_cmd = [
        "uid=",
        "gid=",
        "root:",
        "/bin/bash",
        "drwx",
        "total ", # Saída típica do comando ls
        "daemon:",
        "unix:", # Parte de arquivos de senha
        "www-data:", # Usuário comum em servidores web
        "x:0:0:", # Formato comum em /etc/passwd
        "shell",
        "home",
        "root",
        "/etc/passwd",
        "/var/www",
        "linux",
        "system32", # Para ambientes Windows
        "users",
        "directory of", # Saída do comando dir no Windows
        "bin",
        "usr",
        "var",
        "etc",
        "proc",
        "<dir>", # Saída de dir no Windows
        "<file>", # Saída de dir no Windows
        "bytes free", # Saída de dir no Windows
        "bytes", # Indicador de tamanho de arquivo
        "permission", # Mensagem sobre permissões
        "sbin",
        "tmp"
    ]

    # Indicadores de sucesso para CSRF
    indicadores_csrf = [
        "password changed",
        "alterada com sucesso",
        "successfully changed",
        "account updated",
        "profile updated",
        "settings saved",
        "form submitted",
        "thank you for your submission",
        "update completed",
        "token",
        "csrf"
    ]

    # Inicializa variáveis de controle
    sucesso = False
    motivo = []

    # === VERIFICAÇÕES POR TIPO DE VULNERABILIDADE ===

    # Verifica SQLi
    if tipo_payload == 'sqli':
        # Verifica indicadores de erro ou sucesso SQL
        for indicador in indicadores_sqli:
            if indicador in html_resposta:
                sucesso = True
                motivo.append(f'indicador_sqli={indicador}')

        # Verifica se há múltiplos resultados (OR 1=1)
        if any(x in payload for x in ["or 1=1", "' --", "' or '", "--"]):
            # Um bom indicador é ter vários registros na saída
            linhas_potenciais = html_resposta.count("<tr>")
            if linhas_potenciais > 3:
                sucesso = True
                motivo.append(f'muitas_linhas={linhas_potenciais}')

            # Ou a resposta ser grande
            if len(html_resposta) > 2500:
                sucesso = True
                motivo.append(f'resposta_grande={len(html_resposta)}')

        # Verifica UNION SELECT (dados extraídos)
        if "union select" in payload:
            # UNION SELECT tipicamente extrai colunas específicas
            if any(x in html_resposta for x in ["database()", "version()", "user()", "@@version", "schema_name"]):
                sucesso = True
                motivo.append('dados_sistema_expostos')

            # Busca por padrões de dados sensíveis
            if re.search(r'\b[0-9a-f]{32}\b', html_resposta):  # MD5 hash pattern
                sucesso = True
                motivo.append('hash_md5_encontrado')

    # Verifica XSS
    elif tipo_payload == 'xss':
        # Primeiro verifica se o payload exato foi refletido
        payload_escapado = re.escape(payload)
        if re.search(payload_escapado, html_resposta, re.IGNORECASE):
            sucesso = True
            motivo.append('payload_refletido_exato')

        # Depois verifica indicadores específicos
        for indicador in indicadores_xss:
            if indicador in html_resposta:
                # Verifica mais precisamente se o payload está realmente na resposta
                # e não é parte normal da página
                # Remove caracteres potencialmente escapados
                payload_limpo = re.sub(r'[<>\'"&]', '', payload)
                if payload_limpo and len(payload_limpo) > 3 and payload_limpo in html_resposta:
                    sucesso = True
                    motivo.append(f'indicador_xss={indicador}')

        # Busca por scripts injetados
        if re.search(r'<script[^>]*>[^<]*</script>', html_resposta):
            sucesso = True
            motivo.append('script_tag_encontrada')

        # Verifica eventos JavaScript
        if re.search(r'\bon[a-z]+\s*=\s*["\']?[^>"\s]+', html_resposta):
            sucesso = True
            motivo.append('evento_js_encontrado')

    # Verifica Command Injection
    elif tipo_payload == 'cmd_injection':
        # Busca indicadores diretos
        for indicador in indicadores_cmd:
            if indicador in html_resposta:
                sucesso = True
                motivo.append(f'indicador_cmd={indicador}')

        # Verifica sintaxe típica de saída de comando
        # Saída de 'ls -la'
        if re.search(r'(d|-)(r|-)w(x|-).*(r|-)w(x|-).*(r|-)w(x|-)', html_resposta):
            sucesso = True
            motivo.append('padrao_permissao_arquivos')

        # Saída de 'cat /etc/passwd'
        if re.search(r'[a-z]+:[x*]:\d+:\d+:[^:]*:[^:]*:[^:]*', html_resposta):
            sucesso = True
            motivo.append('padrao_etc_passwd')

        # Verifica se o comando foi executado ao invés de ser usado como parâmetro
        comando_executado = False
        for cmd in ['ls', 'cat', 'id', 'whoami', 'dir', 'echo', 'pwd', 'uname']:
            if cmd in payload and cmd in html_resposta:
                # Verifica se há saída típica deste comando
                comando_executado = True

        if comando_executado and len(html_resposta) > 1000:
            sucesso = True
            motivo.append('comando_executado')

    # Verifica CSRF
    elif tipo_payload == 'csrf':
        for indicador in indicadores_csrf:
            if indicador in html_resposta:
                sucesso = True
                motivo.append(f'indicador_csrf={indicador}')

    # === VERIFICAÇÕES GERAIS ===

    # Se o sucesso já foi determinado durante a coleta
    if row.get('sucesso_exploracao') == True:
        sucesso = True
        motivo.append('sucesso_exploracao=True')

    # Verifica tamanho da resposta (muito grande ou muito pequeno)
    tamanho_resposta = len(html_resposta)
    media_tamanho = 3000  # Valor aproximado para comparação

    # Respostas muito grandes podem indicar dump de dados em SQLi
    if tipo_payload == 'sqli' and tamanho_resposta > media_tamanho * 1.5:
        sucesso = True
        motivo.append(f'resposta_grande={tamanho_resposta}')

    # Respostas muito pequenas podem indicar erro fatal ou desligamento do serviço
    if tamanho_resposta < 100 and "error" in html_resposta:
        sucesso = True
        motivo.append(f'erro_fatal={tamanho_resposta}')

    # Registra os motivos da detecção para análise
    if sucesso and hasattr(logger, 'info'):
        logger.info(f"Vulnerabilidade detectada em {row.get('url_testada', 'URL desconhecida')} ({tipo_payload}): {', '.join(motivo)}")

    return 1 if sucesso else 0

def analisar_outliers(df, coluna, desvios=2.0):
    """Identifica outliers em uma coluna numérica usando desvio padrão"""
    if coluna not in df.columns or not pd.api.types.is_numeric_dtype(df[coluna]):
        return pd.Series([False] * len(df))

    media = df[coluna].mean()
    desvio = df[coluna].std()
    limite_superior = media + (desvios * desvio)
    limite_inferior = media - (desvios * desvio)

    # Marca como outlier valores fora do intervalo
    outliers = (df[coluna] > limite_superior) | (df[coluna] < limite_inferior)
    return outliers

def gerar_estatisticas(df_treino, arquivo_base):
    """Gera estatísticas detalhadas e visualizações dos dados processados"""
    import matplotlib.pyplot as plt
    import seaborn as sns
    from collections import Counter
    import json

    # Garante que o diretório de estatísticas existe
    diretorio_estatisticas = os.path.join('dados_treinamento', 'estatisticas')
    os.makedirs(diretorio_estatisticas, exist_ok=True)

    # Nome base para arquivos de estatísticas
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    nome_base = os.path.splitext(os.path.basename(arquivo_base))[0]
    prefixo_arquivo = os.path.join(diretorio_estatisticas, f'{nome_base}_{timestamp}')

    # Estatísticas gerais
    estatisticas = {
        "nome_arquivo": arquivo_base,
        "total_registros": len(df_treino),
        "vulneraveis": int(df_treino['label'].sum()),
        "nao_vulneraveis": len(df_treino) - int(df_treino['label'].sum()),
        "percentual_vulneraveis": round(df_treino['label'].mean() * 100, 2),
        "tipos_vulnerabilidade": {}
    }

    # Estatísticas por tipo de payload
    for tipo in df_treino['tipo_payload'].unique():
        if pd.isna(tipo):
            continue

        df_tipo = df_treino[df_treino['tipo_payload'] == tipo]
        total_tipo = len(df_tipo)
        vulneraveis_tipo = int(df_tipo['label'].sum())

        estatisticas["tipos_vulnerabilidade"][tipo] = {
            "total": total_tipo,
            "vulneraveis": vulneraveis_tipo,
            "nao_vulneraveis": total_tipo - vulneraveis_tipo,
            "percentual": round((vulneraveis_tipo / total_tipo) * 100, 2) if total_tipo > 0 else 0
        }

    # Salvar estatísticas em JSON
    with open(f"{prefixo_arquivo}_estatisticas.json", 'w', encoding='utf-8') as f:
        json.dump(estatisticas, f, indent=4, ensure_ascii=False)

    # Tentar gerar visualizações se matplotlib estiver disponível
    if VISUALIZACOES_HABILITADAS:
        try:
            # 1. Gráfico de barras com total de vulnerabilidades por tipo
            plt.figure(figsize=(12, 6))
            tipos = list(estatisticas["tipos_vulnerabilidade"].keys())
            totais = [estatisticas["tipos_vulnerabilidade"][tipo]["total"] for tipo in tipos]
            vulneraveis = [estatisticas["tipos_vulnerabilidade"][tipo]["vulneraveis"] for tipo in tipos]
            x = range(len(tipos))
            width = 0.35

            plt.bar(x, totais, width, label='Total')
            plt.bar([i + width for i in x], vulneraveis, width, label='Vulneráveis')

            plt.xlabel('Tipo de Vulnerabilidade')
            plt.ylabel('Quantidade')
            plt.title('Vulnerabilidades por Tipo')
            plt.xticks([i + width/2 for i in x], tipos)
            plt.legend()
            plt.grid(axis='y', linestyle='--', alpha=0.7)

            plt.savefig(f"{prefixo_arquivo}_grafico_vulnerabilidades.png", dpi=300, bbox_inches='tight')
            plt.close()

            # 2. Gráfico de pizza com proporção de vulnerabilidades
            plt.figure(figsize=(10, 10))
            labels = ['Vulnerável', 'Não Vulnerável']
            sizes = [estatisticas["vulneraveis"], estatisticas["nao_vulneraveis"]]
            explode = (0.1, 0)  # explode the 1st slice (Vulnerável)

            plt.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%',
                shadow=True, startangle=90, colors=['#ff9999','#66b3ff'])
            plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            plt.title('Proporção de Registros Vulneráveis')

            plt.savefig(f"{prefixo_arquivo}_grafico_proporcao.png", dpi=300, bbox_inches='tight')
            plt.close()

            # 3. Heatmap de correlação se houver dados numéricos suficientes
            colunas_numericas = df_treino.select_dtypes(include=['float64', 'int64']).columns

            if len(colunas_numericas) >= 3:
                plt.figure(figsize=(12, 10))
                corr = df_treino[colunas_numericas].corr()

                mask = np.triu(np.ones_like(corr, dtype=bool))
                cmap = sns.diverging_palette(230, 20, as_cmap=True)

                sns.heatmap(corr, mask=mask, cmap=cmap, vmax=.3, center=0,
                            square=True, linewidths=.5, annot=True, fmt='.2f')

                plt.title('Correlação entre Variáveis Numéricas')
                plt.savefig(f"{prefixo_arquivo}_grafico_correlacao.png", dpi=300, bbox_inches='tight')
                plt.close()

            logger.info(f"Estatísticas e gráficos salvos em {diretorio_estatisticas}")

        except Exception as e:
            logger.warning(f"Não foi possível gerar visualizações: {str(e)}")
            logger.warning("Instale matplotlib e seaborn para habilitar visualizações")
    else:
        logger.info(f"Estatísticas salvas em {diretorio_estatisticas} (visualizações desativadas)")

    return estatisticas

def processar_dados(arquivo_entrada=None, arquivo_saida='training_data.csv', analise_avancada=True):
    """Processa os dados brutos e gera um dataset de treinamento"""
    # Se não especificado, encontra o arquivo mais recente
    if not arquivo_entrada:
        arquivo_entrada = encontrar_arquivo_mais_recente()
        if not arquivo_entrada:
            logger.error("Não foi possível encontrar um arquivo de dados para processar.")
            return None

    # Cria o diretório para os dados de treinamento
    os.makedirs('dados_treinamento', exist_ok=True)
    arquivo_saida = os.path.join('dados_treinamento', arquivo_saida)

    logger.info(f"Processando arquivo: {arquivo_entrada}")

    try:
        # Carrega o dataset
        df = pd.read_csv(arquivo_entrada)

        # Verificar se estamos trabalhando com arquivo resumo ou completo
        eh_arquivo_resumo = 'html_resposta' not in df.columns

        if eh_arquivo_resumo:
            logger.info("Detectado arquivo de resumo sem HTML. Usando dados disponíveis para rotulagem.")
            # Verifica se temos o mínimo necessário para rotulagem
            colunas_necessarias = ['tipo_payload', 'payload_usado']
        else:
            # Arquivo completo - precisa de HTML
            colunas_necessarias = ['html_resposta', 'tipo_payload', 'payload_usado']

        colunas_faltantes = [col for col in colunas_necessarias if col not in df.columns]

        if colunas_faltantes:
            logger.error(f"Colunas faltantes no arquivo: {colunas_faltantes}")
            # Tentar usar o arquivo completo se estivermos usando o resumo
            if eh_arquivo_resumo and "_resumo" in arquivo_entrada:
                arquivo_completo = arquivo_entrada.replace("_resumo", "")
                if os.path.exists(arquivo_completo):
                    logger.info(f"Tentando usar o arquivo completo: {arquivo_completo}")
                    return processar_dados(arquivo_completo, arquivo_saida)
            return None

        logger.info(f"Dados carregados com sucesso. Total de registros: {len(df)}")

        # Aplica a função de rotulagem
        logger.info("Aplicando heurísticas para rotular os dados...")
        df['label'] = df.apply(rotular_dados, axis=1)

        # Análise avançada para encontrar vulnerabilidades usando estatísticas
        if analise_avancada:
            logger.info("Realizando análise estatística avançada para detectar outliers...")

            # Agrupa por tipo_payload para detectar anomalias em cada grupo
            for tipo in df['tipo_payload'].unique():
                if pd.isna(tipo) or not isinstance(tipo, str):
                    continue

                # Filtrar para este tipo de payload
                df_tipo = df[df['tipo_payload'] == tipo]
                if len(df_tipo) < 5:  # Precisa de amostras suficientes
                    continue

                logger.info(f"Analisando outliers para {tipo}...")

                # Verificar outliers de tamanho de resposta
                if 'tamanho_resposta' in df_tipo.columns:
                    outliers_tamanho = analisar_outliers(df_tipo, 'tamanho_resposta', 2.0)
                    if outliers_tamanho.any():
                        logger.info(f"Encontrados {outliers_tamanho.sum()} outliers de tamanho para {tipo}")
                        # Marca como vulneráveis os outliers com tamanho significativamente maior
                        df.loc[df_tipo[outliers_tamanho & (df_tipo['tamanho_resposta'] > df_tipo['tamanho_resposta'].mean())].index, 'label'] = 1

                # Verificar outliers de tempo de resposta
                if 'tempo_resposta' in df_tipo.columns:
                    outliers_tempo = analisar_outliers(df_tipo, 'tempo_resposta', 2.0)
                    if outliers_tempo.any():
                        logger.info(f"Encontrados {outliers_tempo.sum()} outliers de tempo para {tipo}")
                        # Para SQL Injection, respostas mais lentas podem indicar query pesada
                        if tipo == 'sqli':
                            df.loc[df_tipo[outliers_tempo & (df_tipo['tempo_resposta'] > df_tipo['tempo_resposta'].mean())].index, 'label'] = 1
                        # Para outros tipos, respostas mais rápidas podem indicar erro interno
                        else:
                            df.loc[df_tipo[outliers_tempo & (df_tipo['tempo_resposta'] < df_tipo['tempo_resposta'].mean())].index, 'label'] = 1

        # Cria um novo DataFrame dependendo do tipo de arquivo
        if 'html_resposta' in df.columns:
            # Arquivo completo com HTML
            df_treino = pd.DataFrame({
                'text': df['html_resposta'],
                'label': df['label'],
                'tipo_payload': df['tipo_payload'],  # Mantém para referência
                'payload': df['payload_usado']       # Mantém para referência
            })

            # Remove linhas com texto muito curto
            df_treino = df_treino[df_treino['text'].str.len() > 50]
        else:
            # Arquivo resumo sem HTML - criamos dataset mais simples
            df_treino = pd.DataFrame({
                'url': df['url_testada'],
                'label': df['label'],
                'tipo_payload': df['tipo_payload'],
                'payload': df['payload_usado'],
                'status_code': df['status_code'],
                'tamanho_resposta': df.get('tamanho_resposta', 0),
                'tempo_resposta': df.get('tempo_resposta', 0),
                'indicadores': df.get('indicadores', '')
            })

        # Verifica se o diretório existe e cria se necessário
        os.makedirs(os.path.dirname(arquivo_saida), exist_ok=True)

        # Salva o dataset de treinamento
        df_treino.to_csv(arquivo_saida, index=False)
        logger.info(f"Dataset de treinamento salvo em: {arquivo_saida}")

        # Grava também o arquivo canônico consumido pelo treinador (treinar_modelo_real.py),
        # desde que tenhamos a coluna de texto (necessária para o modelo).
        if 'text' in df_treino.columns:
            arquivo_canonico = os.path.join('dados_treinamento', 'dados_processados.csv')
            colunas_canon = [c for c in ['text', 'label', 'tipo_payload'] if c in df_treino.columns]
            df_treino[colunas_canon].to_csv(arquivo_canonico, index=False)
            logger.info(f"Arquivo canônico de treinamento atualizado em: {arquivo_canonico}")
        else:
            logger.warning("Arquivo de resumo (sem coluna 'text'): dados_processados.csv não foi gerado. "
                           "Use o arquivo completo (com html_resposta) para treinar o modelo.")

        # Imprime estatísticas de balanceamento
        contagem_classes = df_treino['label'].value_counts()
        logger.info(f"Estatísticas de balanceamento do dataset:")
        logger.info(f"Classe 0 (não vulnerável): {contagem_classes.get(0, 0)}")
        logger.info(f"Classe 1 (vulnerável): {contagem_classes.get(1, 0)}")

        # Verifica se o balanceamento está muito desigual
        if contagem_classes.get(1, 0) == 0:
            logger.warning("ATENÇÃO: Não foram encontradas vulnerabilidades no dataset. Verifique as heurísticas de rotulagem.")
        elif contagem_classes.get(1, 0) / len(df_treino) < 0.05:
            logger.warning(f"ATENÇÃO: Dataset muito desbalanceado. Apenas {contagem_classes.get(1, 0) / len(df_treino) * 100:.2f}% das amostras são vulneráveis.")

        # Salva versões específicas por tipo de vulnerabilidade
        for tipo in df_treino['tipo_payload'].unique():
            if pd.notna(tipo):
                df_tipo = df_treino[df_treino['tipo_payload'] == tipo]
                if len(df_tipo) > 0:
                    arquivo_tipo = os.path.join('dados_treinamento', f'training_{tipo}.csv')
                    df_tipo.to_csv(arquivo_tipo, index=False)
                    logger.info(f"Dataset para {tipo}: {arquivo_tipo} ({len(df_tipo)} registros)")
                    logger.info(f"  - Vulneráveis: {sum(df_tipo['label'])}")
                    logger.info(f"  - Não vulneráveis: {len(df_tipo) - sum(df_tipo['label'])}")

        # Gera estatísticas e visualizações
        try:
            logger.info("Gerando estatísticas e visualizações...")
            estatisticas = gerar_estatisticas(df_treino, arquivo_entrada)
        except Exception as e:
            logger.warning(f"Erro ao gerar estatísticas: {str(e)}")

        return df_treino

    except Exception as e:
        logger.error(f"Erro ao processar arquivo: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def main():
    """Função principal"""
    print(f"""
    ┌─────────────────────────────────────────────┐
    │ PenteIA - Processador de Dados para IA     │
    │ Versão {VERSAO}                               │
    └─────────────────────────────────────────────┘
    """)

    logger.info("Iniciando processamento de dados para treinamento de IA...")

    # Verifica se há argumentos na linha de comando
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Processa dados brutos para treinamento de IA')
    parser.add_argument('arquivo', nargs='?', help='Caminho para o arquivo de dados')
    parser.add_argument('--completo', action='store_true', help='Forçar o uso de arquivos completos, não resumos')
    parser.add_argument('--simples', action='store_true', help='Desativar análise avançada')
    parser.add_argument('--sensibilidade', type=float, default=1.0, help='Multiplicador de sensibilidade para detecção (default=1.0)')
    parser.add_argument('--sem-graficos', action='store_true', help='Desativar geração de gráficos e estatísticas')
    args = parser.parse_args()

    # Verifica se visualizações estão habilitadas
    global VISUALIZACOES_HABILITADAS
    if args.sem_graficos:
        VISUALIZACOES_HABILITADAS = False

    # Ajusta a sensibilidade global de detecção
    global SENSIBILIDADE_DETECCAO
    SENSIBILIDADE_DETECCAO = args.sensibilidade

    arquivo_entrada = None
    if args.arquivo:
        arquivo_entrada = args.arquivo
        logger.info(f"Usando arquivo especificado: {arquivo_entrada}")
    elif args.completo:
        # Procurar apenas arquivos completos
        arquivo_entrada = encontrar_arquivo_mais_recente(padrao='raw_data_*[0-9].csv')
        logger.info(f"Buscando arquivo completo mais recente: {arquivo_entrada}")

    # Define se usará análise avançada
    analise_avancada = not args.simples
    if not analise_avancada:
        logger.info("Modo simples: análise avançada desativada")
    else:
        logger.info(f"Análise avançada ativada. Sensibilidade: {SENSIBILIDADE_DETECCAO}")

    # Processa os dados
    dataset = processar_dados(arquivo_entrada, analise_avancada=analise_avancada)

    if dataset is not None:
        logger.info("Processamento concluído com sucesso!")

        # Gera estatísticas adicionais
        total_registros = len(dataset)
        registros_vulneraveis = sum(dataset['label'])
        percentual_vulneraveis = (registros_vulneraveis / total_registros) * 100 if total_registros > 0 else 0

        logger.info(f"Estatísticas finais:")
        logger.info(f"Total de registros processados: {total_registros}")
        logger.info(f"Registros vulneráveis: {registros_vulneraveis} ({percentual_vulneraveis:.2f}%)")
        logger.info(f"Registros não vulneráveis: {total_registros - registros_vulneraveis} ({100 - percentual_vulneraveis:.2f}%)")
    else:
        logger.error("Falha no processamento de dados!")

if __name__ == "__main__":
    main()
