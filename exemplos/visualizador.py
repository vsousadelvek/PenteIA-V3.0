#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script para visualizar estatísticas dos dados coletados pelo PenteIA.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
import glob

# Garante saída UTF-8 no terminal (evita erros no console do Windows / cp1252)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

def encontrar_arquivo_mais_recente(diretorio='dados_treinamento', padrao='training_*.csv'):
    """Encontra o arquivo de dados de treinamento mais recente"""
    arquivos = glob.glob(os.path.join(diretorio, padrao))
    if not arquivos:
        print(f"Nenhum arquivo encontrado com o padrão {padrao} em {diretorio}")
        return None

    # Ordena por data de modificação (mais recente primeiro)
    arquivo_mais_recente = max(arquivos, key=os.path.getmtime)
    print(f"Arquivo mais recente encontrado: {arquivo_mais_recente}")
    return arquivo_mais_recente

def visualizar_dados(arquivo=None):
    """Gera visualizações a partir dos dados de treinamento"""
    if not arquivo:
        arquivo = encontrar_arquivo_mais_recente()
        if not arquivo:
            print("Não foi possível encontrar um arquivo de dados para visualizar.")
            return

    print(f"Visualizando dados do arquivo: {arquivo}")

    try:
        # Carrega o dataset
        df = pd.read_csv(arquivo)

        # Cria diretório para visualizações
        os.makedirs('visualizacoes', exist_ok=True)

        # Configuração para melhor visualização
        sns.set(style="whitegrid")
        plt.rcParams.update({'font.size': 12})

        # 1. Distribuição das classes
        plt.figure(figsize=(10, 6))
        ax = sns.countplot(x='label', data=df, palette='viridis')
        plt.title('Distribuição de Classes (0: Não Vulnerável, 1: Vulnerável)')
        plt.xlabel('Classe')
        plt.ylabel('Contagem')

        # Adicionar valores nas barras
        for p in ax.patches:
            ax.annotate(f'{int(p.get_height())}', 
                       (p.get_x() + p.get_width() / 2., p.get_height()), 
                       ha = 'center', va = 'bottom', 
                       fontsize=12)

        plt.tight_layout()
        plt.savefig('visualizacoes/distribuicao_classes.png')
        plt.close()

        # 2. Distribuição por tipo de payload (se disponível)
        if 'tipo_payload' in df.columns:
            plt.figure(figsize=(12, 7))
            ax = sns.countplot(x='tipo_payload', hue='label', data=df, palette='viridis')
            plt.title('Distribuição por Tipo de Payload')
            plt.xlabel('Tipo de Payload')
            plt.ylabel('Contagem')
            plt.xticks(rotation=45)
            plt.legend(title='Vulnerável', labels=['Não', 'Sim'])
            plt.tight_layout()
            plt.savefig('visualizacoes/distribuicao_por_tipo.png')
            plt.close()

            # Análise percentual de sucesso por tipo
            plt.figure(figsize=(12, 7))
            sucesso_por_tipo = df.groupby('tipo_payload')['label'].mean() * 100
            sucesso_por_tipo = sucesso_por_tipo.reset_index()
            sucesso_por_tipo.columns = ['tipo_payload', 'taxa_sucesso']

            ax = sns.barplot(x='tipo_payload', y='taxa_sucesso', data=sucesso_por_tipo, palette='viridis')
            plt.title('Taxa de Sucesso por Tipo de Payload (%)')
            plt.xlabel('Tipo de Payload')
            plt.ylabel('Taxa de Sucesso (%)')
            plt.xticks(rotation=45)

            # Adicionar valores nas barras
            for p in ax.patches:
                ax.annotate(f'{p.get_height():.1f}%', 
                           (p.get_x() + p.get_width() / 2., p.get_height()), 
                           ha = 'center', va = 'bottom', 
                           fontsize=12)

            plt.tight_layout()
            plt.savefig('visualizacoes/taxa_sucesso_por_tipo.png')
            plt.close()

        # 3. Comprimento das respostas por classe
        if 'text' in df.columns:
            df['text_length'] = df['text'].str.len()

            plt.figure(figsize=(10, 6))
            sns.boxplot(x='label', y='text_length', data=df, palette='viridis')
            plt.title('Distribuição do Comprimento das Respostas por Classe')
            plt.xlabel('Classe (0: Não Vulnerável, 1: Vulnerável)')
            plt.ylabel('Comprimento do Texto (caracteres)')
            plt.yscale('log')  # Escala logarítmica para melhor visualização
            plt.tight_layout()
            plt.savefig('visualizacoes/comprimento_por_classe.png')
            plt.close()

        print(f"Visualizações geradas com sucesso no diretório 'visualizacoes/'")
        print("Estatísticas básicas:")
        print(f"Total de registros: {len(df)}")
        print(f"Registros vulneráveis: {df['label'].sum()} ({df['label'].mean()*100:.2f}%)")
        print(f"Registros não vulneráveis: {len(df) - df['label'].sum()} ({(1-df['label'].mean())*100:.2f}%)")

        if 'tipo_payload' in df.columns:
            print("\nDistribuição por tipo de payload:")
            tipo_counts = df['tipo_payload'].value_counts()
            for tipo, count in tipo_counts.items():
                print(f"  {tipo}: {count} registros")

                # Cálculo da taxa de sucesso para este tipo
                tipo_df = df[df['tipo_payload'] == tipo]
                taxa = tipo_df['label'].mean() * 100
                print(f"    Taxa de sucesso: {taxa:.2f}%")

    except Exception as e:
        print(f"Erro ao processar arquivo: {str(e)}")
        import traceback
        print(traceback.format_exc())

def main():
    """Função principal"""
    print("""
    ┌─────────────────────────────────────────────┐
    │ PenteIA - Visualizador de Dados            │
    │ Versão 1.0                                 │
    └─────────────────────────────────────────────┘
    """)

    # Verifica se há argumentos na linha de comando
    arquivo = None
    if len(sys.argv) > 1:
        arquivo = sys.argv[1]
        print(f"Usando arquivo especificado: {arquivo}")

    visualizar_dados(arquivo)

if __name__ == "__main__":
    main()
