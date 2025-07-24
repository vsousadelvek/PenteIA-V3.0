# PenteIA - Download de Dados de Vulnerabilidades

Este script automatiza o download e processamento de dados de vulnerabilidades web de fontes públicas para uso no treinamento do modelo PenteIA.

## Fontes de Dados

O script coleta dados das seguintes fontes:

1. **OWASP ModSecurity Core Rule Set (CRS)** - Regras de proteção contra vulnerabilidades web
2. **PayloadsAllTheThings** - Coleção de payloads para testes de penetração, incluindo:
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Command Injection
   - Directory Traversal (LFI/RFI)
   - NoSQL Injection
   - XPATH Injection

## Uso

```bash
# Baixar todos os dados (padrão)
python download_vulns.py

# Baixar uma fonte específica
python download_vulns.py --source "PayloadsAllTheThings-SQLi"

# Usar cache existente (não baixar novamente)
python download_vulns.py --skip-download

# Forçar download mesmo com cache existente
python download_vulns.py --force

# Especificar arquivo de saída
python download_vulns.py --output "meus_dados.csv"
```

## Parâmetros

- `--skip-download` ou `-s`: Usa dados em cache sem fazer novos downloads
- `--force` ou `-f`: Força novo download mesmo com cache existente
- `--output` ou `-o`: Define o arquivo de saída (padrão: `dados_treinamento/dados_vulnerabilidades.csv`)
- `--source`: Especifica uma fonte única para download (opções: "OWASP ModSecurity CRS", "PayloadsAllTheThings-SQLi", etc.)

## Estrutura do Arquivo de Saída

O script gera um arquivo CSV com os seguintes campos:

- **text**: Texto simulado contendo payload e contexto (para treinamento)
- **label**: Indicador de vulnerabilidade (1 = vulnerável)
- **tipo_payload**: Tipo de vulnerabilidade (sqli, xss, cmd_injection, etc.)
- **payload**: O payload/vetor de ataque
- **fonte**: Origem do payload

## Integração com o Treinamento

Após o download, você pode usar os dados para treinar o modelo:

```bash
python treinar_modelo_real.py --input dados_treinamento/dados_vulnerabilidades.csv
```

## Requisitos

- Python 3.8+
- Bibliotecas: requests, pandas, pyyaml, tqdm, colorama

## Notas

- Os dados baixados são armazenados em cache para uso futuro
- O script remove automaticamente duplicatas de payloads
- As estatísticas de download são exibidas ao final do processo
