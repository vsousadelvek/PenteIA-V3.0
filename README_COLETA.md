# Guia para Expandir a Coleta de Dados para Treinamento

Este guia contém instruções para aumentar a quantidade de dados coletados para treinamento do modelo PenteIA.

## Opções para Coleta Avançada

Execute o script `collect_vulns.py` com as seguintes opções para maximizar a coleta de dados:

```bash
python collect_vulns.py --url https://seu-alvo.com --discover --recursive --depth 3 --max-pages 100
```

### Parâmetros disponíveis:

- `--url` ou `-u`: URL personalizada para coleta de dados
- `--discover` ou `-d`: Tenta descobrir páginas com parâmetros
- `--recursive` ou `-r`: Ativa exploração recursiva de links
- `--depth` ou `-dp`: Profundidade de exploração recursiva (default=2)
- `--max-pages` ou `-mp`: Número máximo de páginas a explorar (default=50)
- `--timeout` ou `-t`: Timeout para requisições (segundos)

## Fontes de Dados Recomendadas

Para maximizar a coleta, configure os seguintes ambientes vulneráveis:

1. **DVWA (Damn Vulnerable Web Application)**
   - URL: http://localhost/DVWA/ (após instalação)
   - Credenciais: admin/password
   - Instrução: `python collect_vulns.py --url http://localhost/DVWA/ --discover`

2. **OWASP Juice Shop**
   - URL: http://localhost:3000/ (após instalação)
   - Instrução: `python collect_vulns.py --url http://localhost:3000/ --discover --recursive`

3. **WebGoat**
   - URL: http://localhost:8080/WebGoat/ (após instalação)
   - Credenciais: guest/guest
   - Instrução: `python collect_vulns.py --url http://localhost:8080/WebGoat/ --discover`

4. **bWAPP (buggy Web Application)**
   - URL: http://localhost/bWAPP/ (após instalação)
   - Credenciais: bee/bug
   - Instrução: `python collect_vulns.py --url http://localhost/bWAPP/ --discover --recursive`

5. **OWASP Mutillidae II**
   - URL: http://localhost/mutillidae/ (após instalação)
   - Instrução: `python collect_vulns.py --url http://localhost/mutillidae/ --discover --recursive`

## Estratégias para Maximizar Dados

1. **Execute múltiplas vezes com diferentes opções**
   - Altere a profundidade de exploração
   - Use diferentes URLs de entrada
   - Varie os timeouts para capturar respostas mais lentas

2. **Adicione payloads personalizados**
   - Edite o arquivo `exemplos/config_coleta.json`
   - Adicione mais variações de payloads para cada tipo de vulnerabilidade

3. **Combine os dados de várias execuções**
   - Os dados são automaticamente combinados no arquivo `dados_processados.csv`
   - Execute o processador após várias coletas: `python data_processor.py`

4. **Use o modo de descoberta automática**
   - A opção `--discover` encontrará automaticamente formulários e parâmetros
   - Combine com `--recursive` para máxima cobertura

## Exemplo de Fluxo Completo

```bash
# 1. Coleta em múltiplas fontes
python collect_vulns.py --url http://localhost/DVWA/ --discover --recursive
python collect_vulns.py --url http://localhost:3000/ --discover --recursive
python collect_vulns.py --url http://localhost/bWAPP/ --discover --recursive

# 2. Processa os dados coletados
python data_processor.py

# 3. Treina o modelo com os dados combinados
python treinar_modelo_real.py
```

Ao seguir estas instruções, você conseguirá criar um conjunto de dados muito mais robusto para treinamento do seu modelo de detecção de vulnerabilidades.
