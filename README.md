# PenteIA - Sistema de Coleta, Análise e Detecção de Vulnerabilidades com IA

Este projeto é uma suite completa de ferramentas Python para coleta automatizada, processamento, visualização e detecção de vulnerabilidades de segurança em aplicações web. O sistema combina técnicas tradicionais de segurança com inteligência artificial para identificar e classificar vulnerabilidades com alta precisão.

![PenteIA Logo](https://via.placeholder.com/800x200/0078D7/FFFFFF?text=PenteIA+Security+Data+Suite)

## 🚀 Ambiente de Teste Recomendado

Para obter dados funcionais com vulnerabilidades reais, recomendamos fortemente o uso do DVWA (Damn Vulnerable Web Application) em um contêiner Docker:

```bash
# Instalar e executar DVWA usando o script fornecido
chmod +x setup_dvwa.sh
./setup_dvwa.sh
```

O DVWA estará disponível em http://localhost/DVWA/ com as seguintes credenciais:
- Usuário: `admin`
- Senha: `password`

Para parar o ambiente de teste:
```bash
docker stop dvwa
```

### Ambientes Alternativos

O coletor também suporta outros ambientes de teste populares. Confira os arquivos de configuração de exemplo em `exemplos/`:

- **OWASP WebGoat**: Ideal para vulnerabilidades mais complexas
  ```bash
  docker run -p 8080:8080 -p 9090:9090 webgoat/webgoat
  ```

- **OWASP Juice Shop**: Aplicação web moderna com vulnerabilidades realistas
  ```bash
  docker run -p 3000:3000 bkimminich/juice-shop
  ```

## ✨ Funcionalidades

### Coleta de Dados (data_collector.py)
- **Teste automatizado** de múltiplos payloads em diferentes URLs
- **Suporte a vários tipos de vulnerabilidades**:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Command Injection
  - NoSQL Injection
  - E outros tipos configuráveis
- **Autenticação integrada** para ambientes que requerem login
- **Detecção inteligente** de sucesso na exploração
- **Configuração flexível** via arquivo JSON
- **Execução paralela** para coleta eficiente (multi-threading)
- **Logging detalhado** das operações e resultados
- **Exportação de resultados** em formato CSV com diferentes níveis de detalhamento

### Processamento de Dados (data_processor.py)
- **Rotulagem automática** utilizando heurísticas avançadas
- **Análise estatística** para detecção de outliers
- **Geração de datasets** específicos por tipo de vulnerabilidade
- **Normalização e limpeza** de dados para treinamento de IA
- **Análise de correlação** entre variáveis numéricas
- **Detecção avançada** de padrões em respostas HTTP

### Visualização de Dados (visualizador.py)
- **Gráficos interativos** para análise de vulnerabilidades
- **Distribuição estatística** por tipo de payload
- **Métricas de taxa de sucesso** por categoria de ataque
- **Análise comparativa** entre diferentes conjuntos de dados
- **Exportação de visualizações** em formato PNG de alta resolução

### Scanner de Vulnerabilidades (scanner.py)
- **Detecção em tempo real** de vulnerabilidades usando IA
- **Análise de links e formulários** para encontrar pontos de injeção
- **Classificação automática** do tipo de vulnerabilidade
- **Avaliação de gravidade** baseada em confiança do modelo
- **Suporte a autenticação** em aplicações protegidas
- **Relatórios detalhados** em formato JSON
- **Interface colorida** no terminal para fácil interpretação
- **Limiar de detecção ajustável** para controle de falsos positivos

### Gerador de Dados Sintéticos (synthetic_data_generator.py)
- **Geração automática** de dados de treinamento
- **Suporte a múltiplos tipos** de vulnerabilidades:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Command Injection
  - XPATH Injection
  - NoSQL Injection
  - Local/Remote File Inclusion
- **Combinação com dados reais** para melhorar a qualidade do treinamento
- **Download de dados públicos** de fontes confiáveis
- **Balanceamento automático** do conjunto de dados

## 📋 Requisitos

- Python 3.6 ou superior
- Docker (para ambientes de teste)
- Bibliotecas Python:
  - requests>=2.28.0
  - pandas>=1.4.0
  - urllib3>=1.26.12
  - numpy>=1.23.5
  - matplotlib>=3.6.2 (opcional, para visualizações)
  - seaborn>=0.12.1 (opcional, para visualizações avançadas)
  - scikit-learn>=1.2.0 (opcional, para análise avançada)
  - tqdm>=4.64.0 (para indicadores de progresso)
  - colorama>=0.4.5 (para saída colorida no terminal)
  - beautifulsoup4>=4.11.0 (para análise de HTML)
  - tensorflow>=2.10.0 (para execução do modelo de IA)

## 🔧 Instalação

```bash
# Clonar o repositório
git clone https://github.com/seu-usuario/penteia-data-collector.git
cd penteia-data-collector

# Instalar dependências
pip install -r requirements.txt

# Configurar ambiente de teste
./setup_dvwa.sh
```

## ⚙️ Configuração

O arquivo `config.json` permite configurar todos os aspectos da coleta de dados:

```json
{
    "urls_alvo": [
        "http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
    ],
    "payloads": {
        "sqli": [
            "' or 1=1--", 
            "1' UNION SELECT 1,2,3--"
        ]
    },
    "auth": {
        "type": "dvwa",
        "login_url": "http://localhost/DVWA/login.php",
        "username": "admin",
        "password": "password"
    }
}
```

Parametrização detalhada:

- **urls_alvo**: Lista de endpoints a serem testados
- **payloads**: Agrupados por categoria, contendo os vetores de ataque
- **auth**: Configurações de autenticação específicas para cada ambiente
- **headers**: Cabeçalhos HTTP personalizados
- **max_workers**: Número de threads paralelas (recomendado: 3-5)
- **timeout**: Tempo limite para cada requisição em segundos
- **delay_between_requests**: Intervalo entre requisições para evitar sobrecarga

## 🚦 Uso

### Coleta de Dados

```bash
# Executar a coleta com a configuração padrão
python data_collector.py

# Usando uma configuração específica
python data_collector.py --config exemplos/config_webgoat.json
```

### Coleta Avançada de Dados

```bash
# Coleta avançada com descoberta automática de páginas
python collect_vulns.py --url http://localhost/DVWA/ --discover --recursive

# Especificar profundidade de exploração
python collect_vulns.py --url http://localhost/DVWA/ --discover --recursive --depth 3
```

### Download de Dados Públicos

```bash
# Baixar dados de vulnerabilidades de fontes públicas
python download_vulns.py

# Baixar uma fonte específica
python download_vulns.py --source "PayloadsAllTheThings-SQLi"
```

### Geração de Dados Sintéticos

```bash
# Gerar dados sintéticos com configurações padrão
python synthetic_data_generator.py

# Gerar um número específico de exemplos
python synthetic_data_generator.py --num_exemplos 5000
```

### Processamento de Dados

```bash
# Processar o arquivo de dados mais recente
python data_processor.py

# Processar um arquivo específico
python data_processor.py resultados/raw_data_20230615_120000.csv

# Ajustar a sensibilidade da detecção (maior valor = mais detecções)
python data_processor.py --sensibilidade 2.0
```

### Treinamento do Modelo

```bash
# Treinar o modelo com os dados processados
python treinar_modelo_real.py

# Treinar com configurações específicas de memória
python treinar_modelo_real.py --memoria_limitada
```

### Scanner de Vulnerabilidades

```bash
# Escanear uma URL em busca de vulnerabilidades
python scanner.py --url http://localhost/DVWA/

# Escanear com autenticação
python scanner.py --url http://localhost/DVWA/ --auth auth_dvwa.json

# Ajustar o limiar de detecção (maior valor = menos falsos positivos)
python scanner.py --url http://localhost/DVWA/ --threshold 0.9
```

## 📊 Estrutura dos Resultados

Os resultados da coleta são salvos no diretório `resultados/` com timestamp:

1. **Dados completos** (`raw_data_YYYYMMDD_HHMMSS.csv`):
   - Contém todas as informações coletadas, incluindo conteúdo HTML das respostas

2. **Resumo** (`raw_data_YYYYMMDD_HHMMSS_resumo.csv`):
   - Versão condensada sem o HTML para análise rápida

3. **Sucessos** (`raw_data_YYYYMMDD_HHMMSS_sucessos.csv`):
   - Apenas os payloads que tiveram sucesso na exploração

## 🔍 Processamento dos Dados

O projeto inclui um processador de dados avançado para preparar datasets de treinamento para modelos de IA:

```bash
# Processar o arquivo de dados mais recente
python data_processor.py

# Processar um arquivo específico
python data_processor.py resultados/raw_data_20230615_120000.csv

# Ajustar a sensibilidade da detecção (maior valor = mais detecções)
python data_processor.py --sensibilidade 2.0

# Forçar o uso do arquivo completo, não o resumo
python data_processor.py --completo

# Desativar análise avançada (mais rápido, mas menos preciso)
python data_processor.py --simples

# Desativar geração de gráficos
python data_processor.py --sem-graficos
```

O processador aplica heurísticas avançadas e análise estatística para rotular os dados e gera:

1. **Dataset completo** (`dados_treinamento/training_data.csv`):
   - Contém as colunas `text`, `label`, `tipo_payload` e `payload`
   - Rótulos: 1 (vulnerável) e 0 (não vulnerável)

2. **Datasets específicos** por tipo de vulnerabilidade:
   - `dados_treinamento/training_sqli.csv` (SQL Injection)
   - `dados_treinamento/training_xss.csv` (Cross-Site Scripting)
   - `dados_treinamento/training_csrf.csv` (Cross-Site Request Forgery)
   - `dados_treinamento/training_cmd_injection.csv` (Command Injection)

3. **Estatísticas e visualizações**:
   - Arquivos JSON com estatísticas detalhadas
   - Gráficos de distribuição de vulnerabilidades
   - Análise de correlação entre variáveis
   - Tudo salvo em `dados_treinamento/estatisticas/`

### 📊 Detecção de Vulnerabilidades

O processador utiliza múltiplas técnicas para identificar vulnerabilidades:

- **Heurísticas por tipo**: Regras específicas para cada tipo de vulnerabilidade
- **Análise de conteúdo**: Busca por padrões e indicadores nas respostas
- **Detecção de outliers**: Identifica comportamentos anômalos estatisticamente
- **Análise de correlação**: Examina relações entre variáveis para identificar padrões
- **Análise de resposta HTTP**: Examina códigos de status, tempos de resposta e tamanhos
- **Análise de payload refletido**: Detecta quando o payload é retornado na resposta
- **Detecção de erros específicos**: Identifica mensagens de erro características de cada vulnerabilidade

A sensibilidade da detecção pode ser ajustada com o parâmetro `--sensibilidade`.

## 🔍 Scanner de Vulnerabilidades

O módulo `scanner.py` é a aplicação prática do modelo de IA treinado, permitindo detectar vulnerabilidades em sistemas reais:

### Características

- **Detecção em tempo real**: Análise imediata de páginas web
- **Crawling inteligente**: Identifica automaticamente links e formulários para teste
- **Classificação por tipo**: Identifica o tipo específico de vulnerabilidade (SQL Injection, XSS, etc.)
- **Avaliação de gravidade**: Classifica as vulnerabilidades como Crítica, Alta ou Média
- **Interface amigável**: Saída colorida no terminal para fácil interpretação
- **Relatórios detalhados**: Salvos em formato JSON para análise posterior

### Formato dos relatórios

Os relatórios são salvos em `relatorios/penteia_scan_[dominio]_[timestamp].json` e contêm:

```json
{
  "url": "http://exemplo.com",
  "timestamp": "2023-07-15T14:30:45.123456",
  "total_tests": 156,
  "total_vulnerabilities": 3,
  "vulnerabilities": [
    {
      "vulnerable": true,
      "probability": 0.97,
      "severity": "CRÍTICA",
      "type": "SQL Injection",
      "url": "http://exemplo.com/busca?q=payload",
      "payload": "' OR 1=1--"
    }
  ]
}
```

### Interpretação dos resultados

O scanner exibe resultados em tempo real com códigos de cores:
- 🔴 **CRÍTICA**: Alta confiança (>95%) de vulnerabilidade explorável
- 🟣 **ALTA**: Forte indicação (90-95%) de vulnerabilidade
- 🟡 **MÉDIA**: Possível vulnerabilidade (80-90%)

Um resumo completo é exibido ao final do escaneamento, facilitando a priorização de correções.

#### Matriz de Indicadores de Detecção

| Tipo de Vulnerabilidade | Indicadores Primários | Indicadores Secundários |
|-------------------------|------------------------|-------------------------|
| SQL Injection           | Erros SQL, múltiplos resultados | Tempo de resposta, padrões de dados |
| XSS                     | Payload refletido, tags HTML injetadas | Elementos JavaScript, eventos DOM |
| Command Injection       | Saída de comandos, listagem de arquivos | Padrões de permissão, conteúdo de sistema |
| CSRF                    | Confirmações de alteração, tokens | Mensagens de sucesso, redirecionamentos |
| NoSQL Injection         | Erros de banco, resultados inesperados | Tempo de resposta, quantidade de dados |

## 📈 Análise dos Dados

Os dados coletados podem ser usados para:

- Treinar modelos de IA para detectar vulnerabilidades
- Analisar padrões de resposta para diferentes tipos de ataques
- Gerar datasets para ferramentas de segurança automatizadas
- Criar casos de teste para verificação de segurança

## 🔄 Arquitetura do Sistema

O PenteIA é composto por seis módulos principais que trabalham em conjunto:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  data_collector  │────>│  data_processor │────>│   visualizador   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  raw_data.csv   │────>│ training_data.csv│────>│   visualizações │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              │
                              ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ synthetic_data  │────>│ treinar_modelo  │────>│     scanner     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                       │
                                                       ▼
                                                ┌─────────────────┐
                                                │    relatórios    │
                                                └─────────────────┘
```

1. **Coleta de Dados**: Os módulos `data_collector.py` e `collect_vulns.py` interagem com aplicações vulneráveis, enviando payloads e coletando respostas.

2. **Download e Geração de Dados**: Os módulos `download_vulns.py` e `synthetic_data_generator.py` obtêm dados adicionais de fontes públicas e geram dados sintéticos.

3. **Processamento**: O módulo `data_processor.py` analisa os dados brutos, aplica heurísticas para rotulagem e gera datasets estruturados para treinamento.

4. **Treinamento**: O módulo `treinar_modelo_real.py` treina o modelo de IA com os dados processados.

5. **Visualização**: O módulo de visualização cria representações visuais dos dados processados para facilitar a análise e interpretação.

6. **Scanner**: O módulo `scanner.py` utiliza o modelo treinado para detectar vulnerabilidades em tempo real em aplicações web alvo.

Esta arquitetura modular permite que cada componente seja utilizado independentemente ou como parte do fluxo completo de trabalho.

## 🔒 Segurança

⚠️ **IMPORTANTE**: Este script deve ser executado APENAS em ambientes de teste controlados. Nunca use esta ferramenta contra sistemas de produção ou sites sem permissão explícita.

O uso indevido desta ferramenta pode violar leis de segurança cibernética e resultar em penalidades legais.

## 🤝 Contribuição

Contribuições são bem-vindas! Para contribuir:

1. Faça um fork do projeto
2. Crie uma nova branch (`git checkout -b feature/nova-funcionalidade`)
3. Faça commit das suas alterações (`git commit -m 'Adiciona nova funcionalidade'`)
4. Envie para o branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

## 📜 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.

## 📞 Contato

Para dúvidas, sugestões ou colaborações, entre em contato através do GitHub.

---

<p align="center">
  Desenvolvido com ❤️ para a comunidade de segurança e IA<br>
  <b>PenteIA v3.0</b> - Sistema de Coleta, Análise e Detecção de Vulnerabilidades<br>
  © 2023-2025 Todos os direitos reservados
</p>

> ⚠️ **AVISO ÉTICO**: Utilize esta ferramenta apenas em sistemas para os quais você tem permissão explícita para testar. O uso indevido pode violar leis de segurança cibernética.