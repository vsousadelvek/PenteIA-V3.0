# PenteIA Scanner - Guia de Uso

## Executando o Scanner

O scanner de vulnerabilidades com IA é uma ferramenta que analisa aplicações web para identificar possíveis vulnerabilidades utilizando um modelo de inteligência artificial treinado com os dados coletados pelo PenteIA.

## 📋 Pré-requisitos

Antes de usar o scanner, certifique-se de que:

1. O ambiente virtual está ativado (se estiver usando um)
2. O modelo treinado existe em `modelos/penteia_model.joblib`
3. Os metadados existem em `modelos/model_meta.json`

> Se ainda não treinou um modelo, gere um de demonstração rápido com:
> `python criar_modelo_demo.py`

## 🚀 Comandos básicos

### Escanear um site público

```bash
# Substitua example.com pela URL do site que você deseja escanear
python scanner.py --url http://example.com
```

### Escanear o DVWA localmente

```bash
# Certifique-se de que o DVWA está rodando
python scanner.py --url http://localhost/DVWA/ --auth auth_dvwa.json
```

### Escanear o WebGoat

```bash
# Certifique-se de que o WebGoat está rodando
python scanner.py --url http://localhost:8080/WebGoat/ --config exemplos/config_webgoat.json
```

### Escanear o OWASP Juice Shop

```bash
# Certifique-se de que o Juice Shop está rodando
python scanner.py --url http://localhost:3000/ --config exemplos/config_juiceshop.json
```

## 🔧 Opções do scanner

| Opção | Descrição |
|-------|------------|
| `--url` ou `-u` | **OBRIGATÓRIO**: URL alvo para escaneamento |
| `--auth` ou `-a` | Arquivo JSON com credenciais de autenticação |
| `--threshold` ou `-t` | Limiar de probabilidade (0.0-1.0, padrão: 0.8) |
| `--config` ou `-c` | Arquivo de configuração personalizado |

## 📊 Interpretando os resultados

O scanner exibe resultados em tempo real com códigos de cores:

- 🔴 **CRÍTICA**: Alta confiança (>95%) de vulnerabilidade explorável
- 🟣 **ALTA**: Forte indicação (90-95%) de vulnerabilidade
- 🟡 **MÉDIA**: Possível vulnerabilidade (80-90%)

Um relatório detalhado é salvo automaticamente na pasta `relatorios/`.

## 🔍 Exemplos de uso avançado

### Ajustar o limiar de detecção

```bash
# Usar um limiar mais rigoroso (menos falsos positivos)
python scanner.py --url http://localhost/DVWA/ --threshold 0.95

# Usar um limiar mais sensível (pode ter mais falsos positivos)
python scanner.py --url http://localhost/DVWA/ --threshold 0.7
```

### Usar com autenticação personalizada

Crie um arquivo JSON com as informações de autenticação:

```json
{
    "login_url": "http://exemplo.com/login",
    "username_field": "user",
    "password_field": "pass",
    "username": "seu_usuario",
    "password": "sua_senha"
}
```

E execute o scanner com:

```bash
python scanner.py --url http://exemplo.com --auth seu_arquivo_auth.json
```

## ⚠️ Solução de problemas

### Modelo não encontrado

Se você receber um erro indicando que o modelo não foi encontrado:

1. Verifique se você já executou o treinamento do modelo
2. Certifique-se de que a pasta `modelos/` existe e contém os arquivos necessários

### Erros de conexão

Se o scanner não conseguir se conectar ao alvo:

1. Verifique se a aplicação alvo está rodando
2. Verifique se você tem acesso à URL (teste no navegador)
3. Para alvos locais, certifique-se de que o Docker ou o servidor web está ativo

## 🔒 Uso ético

Lembre-se de que esta ferramenta deve ser usada apenas em sistemas para os quais você tem permissão explícita para testar. O uso indevido pode violar leis e regulamentos de segurança cibernética.
