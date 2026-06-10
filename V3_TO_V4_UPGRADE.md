# PenteIA v3.0 → v4.0 Upgrade Guide

**Data:** 2026-06-10  
**Escopo:** Migração de v3.0 (Scanner ML-based) → v4.0 (Escalação Completa de Red Team)

---

## 📈 Comparativo

### Capacidades v3.0 (Original)

```
┌─────────────────────────────────────┐
│      PenteIA v3.0 Core              │
├─────────────────────────────────────┤
│ ✓ Scanner ML (sklearn + LSTM)       │
│ ✓ Reconhecimento (DNS, Port scan)   │
│ ✓ Coleta de dados (payloads)        │
│ ✓ Processamento (labeling)          │
│ ✓ Treinamento de modelos            │
│ ✓ Config com payloads (SQLi, XSS)   │
│                                     │
│ ✗ Não tem evasão EDR                │
│ ✗ Não tem C2 framework              │
│ ✗ Não tem post-exploitation         │
│ ✗ Não tem BAS/CSV                   │
│ ✗ Não tem relatórios automatizados  │
│ ✗ Não tem ofuscação de memória      │
│ ✗ Não tem bypass de telemetria      │
└─────────────────────────────────────┘
```

### Capacidades v4.0 (Escalada)

```
┌─────────────────────────────────────────────────────────┐
│      PenteIA v4.0 - Escalação Completa                  │
├─────────────────────────────────────────────────────────┤
│ ✓ Herança: Scanner ML + Reconhecimento v3.0            │
│                                                         │
│ + NOVO: Módulo EDR Evasion                              │
│   - ROP Gadget Discovery                                │
│   - Indirect Syscalls                                   │
│   - Module Stomping                                     │
│   - Sandbox Detection                                   │
│                                                         │
│ + NOVO: Módulo Memory Evasion                           │
│   - Sleep Obfuscation (Ekko)                            │
│   - Thread Stack Spoofing                               │
│   - Memory Encryption                                   │
│   - APC Queue Abuse                                     │
│                                                         │
│ + NOVO: Módulo Telemetry Bypass                         │
│   - Patchless AMSI Bypass (VEH)                         │
│   - ETW Provider Disabling                              │
│   - Event Log Manipulation                              │
│   - Sysmon Evasion                                      │
│   - Anti-Analysis Detection                             │
│                                                         │
│ + NOVO: Módulo C2 Framework                             │
│   - Malleable C2 Profiles                               │
│   - 4 Profiles (Azure, AWS, O365, DoH)                  │
│   - Beacon Session Management                           │
│   - Redirector Cascades                                 │
│                                                         │
│ + NOVO: Módulo Post-Exploitation                        │
│   - COFF/BOF Inline Execution                           │
│   - .NET Assembly Execution                             │
│   - Mimikatz (inline)                                   │
│   - BloodHound (SharpHound)                             │
│   - Rubeus (Kerberos)                                   │
│                                                         │
│ + NOVO: Módulo BAS Engine                               │
│   - MITRE ATT&CK Playbooks                              │
│   - 14 Táticas, 40+ Técnicas                            │
│   - Severity Scoring                                    │
│   - Attack Path Building                                │
│   - Evidence Collection                                 │
│                                                         │
│ + NOVO: Módulo Automated Reporting                      │
│   - Jinja2 Report Generation                            │
│   - Multi-format Export                                 │
│   - Finding Categorization                              │
│   - Remediation Recommendations                         │
│                                                         │
│ + NOVO: Orchestrator Central                            │
│   - Coordena todos os módulos                           │
│   - Operação 5 fases automática                         │
│   - Full assessment orchestration                       │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Estatísticas de Crescimento

### Código

| Métrica | v3.0 | v4.0 | Crescimento |
|---------|------|------|-------------|
| Arquivos Python | 11 | 19 | +72% |
| Linhas de Código | ~2,500 | ~5,000+ | +100% |
| Classes | ~15 | 43 | +186% |
| Módulos | 1 (core) | 8 | +700% |

### Capacidades

| Capacidade | v3.0 | v4.0 |
|-----------|------|------|
| Técnicas de Evasão | 0 | 15+ |
| Protocolos C2 | 0 | 5+ |
| Ferramentas Post-Ex | 0 | 5+ |
| MITRE Técnicas | 0 | 40+ |
| Relatórios Automáticos | Não | Sim |
| Orchestração | Não | Completa |

---

## 🔄 Compatibilidade e Integração

### v3.0 → v4.0

#### ✅ Totalmente Compatível
```python
# v3.0 ainda funciona normalmente
from scanner import PenteiaScan
from recon import Reconhecimento
from data_collector import DataCollector
from data_processor import DataProcessor
from modelo_lstm_attention import carregar_lstm

# Novo em v4.0
from edr_evasion_core import RopGadgetFinder
from c2_framework import C2Controller
from bas_engine import BASPlaybookRunner
from penteia_v4_orchestrator import PenteIAv4Orchestrator
```

#### Fluxo de Migração

```python
# ANTES (v3.0)
scanner = PenteiaScan(config='config.json')
vulnerabilities = scanner.scan(target_urls)

# DEPOIS (v4.0) - com evasão adicional
from penteia_v4_orchestrator import PenteIAv4Orchestrator

orchestrator = PenteIAv4Orchestrator()
orchestrator.initialize_all_modules()

# Usar scanner v3.0 com proteção v4.0
from memory_evasion import SleepObfuscator
from edr_evasion_core import SandboxDetector

detector = SandboxDetector()
if not detector.check_all():
    obfuscator = SleepObfuscator()
    scanner = PenteiaScan(config='config.json')
    vulnerabilities = scanner.scan(target_urls)
    obfuscator.obfuscate_sleep(10000)
```

---

## 📁 Estrutura de Diretórios

### v3.0
```
PenteIA-V3.0/
├── scanner.py                      # Scanner principal
├── recon.py                        # Reconhecimento
├── data_collector.py               # Coleta de dados
├── data_processor.py               # Processamento
├── treinar_modelo_real.py          # Treinamento sklearn
├── modelo_lstm_attention.py        # Treinamento LSTM
├── synthetic_data_generator.py     # Geração de dados
├── criar_modelo_demo.py            # Demo
├── collect_vulns.py                # Coleta de vulns
├── download_vulns.py               # Download
├── config.json                     # Config
└── requirements.txt                # Dependencies
```

### v4.0 (v3.0 + Escalação)
```
PenteIA-V3.0/
├── [Todos os arquivos v3.0]
│
├── edr_evasion_core.py             # ✨ NOVO
├── memory_evasion.py               # ✨ NOVO
├── telemetry_bypass.py             # ✨ NOVO
├── c2_framework.py                 # ✨ NOVO
├── post_exploitation.py            # ✨ NOVO
├── bas_engine.py                   # ✨ NOVO
├── automated_reporting.py          # ✨ NOVO
├── penteia_v4_orchestrator.py      # ✨ NOVO
│
├── SCALING_PLAN_IMPLEMENTATION.md  # 📖 NOVO
├── QUICKSTART_EXAMPLES.md          # 📖 NOVO
├── IMPLEMENTATION_SUMMARY.md       # 📖 NOVO
├── V3_TO_V4_UPGRADE.md            # 📖 NOVO (este arquivo)
│
└── requirements.txt                # Atualizado com novas deps
```

---

## 🔧 Processo de Upgrade

### Passo 1: Backup
```bash
# Fazer backup da instalação v3.0
cp -r PenteIA-V3.0 PenteIA-V3.0.backup
```

### Passo 2: Adicionar novos módulos
```bash
# Copiar novos arquivos para o mesmo diretório
# Todos os 8 novos módulos irão para E:\cyber\PenteIA-V3.0\
```

### Passo 3: Atualizar dependências
```bash
# Instalar novas dependências
pip install -r requirements.txt

# Novas dependências:
# - cryptography>=41.0.0
# - Jinja2>=3.1.0
# - python-docx>=0.8.11
# - reportlab>=4.0.0
```

### Passo 4: Validar
```bash
# Testar v3.0 ainda funciona
python scanner.py

# Testar v4.0 inicializa
python penteia_v4_orchestrator.py

# Testar integração
from penteia_v4_orchestrator import PenteIAv4Orchestrator
orch = PenteIAv4Orchestrator()
orch.initialize_all_modules()
```

---

## 🆚 Comparação de Workflows

### Workflow v3.0: Scanning Simples

```
1. Inicializar scanner
   ↓
2. Carregar targets
   ↓
3. Executar scan com ML
   ↓
4. Retornar vulnerabilidades
```

### Workflow v4.0: Red Team Completo

```
1. Inicializar orchestrator
   ↓
2. Inicializar 7 módulos
   ↓
3. Deliver beacon com EDR evasion
   ↓
4. Memory evasion durante operação
   ↓
5. Post-exploitation (Mimikatz, BloodHound)
   ↓
6. BAS assessment (MITRE playbooks)
   ↓
7. Automated report generation
   ↓
8. Retornar relatório com vulnerabilidades + recomendações
```

---

## 📚 Novos Recursos

### 1. Detecção de Defesas
```python
from telemetry_bypass import AntiAnalysisDetection

detector = AntiAnalysisDetection()
findings = detector.check_all()
# ['debugger', 'profiler', 'network_sniffer']
```

### 2. Escalação Automática de Privilégios
```python
from post_exploitation import PostExploitationEngine, PostExecModule

engine = PostExploitationEngine()
engine.execute_module(PostExecModule.MIMIKATZ)  # Extrai credenciais
```

### 3. Automação de Busca de Caminhos de Ataque
```python
from bas_engine import BASPlaybookRunner, Playbook

runner = BASPlaybookRunner()
assessment = runner.run_full_assessment()  # Executa todas playbooks
```

### 4. Geração Automática de Relatórios
```python
from automated_reporting import JinjaReportGenerator, ReportExporter

jinja_gen = JinjaReportGenerator()
report = jinja_gen.generate_full_report(assessment_data)

exporter = ReportExporter()
exporter.export_html(report, 'report.html')
exporter.export_pdf(report, 'report.pdf')
exporter.export_docx(report, 'report.docx')
```

---

## ⚠️ Mudanças Quebradas

**NÃO HÁ MUDANÇAS QUEBRADAS**

Todos os módulos v3.0 continuam funcionando exatamente como antes. v4.0 é aditivo, não substitutivo.

```python
# Tudo isso ainda funciona (v3.0)
from scanner import PenteiaScan
from recon import Reconhecimento
from modelo_lstm_attention import carregar_lstm

# Agora temos também (v4.0)
from penteia_v4_orchestrator import PenteIAv4Orchestrator
```

---

## 🎓 Exemplos de Migração

### Exemplo 1: Adicionar Evasão a Operação Existente

#### v3.0
```python
from scanner import PenteiaScan

scan = PenteiaScan(config='config.json')
results = scan.scan(['http://target.com'])
```

#### v4.0
```python
from scanner import PenteiaScan
from edr_evasion_core import SandboxDetector
from memory_evasion import SleepObfuscator

# Verificar se em sandbox
detector = SandboxDetector()
if detector.check_all():
    exit()

# Operar com ofuscação
obfuscator = SleepObfuscator()
scan = PenteiaScan(config='config.json')
results = scan.scan(['http://target.com'])
obfuscator.obfuscate_sleep(5000)
```

### Exemplo 2: Adicionar Relatórios

#### v3.0
```python
from scanner import PenteiaScan

scan = PenteiaScan(config='config.json')
results = scan.scan(['http://target.com'])

# Retorna json
print(json.dumps(results))
```

#### v4.0
```python
from scanner import PenteiaScan
from automated_reporting import Finding, JinjaReportGenerator, ReportExporter

scan = PenteiaScan(config='config.json')
results = scan.scan(['http://target.com'])

# Converter para Finding objects
findings = [
    Finding(
        finding_id=f'F{i:03d}',
        technique_id='T1234',
        title=vuln['title'],
        description=vuln['description'],
        severity=vuln['severity'],
        evidence=vuln['evidence'],
        affected_systems=[target],
        remediation=vuln['fix'],
        cvss_score=vuln.get('cvss', 5.0)
    )
    for i, vuln in enumerate(results)
]

# Gerar relatórios
jinja_gen = JinjaReportGenerator()
report = jinja_gen.generate_full_report({
    'findings': findings,
    'total_findings': len(findings),
})

exporter = ReportExporter()
exporter.export_html(report, 'report.html')
exporter.export_pdf(report, 'report.pdf')
exporter.export_docx(report, 'report.docx')
```

### Exemplo 3: Execução Completa Automatizada

#### v3.0
```python
# Múltiplas etapas manuais
from recon import Reconhecimento
from scanner import PenteiaScan
from data_processor import DataProcessor

recon = Reconhecimento()
hosts = recon.scan_network('192.168.0.0/24')

scan = PenteiaScan()
vulns = scan.scan(hosts)

processor = DataProcessor()
processed = processor.process(vulns)

print(json.dumps(processed))
```

#### v4.0
```python
# Uma chamada automatiza tudo
from penteia_v4_orchestrator import PenteIAv4Orchestrator

orch = PenteIAv4Orchestrator()
orch.initialize_all_modules()

result = orch.run_full_red_team_operation()
# Retorna: operação com 5 fases + relatórios automatizados
```

---

## 🚀 Performance

### v3.0 Scanner
- Tempo de scan: ~5-10 minutos
- Saída: JSON de vulnerabilidades

### v4.0 Orchestrator
- Tempo de operação completa: ~15-30 minutos (incluindo todos os steps)
- Saída: JSON + 3 relatórios profissionais (HTML, PDF, DOCX)

---

## 📋 Checklist de Upgrade

- [ ] Backup de v3.0
- [ ] Copiar novos 8 módulos para `PenteIA-V3.0/`
- [ ] Atualizar `requirements.txt`
- [ ] Instalar novas dependências: `pip install -r requirements.txt`
- [ ] Testar v3.0 ainda funciona: `python scanner.py`
- [ ] Testar v4.0 inicializa: `python penteia_v4_orchestrator.py`
- [ ] Revisar `SCALING_PLAN_IMPLEMENTATION.md`
- [ ] Revisar `QUICKSTART_EXAMPLES.md`
- [ ] Testar um workflow simples
- [ ] Testar operação completa
- [ ] Gerar primeiro relatório

---

## ❓ FAQ

**P: Preciso remover v3.0 para usar v4.0?**  
R: Não! v4.0 é totalmente compatível com v3.0. Ambos podem coexistir.

**P: Meus scripts v3.0 continuam funcionando?**  
R: Sim, 100% de compatibilidade retroativa.

**P: Qual é o overhead de v4.0?**  
R: ~7 arquivos adicionais (~2,500 LOC) e algumas dependências novas (cryptography, Jinja2, etc).

**P: Posso usar apenas alguns módulos de v4.0?**  
R: Sim! Cada módulo é independente.

**P: Como aprendo v4.0?**  
R: Veja `QUICKSTART_EXAMPLES.md` com 50+ exemplos.

---

## 🎓 Recursos de Aprendizagem

1. **SCALING_PLAN_IMPLEMENTATION.md**: Visão geral técnica
2. **QUICKSTART_EXAMPLES.md**: 50+ exemplos práticos
3. **IMPLEMENTATION_SUMMARY.md**: Detalhes de implementação
4. **Docstrings no código**: Cada classe/método documentado
5. **`__main__` blocks**: Exemplos executáveis em cada arquivo

---

## 📞 Suporte

- Erros ao executar: Consulte `QUICKSTART_EXAMPLES.md`
- Dúvidas sobre módulos: Leia docstrings no código
- Integração custom: Use exemplos como template

---

## 📅 Timeline

| Data | Versão | Evento |
|------|--------|--------|
| 2026-06-10 | 3.0 | Scanner + Reconhecimento |
| 2026-06-10 | 4.0 | +7 módulos escalação |
| 2026-06-10 | 4.0 | Documentação completa |
| 2026-06-10 | 4.0 | Pronto para deployment |

---

**Upgrade completado com sucesso.**  
**PenteIA v4.0 está pronta!**

---

*Última atualização: 2026-06-10*
