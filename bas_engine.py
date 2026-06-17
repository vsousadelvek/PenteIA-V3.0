#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
BAS Engine - PenteIA v4.0
Breach and Attack Simulation / Continuous Security Validation
- MITRE ATT&CK playbook automation (150+ técnicas, 14 táticas)
- Technique execution and evidence collection
- Severity scoring and detection coverage
"""

import json
import uuid
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum
import hashlib


class MITRETactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class MITRETechnique:
    """Representa uma técnica MITRE ATT&CK"""

    def __init__(self, technique_id: str, name: str, tactic: MITRETactic,
                 description: str, severity: str = "medium"):
        self.technique_id = technique_id
        self.name = name
        self.tactic = tactic
        self.description = description
        self.severity = severity
        self.platforms = ["Windows", "Linux", "macOS"]
        self.executable = True

    def to_dict(self) -> dict:
        return {
            'technique_id': self.technique_id,
            'name': self.name,
            'tactic': self.tactic.value,
            'tactic_name': self.tactic.name,
            'description': self.description,
            'severity': self.severity,
        }


# ── Biblioteca completa de técnicas MITRE ATT&CK ──────────────────────────────

ALL_TECHNIQUES: List[MITRETechnique] = [

    # ── RECONNAISSANCE (TA0043) ──────────────────────────────────────────────
    MITRETechnique('T1595', 'Active Scanning', MITRETactic.RECONNAISSANCE,
                   'Varredura ativa de portas, serviços e banners via ferramentas automatizadas', 'medium'),
    MITRETechnique('T1595.001', 'Scanning IP Blocks', MITRETactic.RECONNAISSANCE,
                   'Varredura de blocos de IPs para mapear ativos expostos', 'medium'),
    MITRETechnique('T1595.002', 'Vulnerability Scanning', MITRETactic.RECONNAISSANCE,
                   'Uso de scanners (Nessus, OpenVAS) para identificar CVEs conhecidos', 'high'),
    MITRETechnique('T1592', 'Gather Victim Host Info', MITRETactic.RECONNAISSANCE,
                   'Coleta de informações sobre hardware, OS e configurações do alvo', 'low'),
    MITRETechnique('T1592.002', 'Software Discovery', MITRETactic.RECONNAISSANCE,
                   'Identificação de softwares instalados via banner grabbing e fingerprinting', 'medium'),
    MITRETechnique('T1591', 'Gather Victim Org Info', MITRETactic.RECONNAISSANCE,
                   'Coleta de informações organizacionais via OSINT (LinkedIn, RIPE, WHOIS)', 'low'),
    MITRETechnique('T1589', 'Gather Victim Identity Info', MITRETactic.RECONNAISSANCE,
                   'Coleta de emails, nomes e credenciais via OSINT e data breaches', 'medium'),
    MITRETechnique('T1590', 'Gather Victim Network Info', MITRETactic.RECONNAISSANCE,
                   'Mapeamento de rede: ASN, blocos de IP, DNS, topologia', 'medium'),
    MITRETechnique('T1596', 'Search Open Technical Databases', MITRETactic.RECONNAISSANCE,
                   'Consulta a Shodan, Censys, VirusTotal para informações técnicas do alvo', 'medium'),
    MITRETechnique('T1598', 'Phishing for Information', MITRETactic.RECONNAISSANCE,
                   'Coleta de informações via spear-phishing sem payload malicioso', 'high'),

    # ── RESOURCE DEVELOPMENT (TA0042) ────────────────────────────────────────
    MITRETechnique('T1583', 'Acquire Infrastructure', MITRETactic.RESOURCE_DEVELOPMENT,
                   'Aquisição de servidores, domínios e IPs para operação', 'medium'),
    MITRETechnique('T1583.001', 'Domains', MITRETactic.RESOURCE_DEVELOPMENT,
                   'Registro de domínios similares ao alvo para phishing/C2', 'medium'),
    MITRETechnique('T1583.003', 'Virtual Private Server', MITRETactic.RESOURCE_DEVELOPMENT,
                   'Uso de VPS para hospedar infraestrutura de C2 anônima', 'medium'),
    MITRETechnique('T1584', 'Compromise Infrastructure', MITRETactic.RESOURCE_DEVELOPMENT,
                   'Comprometimento de servidores legítimos de terceiros para relay de ataques', 'high'),
    MITRETechnique('T1587', 'Develop Capabilities', MITRETactic.RESOURCE_DEVELOPMENT,
                   'Desenvolvimento de malware, exploits e ferramentas customizadas', 'high'),
    MITRETechnique('T1588', 'Obtain Capabilities', MITRETactic.RESOURCE_DEVELOPMENT,
                   'Obtenção de ferramentas: Cobalt Strike, Metasploit, exploits de 0day', 'high'),

    # ── INITIAL ACCESS (TA0001) ──────────────────────────────────────────────
    MITRETechnique('T1566', 'Phishing', MITRETactic.INITIAL_ACCESS,
                   'Envio de emails maliciosos com links ou anexos para ganhar acesso inicial', 'high'),
    MITRETechnique('T1566.001', 'Spearphishing Attachment', MITRETactic.INITIAL_ACCESS,
                   'Email direcionado com anexo malicioso (Office macro, PDF exploit)', 'critical'),
    MITRETechnique('T1566.002', 'Spearphishing Link', MITRETactic.INITIAL_ACCESS,
                   'Email com link para site falso ou download de payload', 'high'),
    MITRETechnique('T1190', 'Exploit Public-Facing Application', MITRETactic.INITIAL_ACCESS,
                   'Exploração de aplicações web expostas: SQLi, RCE, SSRF, XXE', 'critical'),
    MITRETechnique('T1133', 'External Remote Services', MITRETactic.INITIAL_ACCESS,
                   'Acesso via VPN, RDP, Citrix ou outros serviços remotos expostos', 'high'),
    MITRETechnique('T1078', 'Valid Accounts', MITRETactic.INITIAL_ACCESS,
                   'Uso de credenciais legítimas obtidas por phishing, dump ou compra', 'high'),
    MITRETechnique('T1091', 'Replication Through Removable Media', MITRETactic.INITIAL_ACCESS,
                   'Infecção via USB/mídia removível com autorun ou LNK malicioso', 'medium'),
    MITRETechnique('T1195', 'Supply Chain Compromise', MITRETactic.INITIAL_ACCESS,
                   'Comprometimento da cadeia de suprimentos: software, hardware ou dependências', 'critical'),
    MITRETechnique('T1199', 'Trusted Relationship', MITRETactic.INITIAL_ACCESS,
                   'Acesso via parceiro/fornecedor com acesso privilegiado ao ambiente alvo', 'high'),

    # ── EXECUTION (TA0002) ───────────────────────────────────────────────────
    MITRETechnique('T1059', 'Command and Scripting Interpreter', MITRETactic.EXECUTION,
                   'Uso de interpretadores de script para executar comandos maliciosos', 'high'),
    MITRETechnique('T1059.001', 'PowerShell', MITRETactic.EXECUTION,
                   'Execução de comandos via PowerShell: download, bypass de políticas, shellcode', 'high'),
    MITRETechnique('T1059.002', 'AppleScript', MITRETactic.EXECUTION,
                   'Uso de AppleScript em macOS para execução de comandos do sistema', 'medium'),
    MITRETechnique('T1059.003', 'Windows Command Shell', MITRETactic.EXECUTION,
                   'Execução via cmd.exe: batch scripts, pipes, redirecionamentos', 'high'),
    MITRETechnique('T1059.004', 'Unix Shell', MITRETactic.EXECUTION,
                   'Shell scripts em bash/sh para execução em Linux/macOS', 'high'),
    MITRETechnique('T1059.006', 'Python', MITRETactic.EXECUTION,
                   'Scripts Python para execução de payloads, reverse shells e automação', 'medium'),
    MITRETechnique('T1059.007', 'JavaScript', MITRETactic.EXECUTION,
                   'Node.js ou JS em browser para XSS, BeEF hooks e execução no cliente', 'medium'),
    MITRETechnique('T1047', 'WMI Execution', MITRETactic.EXECUTION,
                   'Execução remota de comandos via Windows Management Instrumentation', 'high'),
    MITRETechnique('T1053', 'Scheduled Task/Job', MITRETactic.EXECUTION,
                   'Uso de tarefas agendadas para execução de payloads persistentes', 'medium'),
    MITRETechnique('T1072', 'Software Deployment Tools', MITRETactic.EXECUTION,
                   'Abuso de ferramentas de deploy (Ansible, Chef, Puppet) para execução lateral', 'high'),
    MITRETechnique('T1106', 'Native API', MITRETactic.EXECUTION,
                   'Chamadas diretas à API do SO para evitar detecção por hooking de userland', 'high'),
    MITRETechnique('T1129', 'Shared Modules', MITRETactic.EXECUTION,
                   'Carregamento de DLLs ou shared objects maliciosos via módulos do sistema', 'medium'),
    MITRETechnique('T1204', 'User Execution', MITRETactic.EXECUTION,
                   'Engano do usuário para executar arquivo malicioso (double extension, ícone falso)', 'high'),

    # ── PERSISTENCE (TA0003) ─────────────────────────────────────────────────
    MITRETechnique('T1547.001', 'Registry Run Keys', MITRETactic.PERSISTENCE,
                   'Persistência via HKCU/HKLM Run keys no registro do Windows', 'medium'),
    MITRETechnique('T1053.005', 'Scheduled Task', MITRETactic.PERSISTENCE,
                   'Tarefa agendada no Windows para execução recorrente de payload', 'medium'),
    MITRETechnique('T1053.003', 'Cron', MITRETactic.PERSISTENCE,
                   'Entrada no crontab Linux/macOS para persistência via script', 'medium'),
    MITRETechnique('T1137.006', 'Office Add-ins', MITRETactic.PERSISTENCE,
                   'Add-in do Office malicioso carregado automaticamente ao abrir Word/Excel', 'high'),
    MITRETechnique('T1098', 'Account Manipulation', MITRETactic.PERSISTENCE,
                   'Criação ou modificação de conta para manter acesso futuro', 'high'),
    MITRETechnique('T1136', 'Create Account', MITRETactic.PERSISTENCE,
                   'Criação de conta local ou de domínio para backdoor de longo prazo', 'high'),
    MITRETechnique('T1197', 'BITS Jobs', MITRETactic.PERSISTENCE,
                   'Uso de Background Intelligent Transfer Service para download/execução persistente', 'medium'),
    MITRETechnique('T1543', 'Create or Modify System Process', MITRETactic.PERSISTENCE,
                   'Criação de serviço Windows ou daemon Linux malicioso com inicialização automática', 'high'),
    MITRETechnique('T1543.003', 'Windows Service', MITRETactic.PERSISTENCE,
                   'Serviço Windows malicioso instalado com sc.exe ou API de serviços', 'high'),
    MITRETechnique('T1574', 'Hijack Execution Flow', MITRETactic.PERSISTENCE,
                   'DLL hijacking, PATH manipulation ou LD_PRELOAD para sequestro de execução', 'high'),
    MITRETechnique('T1556', 'Modify Authentication Process', MITRETactic.PERSISTENCE,
                   'Modificação do processo de autenticação para bypass ou credential harvesting', 'critical'),
    MITRETechnique('T1505.003', 'Web Shell', MITRETactic.PERSISTENCE,
                   'Upload de web shell para acesso persistente via HTTP/HTTPS', 'critical'),

    # ── PRIVILEGE ESCALATION (TA0004) ────────────────────────────────────────
    MITRETechnique('T1548.004', 'Elevated Execution with Prompt', MITRETactic.PRIVILEGE_ESCALATION,
                   'Execução com privilégios elevados via prompt de UAC ou sudo', 'high'),
    MITRETechnique('T1055', 'Process Injection', MITRETactic.PRIVILEGE_ESCALATION,
                   'Injeção de código em processo privilegiado: DLL injection, shellcode injection', 'critical'),
    MITRETechnique('T1055.001', 'DLL Injection', MITRETactic.PRIVILEGE_ESCALATION,
                   'Injeção de DLL maliciosa em processo privilegiado via LoadLibrary', 'critical'),
    MITRETechnique('T1055.012', 'Process Hollowing', MITRETactic.PRIVILEGE_ESCALATION,
                   'Esvaziamento de processo legítimo e substituição por código malicioso', 'critical'),
    MITRETechnique('T1134', 'Access Token Manipulation', MITRETactic.PRIVILEGE_ESCALATION,
                   'Roubo ou impersonação de token de acesso de processo privilegiado', 'critical'),
    MITRETechnique('T1484', 'Domain Policy Modification', MITRETactic.PRIVILEGE_ESCALATION,
                   'Modificação de GPO de domínio para escalação em todo o AD', 'critical'),
    MITRETechnique('T1611', 'Escape to Host', MITRETactic.PRIVILEGE_ESCALATION,
                   'Fuga de container Docker/Kubernetes para o host subjacente', 'critical'),
    MITRETechnique('T1068', 'Exploitation for Privilege Escalation', MITRETactic.PRIVILEGE_ESCALATION,
                   'Exploração de CVE de kernel ou driver para obter SYSTEM/root', 'critical'),

    # ── DEFENSE EVASION (TA0005) ─────────────────────────────────────────────
    MITRETechnique('T1036.005', 'Match Legitimate Name/Location', MITRETactic.DEFENSE_EVASION,
                   'Renomear executável malicioso para nome de processo do sistema (svchost, lsass)', 'high'),
    MITRETechnique('T1562.008', 'Clear Windows Event Logs', MITRETactic.DEFENSE_EVASION,
                   'Limpeza de logs de eventos Windows para remover rastros de atividade', 'high'),
    MITRETechnique('T1070', 'Indicator Removal', MITRETactic.DEFENSE_EVASION,
                   'Remoção de artefatos: logs, prefetch, timestamps, registros', 'high'),
    MITRETechnique('T1070.001', 'Clear Windows Event Logs', MITRETactic.DEFENSE_EVASION,
                   'Uso de wevtutil ou API para limpar event logs', 'high'),
    MITRETechnique('T1070.004', 'File Deletion', MITRETactic.DEFENSE_EVASION,
                   'Deleção segura de arquivos de payload e ferramenta pós-uso', 'medium'),
    MITRETechnique('T1140', 'Deobfuscate/Decode Files', MITRETactic.DEFENSE_EVASION,
                   'Decodificação de payload em base64/XOR/AES para evitar detecção estática', 'high'),
    MITRETechnique('T1202', 'Indirect Command Execution', MITRETactic.DEFENSE_EVASION,
                   'Execução indireta via forfiles, pcalua, msiexec para bypass de whitelist', 'medium'),
    MITRETechnique('T1218', 'System Binary Proxy Execution (LOLBins)', MITRETactic.DEFENSE_EVASION,
                   'Uso de binários legítimos (mshta, regsvr32, certutil) para execução de payload', 'high'),
    MITRETechnique('T1218.011', 'Rundll32', MITRETactic.DEFENSE_EVASION,
                   'Execução de DLL maliciosa via rundll32.exe para bypass de AV', 'high'),
    MITRETechnique('T1222', 'File and Directory Permissions Modification', MITRETactic.DEFENSE_EVASION,
                   'Modificação de ACLs para ocultar arquivos ou permitir acesso não autorizado', 'medium'),
    MITRETechnique('T1562', 'Impair Defenses', MITRETactic.DEFENSE_EVASION,
                   'Desativação de AV, EDR, firewall ou regras de auditoria', 'critical'),
    MITRETechnique('T1562.001', 'Disable or Modify Tools', MITRETactic.DEFENSE_EVASION,
                   'Desativação do Windows Defender, Sysmon ou agente EDR via registro ou API', 'critical'),
    MITRETechnique('T1620', 'Reflective Code Loading', MITRETactic.DEFENSE_EVASION,
                   'Carregamento de DLL/shellcode diretamente na memória sem tocar disco', 'critical'),
    MITRETechnique('T1027', 'Obfuscated Files or Information', MITRETactic.DEFENSE_EVASION,
                   'Ofuscação de payload: empacotadores, codificação, criptografia de strings', 'high'),

    # ── CREDENTIAL ACCESS (TA0006) ────────────────────────────────────────────
    MITRETechnique('T1110.001', 'Password Guessing', MITRETactic.CREDENTIAL_ACCESS,
                   'Tentativas de senhas comuns e padrão contra serviços de autenticação', 'high'),
    MITRETechnique('T1187', 'LLMNR/NBNS Poisoning', MITRETactic.CREDENTIAL_ACCESS,
                   'Envenenamento LLMNR/mDNS para captura de hashes NTLMv2 na rede local', 'high'),
    MITRETechnique('T1003', 'OS Credential Dumping', MITRETactic.CREDENTIAL_ACCESS,
                   'Extração de credenciais do LSASS, SAM, NTDS.dit ou keychains', 'critical'),
    MITRETechnique('T1003.001', 'LSASS Memory', MITRETactic.CREDENTIAL_ACCESS,
                   'Dump de memória do processo LSASS para extrair senhas em texto claro', 'critical'),
    MITRETechnique('T1056', 'Input Capture', MITRETactic.CREDENTIAL_ACCESS,
                   'Keylogger ou hook de API para captura de senhas digitadas', 'high'),
    MITRETechnique('T1212', 'Exploitation for Credential Access', MITRETactic.CREDENTIAL_ACCESS,
                   'Exploração de vulnerabilidade para extrair credenciais (EternalBlue, PrintNightmare)', 'critical'),
    MITRETechnique('T1528', 'Steal Application Access Token', MITRETactic.CREDENTIAL_ACCESS,
                   'Roubo de tokens OAuth/JWT/API de aplicações para acesso a serviços cloud', 'high'),
    MITRETechnique('T1539', 'Steal Web Session Cookie', MITRETactic.CREDENTIAL_ACCESS,
                   'Extração de cookies de sessão via XSS, MitM ou acesso ao filesystem', 'high'),
    MITRETechnique('T1552', 'Unsecured Credentials', MITRETactic.CREDENTIAL_ACCESS,
                   'Busca de credenciais em arquivos de config, env vars, scripts e repositórios', 'high'),
    MITRETechnique('T1558', 'Steal or Forge Kerberos Tickets', MITRETactic.CREDENTIAL_ACCESS,
                   'Kerberoasting, Pass-the-Ticket, Golden Ticket para comprometimento do AD', 'critical'),
    MITRETechnique('T1110.003', 'Password Spraying', MITRETactic.CREDENTIAL_ACCESS,
                   'Uma senha contra muitos usuários para evitar lockout de conta', 'high'),

    # ── DISCOVERY (TA0007) ───────────────────────────────────────────────────
    MITRETechnique('T1040', 'Network Sniffing', MITRETactic.DISCOVERY,
                   'Captura de tráfego de rede para análise de protocolos e credenciais', 'medium'),
    MITRETechnique('T1007', 'System Service Discovery', MITRETactic.DISCOVERY,
                   'Enumeração de serviços em execução via sc.exe, tasklist ou systemctl', 'low'),
    MITRETechnique('T1010', 'Application Window Discovery', MITRETactic.DISCOVERY,
                   'Enumeração de janelas abertas para identificar aplicações em uso', 'low'),
    MITRETechnique('T1012', 'Query Registry', MITRETactic.DISCOVERY,
                   'Consulta ao registro Windows para enumerar software, configurações e credenciais', 'medium'),
    MITRETechnique('T1016', 'System Network Configuration Discovery', MITRETactic.DISCOVERY,
                   'Enumeração de interfaces de rede, rotas, DNS e configurações de proxy', 'low'),
    MITRETechnique('T1018', 'Remote System Discovery', MITRETactic.DISCOVERY,
                   'Descoberta de hosts na rede via ping sweep, ARP, nbtscan', 'medium'),
    MITRETechnique('T1033', 'System Owner/User Discovery', MITRETactic.DISCOVERY,
                   'Identificação do usuário atual e membros de grupos privilegiados', 'low'),
    MITRETechnique('T1049', 'System Network Connections Discovery', MITRETactic.DISCOVERY,
                   'Enumeração de conexões de rede estabelecidas via netstat', 'low'),
    MITRETechnique('T1057', 'Process Discovery', MITRETactic.DISCOVERY,
                   'Listagem de processos em execução para identificar AV/EDR e aplicações', 'low'),
    MITRETechnique('T1082', 'System Information Discovery', MITRETactic.DISCOVERY,
                   'Coleta de informações do sistema: OS, patches, arquitetura, hostname', 'low'),
    MITRETechnique('T1083', 'File and Directory Discovery', MITRETactic.DISCOVERY,
                   'Enumeração de arquivos e diretórios para encontrar dados sensíveis', 'medium'),
    MITRETechnique('T1518', 'Software Discovery', MITRETactic.DISCOVERY,
                   'Enumeração de softwares instalados para identificar versões vulneráveis', 'low'),
    MITRETechnique('T1087', 'Account Discovery', MITRETactic.DISCOVERY,
                   'Enumeração de contas locais, de domínio e de serviços cloud', 'medium'),
    MITRETechnique('T1069', 'Permission Groups Discovery', MITRETactic.DISCOVERY,
                   'Enumeração de grupos e suas permissões no AD, Azure AD ou Linux', 'medium'),

    # ── LATERAL MOVEMENT (TA0008) ────────────────────────────────────────────
    MITRETechnique('T1021.001', 'RDP', MITRETactic.LATERAL_MOVEMENT,
                   'Movimento lateral via Remote Desktop Protocol com credenciais válidas', 'high'),
    MITRETechnique('T1570', 'Lateral Tool Transfer via SMB', MITRETactic.LATERAL_MOVEMENT,
                   'Transferência de ferramentas entre hosts via compartilhamentos SMB', 'high'),
    MITRETechnique('T1021.002', 'SMB/Windows Admin Shares', MITRETactic.LATERAL_MOVEMENT,
                   'Acesso a C$, ADMIN$, IPC$ para movimento lateral e execução remota', 'high'),
    MITRETechnique('T1021.004', 'SSH', MITRETactic.LATERAL_MOVEMENT,
                   'Uso de SSH com chaves roubadas ou credenciais para movimento lateral Linux', 'medium'),
    MITRETechnique('T1210', 'Exploitation of Remote Services', MITRETactic.LATERAL_MOVEMENT,
                   'Exploração de serviços remotos vulneráveis para mover lateralmente', 'critical'),
    MITRETechnique('T1534', 'Internal Spearphishing', MITRETactic.LATERAL_MOVEMENT,
                   'Phishing interno de conta comprometida para infectar outros usuários', 'high'),
    MITRETechnique('T1563', 'Remote Service Session Hijacking', MITRETactic.LATERAL_MOVEMENT,
                   'Sequestro de sessões RDP, SSH ou VNC ativas de outros usuários', 'critical'),
    MITRETechnique('T1550', 'Use Alternate Authentication Material', MITRETactic.LATERAL_MOVEMENT,
                   'Pass-the-Hash, Pass-the-Ticket, Pass-the-Cookie para movimento sem senha', 'critical'),

    # ── COLLECTION (TA0009) ──────────────────────────────────────────────────
    MITRETechnique('T1005', 'Data from Local System', MITRETactic.COLLECTION,
                   'Coleta de arquivos sensíveis do sistema local: config, DB, docs, keys', 'high'),
    MITRETechnique('T1025', 'Data from Removable Media', MITRETactic.COLLECTION,
                   'Coleta de dados de USB, DVDs ou outros dispositivos de mídia removível', 'medium'),
    MITRETechnique('T1039', 'Data from Network Shared Drive', MITRETactic.COLLECTION,
                   'Coleta de dados de compartilhamentos de rede: file servers, NAS, SharePoint', 'high'),
    MITRETechnique('T1074', 'Data Staged', MITRETactic.COLLECTION,
                   'Agregação e preparação de dados roubados para exfiltração em um staging point', 'medium'),
    MITRETechnique('T1113', 'Screen Capture', MITRETactic.COLLECTION,
                   'Captura de screenshots da tela do usuário para espionagem', 'medium'),
    MITRETechnique('T1119', 'Automated Collection', MITRETactic.COLLECTION,
                   'Scripts para coletar automaticamente tipos específicos de arquivos sensíveis', 'high'),
    MITRETechnique('T1185', 'Browser Session Hijacking', MITRETactic.COLLECTION,
                   'Acesso ao perfil do browser para roubo de cookies, senhas salvas e histórico', 'high'),
    MITRETechnique('T1114', 'Email Collection', MITRETactic.COLLECTION,
                   'Coleta de emails via acesso a mailbox local, IMAP ou Exchange/O365 API', 'high'),

    # ── COMMAND AND CONTROL (TA0011) ──────────────────────────────────────────
    MITRETechnique('T1071', 'Application Layer Protocol', MITRETactic.COMMAND_CONTROL,
                   'C2 via protocolo de aplicação (HTTP, HTTPS, DNS, SMTP) para blending', 'medium'),
    MITRETechnique('T1071.001', 'Web Protocols', MITRETactic.COMMAND_CONTROL,
                   'C2 via HTTP/HTTPS para mistura com tráfego legítimo de navegação', 'medium'),
    MITRETechnique('T1071.004', 'DNS', MITRETactic.COMMAND_CONTROL,
                   'C2 via consultas DNS (TXT, CNAME) para bypassar proxies corporativos', 'high'),
    MITRETechnique('T1090', 'Proxy', MITRETactic.COMMAND_CONTROL,
                   'Uso de proxies, Tor ou botnets para ocultar origem do tráfego C2', 'high'),
    MITRETechnique('T1095', 'Non-Application Layer Protocol', MITRETactic.COMMAND_CONTROL,
                   'C2 via ICMP, raw sockets ou protocolos não HTTP para evasão', 'high'),
    MITRETechnique('T1102', 'Web Service', MITRETactic.COMMAND_CONTROL,
                   'Abuso de serviços legítimos (Pastebin, GitHub, Slack) como canal C2', 'medium'),
    MITRETechnique('T1104', 'Multi-Stage Channels', MITRETactic.COMMAND_CONTROL,
                   'Uso de múltiplos canais C2 em fases distintas para resiliência', 'high'),
    MITRETechnique('T1132', 'Data Encoding', MITRETactic.COMMAND_CONTROL,
                   'Codificação de tráfego C2 em base64, XOR ou outros esquemas', 'medium'),
    MITRETechnique('T1573', 'Encrypted Channel', MITRETactic.COMMAND_CONTROL,
                   'Criptografia do canal C2 com TLS customizado ou criptografia proprietária', 'high'),

    # ── EXFILTRATION (TA0010) ────────────────────────────────────────────────
    MITRETechnique('T1041', 'Exfiltration Over C2 Channel', MITRETactic.EXFILTRATION,
                   'Exfiltração de dados pelo mesmo canal C2 já estabelecido', 'high'),
    MITRETechnique('T1048', 'Exfiltration Over Alternative Protocol', MITRETactic.EXFILTRATION,
                   'Exfiltração via DNS, ICMP, FTP ou outros protocolos alternativos ao C2', 'high'),
    MITRETechnique('T1048.003', 'Exfiltration Over Unencrypted Protocol', MITRETactic.EXFILTRATION,
                   'Exfiltração via HTTP, FTP ou SMTP sem criptografia — detectável em DLP', 'medium'),
    MITRETechnique('T1011', 'Exfiltration Over Other Network Medium', MITRETactic.EXFILTRATION,
                   'Exfiltração via Bluetooth, WiFi ad-hoc ou outros meios alternativos', 'medium'),
    MITRETechnique('T1020', 'Automated Exfiltration', MITRETactic.EXFILTRATION,
                   'Script automatizado para exfiltrar dados coletados de forma contínua', 'high'),
    MITRETechnique('T1029', 'Scheduled Transfer', MITRETactic.EXFILTRATION,
                   'Exfiltração programada em horários de menor monitoramento (madrugada)', 'medium'),
    MITRETechnique('T1030', 'Data Transfer Size Limits', MITRETactic.EXFILTRATION,
                   'Fragmentação dos dados exfiltrados em pequenos pacotes para evitar DLP', 'medium'),
    MITRETechnique('T1537', 'Transfer Data to Cloud Account', MITRETactic.EXFILTRATION,
                   'Upload de dados para conta cloud controlada pelo atacante (S3, Dropbox, GDrive)', 'high'),

    # ── IMPACT (TA0040) ──────────────────────────────────────────────────────
    MITRETechnique('T1485', 'Data Destruction', MITRETactic.IMPACT,
                   'Destruição permanente de dados: wipe de disco, destruição de backups', 'critical'),
    MITRETechnique('T1486', 'Data Encrypted for Impact (Ransomware)', MITRETactic.IMPACT,
                   'Criptografia de arquivos com demanda de resgate (ransomware)', 'critical'),
    MITRETechnique('T1489', 'Service Stop', MITRETactic.IMPACT,
                   'Parada de serviços críticos: antivírus, backup, banco de dados, AD', 'high'),
    MITRETechnique('T1490', 'Inhibit System Recovery', MITRETactic.IMPACT,
                   'Deleção de shadow copies, backups e pontos de restauração do sistema', 'critical'),
    MITRETechnique('T1491', 'Defacement', MITRETactic.IMPACT,
                   'Desfiguração de website interno ou externo para impacto reputacional', 'medium'),
    MITRETechnique('T1498', 'Network Denial of Service', MITRETactic.IMPACT,
                   'Ataque de negação de serviço em nível de rede para indisponibilidade', 'high'),
    MITRETechnique('T1499', 'Endpoint Denial of Service', MITRETactic.IMPACT,
                   'Esgotamento de recursos do endpoint: CPU, memória, conexões, threads', 'high'),
    MITRETechnique('T1561', 'Disk Wipe', MITRETactic.IMPACT,
                   'Sobrescrita do MBR, partições ou disco completo para tornar sistema inoperável', 'critical'),
    MITRETechnique('T1529', 'System Shutdown/Reboot', MITRETactic.IMPACT,
                   'Forçar desligamento ou reboot de sistemas críticos para causar indisponibilidade', 'high'),

    # ── BRASIL — Ameaças Endêmicas ────────────────────────────────────────────
    MITRETechnique('BR-PIX-001', 'Pix Transaction Hijacking', MITRETactic.IMPACT,
                   'Interceptação e redirecionamento de transações Pix via AiTM em apps bancários móveis', 'critical'),
    MITRETechnique('BR-PIX-002', 'Pix QR Code Tampering', MITRETactic.COLLECTION,
                   'Substituição de QR Codes Pix em e-commerce e PDVs para desvio de pagamentos', 'high'),
    MITRETechnique('BR-PIX-003', 'Chave Pix Social Engineering', MITRETactic.INITIAL_ACCESS,
                   'Engenharia social via WhatsApp/SMS para obter chaves Pix e senhas bancárias', 'high'),
    MITRETechnique('BR-MALW-001', 'Grandoreiro Banking Trojan', MITRETactic.EXECUTION,
                   'Trojan bancário brasileiro com overlay de tela falsa sobre apps bancários e acesso ao SISBACEN', 'critical'),
    MITRETechnique('BR-MALW-002', 'Guildma/Astaroth RAT', MITRETactic.EXECUTION,
                   'RAT brasileiro usando LOLBins (BITSAdmin, Certutil) para evasão de AV e acesso a home banking', 'critical'),
    MITRETechnique('BR-MALW-003', 'Javali Banking Trojan', MITRETactic.COLLECTION,
                   'Trojan focado em credenciais de bancos brasileiros: BB, Bradesco, Itaú, Santander, CEF', 'critical'),
    MITRETechnique('BR-PHISH-001', 'Brazilian Banking Phishing', MITRETactic.INITIAL_ACCESS,
                   'Phishing direcionado a clientes de bancos BR com páginas clonadas de BB, CEF, Nubank, Itaú', 'high'),
    MITRETechnique('BR-SISBACEN-001', 'SISBACEN Unauthorized Access', MITRETactic.CREDENTIAL_ACCESS,
                   'Acesso não autorizado ao SISBACEN via credential stuffing ou insider threat em instituições financeiras', 'critical'),
    MITRETechnique('BR-PIX-004', 'Pix Mule Account Network', MITRETactic.EXFILTRATION,
                   'Uso de contas laranja para lavagem e fragmentação de transferências Pix ilegais', 'high'),
    MITRETechnique('BR-SOCIAL-001', 'WhatsApp Account Cloning Scam', MITRETactic.INITIAL_ACCESS,
                   'Clonagem de conta WhatsApp para golpe financeiro impersonando contatos da vítima (Golpe do Zap)', 'high'),
]

# Índice por technique_id para busca rápida
TECHNIQUE_INDEX: Dict[str, MITRETechnique] = {t.technique_id: t for t in ALL_TECHNIQUES}


class Playbook:
    """
    Playbook BAS: conjunto de técnicas a executar.
    Baseado em MITRE ATT&CK framework.
    """

    PREDEFINED_PLAYBOOKS = {
        # ── Playbooks originais ───────────────────────────────────────────────
        'lateral_movement': ['T1021.001', 'T1047', 'T1570', 'T1021.002', 'T1550', 'T1563'],
        'credential_harvesting': ['T1110.001', 'T1187', 'T1040', 'T1003', 'T1558', 'T1110.003', 'T1539'],
        'persistence': ['T1547.001', 'T1053.005', 'T1137.006', 'T1543.003', 'T1505.003', 'T1098'],
        'defense_evasion': ['T1548.004', 'T1036.005', 'T1562.008', 'T1562.001', 'T1620', 'T1218', 'T1027'],

        # ── Novos playbooks ───────────────────────────────────────────────────
        'web_app_full_audit': [
            'T1595.002', 'T1190', 'T1059.007', 'T1083', 'T1078', 'T1185',
            'T1552', 'T1499', 'T1190e', 'T1056',
        ],
        'ransomware_simulation': [
            'T1566.001', 'T1059.001', 'T1562.001', 'T1490', 'T1486',
            'T1485', 'T1489', 'T1529',
        ],
        'cloud_attack': [
            'T1537', 'T1528', 'T1078', 'T1195', 'T1190',
            'T1611', 'T1020',
        ],
        'insider_threat': [
            'T1078', 'T1039', 'T1005', 'T1074', 'T1048',
            'T1114', 'T1029',
        ],
        'recon_full': [
            'T1595', 'T1592', 'T1591', 'T1589', 'T1590',
            'T1596', 'T1598',
        ],
        'privilege_escalation': [
            'T1055', 'T1055.001', 'T1055.012', 'T1134', 'T1068',
            'T1484', 'T1611',
        ],
    }

    def __init__(self, name: str, techniques: List[MITRETechnique] = None):
        self.playbook_id = str(uuid.uuid4())
        self.name = name
        self.techniques = techniques or []
        self.created_at = datetime.now()
        self.executed = False
        self.results = []

    @staticmethod
    def from_preset(preset_name: str) -> 'Playbook':
        """Cria playbook a partir de preset"""
        if preset_name not in Playbook.PREDEFINED_PLAYBOOKS:
            raise ValueError(f"Unknown preset: {preset_name}")
        ids = Playbook.PREDEFINED_PLAYBOOKS[preset_name]
        techniques = [TECHNIQUE_INDEX[tid] for tid in ids if tid in TECHNIQUE_INDEX]
        return Playbook(preset_name, techniques)

    @staticmethod
    def get_all_techniques_by_tactic() -> Dict[str, List[MITRETechnique]]:
        """Retorna todas as técnicas agrupadas por tática"""
        by_tactic: Dict[str, List[MITRETechnique]] = {}
        for t in ALL_TECHNIQUES:
            key = t.tactic.name
            by_tactic.setdefault(key, []).append(t)
        return by_tactic


def _empty_artifacts() -> dict:
    return {'files_created': [], 'registry_modified': [], 'processes_spawned': [], 'network_connections': []}


class TechniqueExecutor:
    """Executa técnicas MITRE ATT&CK — usa execution_engine para handlers reais."""

    # Técnicas que têm handler real no execution_engine
    _REAL_HANDLERS = {
        'T1003', 'T1016', 'T1021', 'T1021.001', 'T1021.002', 'T1021.004',
        'T1033', 'T1041', 'T1049', 'T1057', 'T1059', 'T1059.001', 'T1059.003',
        'T1059.004', 'T1070', 'T1070.004', 'T1082', 'T1083', 'T1087',
        'T1087.001', 'T1105', 'T1107', 'T1012', 'T1518', 'T1547', 'T1547.001',
        'T1007', 'T1552', 'T1552.001', 'T1113',
    }

    # Técnicas destrutivas — nunca executar; apenas documentar e observar indicadores
    _DESTRUCTIVE = {
        'T1486', 'T1485', 'T1490', 'T1561', 'T1529', 'T1070.001', 'T1562.008',
        'T1055', 'T1055.001', 'T1055.012', 'T1134', 'T1003.001',
    }

    def __init__(self):
        self.executions = []
        self._eng = None

    def _get_engine(self):
        if self._eng is None:
            try:
                import execution_engine
                self._eng = execution_engine
            except ImportError:
                self._eng = False
        return self._eng if self._eng else None

    def execute(self, technique: MITRETechnique) -> dict:
        execution_id = str(uuid.uuid4())
        tid = technique.technique_id

        # ── Rota 1: handler real no execution_engine ──────────────────────────
        eng = self._get_engine()
        if eng and tid in eng.TECHNIQUE_HANDLERS:
            try:
                raw = eng.execute_technique(tid, 'localhost', 'safe')
                ev_data = raw.get('technique_evidence', {})
                evidence = self._extract_evidence_from_raw(ev_data, technique)
                artifacts = self._extract_artifacts_from_raw(ev_data)
                success = raw.get('status') == 'completed'
                exec_type = 'real'
            except Exception as e:
                evidence = [f'Handler error: {e}']
                artifacts = _empty_artifacts()
                success = False
                exec_type = 'error'

        # ── Rota 2: handler aproximado por prefixo ────────────────────────────
        elif eng:
            base_id = tid.split('.')[0]
            if base_id in eng.TECHNIQUE_HANDLERS:
                try:
                    raw = eng.execute_technique(base_id, 'localhost', 'safe')
                    ev_data = raw.get('technique_evidence', {})
                    evidence = self._extract_evidence_from_raw(ev_data, technique)
                    artifacts = self._extract_artifacts_from_raw(ev_data)
                    success = True
                    exec_type = 'real_parent'
                except Exception:
                    evidence = self._collect_evidence_safe(technique)
                    artifacts = _empty_artifacts()
                    success = True
                    exec_type = 'safe_simulation'
            else:
                evidence = self._collect_evidence_safe(technique)
                artifacts = _empty_artifacts()
                success = True
                exec_type = 'safe_simulation'
        else:
            evidence = self._collect_evidence_safe(technique)
            artifacts = _empty_artifacts()
            success = True
            exec_type = 'safe_simulation'

        # Técnicas destrutivas nunca marcadas como success real
        if tid in self._DESTRUCTIVE:
            exec_type = 'safe_simulation'
            evidence = self._collect_destructive_indicators(technique)

        result = {
            'execution_id': execution_id,
            'technique_id': tid,
            'technique_name': technique.name,
            'tactic': technique.tactic.name,
            'executed_at': datetime.now().isoformat(),
            'success': success,
            'severity': technique.severity,
            'evidence': evidence,
            'artifacts': artifacts,
            'execution_type': exec_type,
            'detection_status': 'executed' if exec_type.startswith('real') else 'simulated',
        }
        self.executions.append(result)
        return result

    # ── Extratores de evidência ───────────────────────────────────────────────

    def _extract_evidence_from_raw(self, ev: dict, technique: MITRETechnique) -> list:
        out = []
        tid = technique.technique_id

        if 'users' in ev:
            out.append(f"Usuários encontrados: {', '.join(str(u) for u in ev['users'][:5])}")
        if 'groups' in ev:
            out.append(f"Grupos: {len(ev['groups'])} grupos locais enumerados")
        if 'admin_members' in ev:
            out.append(f"Membros do grupo Administrators: {len(ev['admin_members'])} entradas")
        if 'shells_available' in ev:
            shells = [s['name'] for s in ev.get('shells_available', []) if s.get('available')]
            out.append(f"Shells disponíveis: {', '.join(shells) or 'nenhum'}")
        if 'system_info' in ev:
            si = ev['system_info']
            out.append(f"Sistema: {si.get('hostname','?')} | OS: {si.get('os','?')} {si.get('os_version','')[:40]}")
        if 'processes_snapshot' in ev:
            out.append(f"Processos capturados: {len(ev['processes_snapshot'])} entradas")
        if 'security_tools_detected' in ev:
            tools = ev['security_tools_detected']
            out.append(f"Ferramentas de segurança detectadas: {', '.join(tools) or 'nenhuma'}")
        if 'autostart_locations' in ev:
            total = sum(len(loc.get('entries', [])) for loc in ev['autostart_locations'])
            out.append(f"Chaves de autostart no registro: {total} entradas")
        if 'connectivity' in ev:
            for svc, v in ev['connectivity'].items():
                status = 'ABERTA' if v.get('open') or v.get('reachable') else 'FECHADA'
                out.append(f"Porta {svc}: {status}")
        if 'interfaces' in ev:
            out.append(f"Interfaces de rede: {len(ev['interfaces'])} linhas coletadas")
        if 'sensitive_paths' in ev:
            total_sensitive = sum(len(p.get('sensitive_files', [])) for p in ev['sensitive_paths'])
            out.append(f"Arquivos sensíveis (.kdbx/.pfx/.pem/.ovpn): {total_sensitive} encontrados")
        if 'phases' in ev:
            for ph in ev['phases']:
                out.append(f"Fase {ph.get('phase','?')}: {ph.get('status', ph.get('error','?'))}")
        if 'edr_test' in ev:
            out.append(f"Arquivo de teste EDR: {ev['edr_test'].get('file_written','?')} — EDR deveria alertar: {ev['edr_test'].get('edr_should_alert')}")
        for label, v in ev.get('connectivity', {}).items() if isinstance(ev.get('connectivity'), dict) else []:
            reach = v.get('reachable', v.get('open', False))
            out.append(f"{label}: {'alcançável' if reach else 'bloqueado'}")
        if 'services' in ev:
            out.append(f"Serviços do sistema: {len(ev['services'])} enumerados")
        if 'software' in ev:
            out.append(f"Softwares instalados: {len(ev['software'])} encontrados")
        if 'credential_files' in ev:
            found = ev['credential_files']
            out.append(f"Arquivos de credenciais localizados: {len(found)} ({', '.join(str(f) for f in found[:3])})")
        if 'registry_keys' in ev:
            out.append(f"Chaves de registro com credenciais: {len(ev['registry_keys'])} verificadas")
        if 'current_user' in ev:
            out.append(f"Usuário atual: {ev['current_user']}")

        if not out:
            for key, val in ev.items():
                if key == 'technique':
                    continue
                if isinstance(val, list) and val:
                    out.append(f"{key}: {len(val)} itens")
                elif isinstance(val, str) and val:
                    out.append(f"{key}: {val[:120]}")
        return out or [f'Técnica {technique.technique_id} executada — sem output estruturado']

    def _extract_artifacts_from_raw(self, ev: dict) -> dict:
        artifacts = _empty_artifacts()
        if 'phases' in ev:
            for ph in ev['phases']:
                if ph.get('phase') == 'create' and ph.get('path'):
                    artifacts['files_created'].append(ph['path'])
        if 'autostart_locations' in ev:
            for loc in ev['autostart_locations']:
                if loc.get('key'):
                    artifacts['registry_modified'].append(loc['key'])
        return artifacts

    def _collect_evidence_safe(self, technique: MITRETechnique) -> list:
        tid = technique.technique_id
        # Safe observation sem handler dedicado
        safe_map = {
            'T1566': ['Email delivery mechanism observado; sem execução de payload'],
            'T1566.001': ['Anexo malicioso simulado; execução bloqueada para segurança'],
            'T1195': ['Supply chain compromise simulado; requer acesso ao repositório de software'],
            'T1110.001': ['Password guessing: verificação de lockout policy'],
            'T1110.003': ['Password spraying: verificação de threshold de lockout'],
            'T1187': ['LLMNR poisoning: requer posição de rede local (ARP)'],
            'T1040': ['Network sniffing: requer interface em modo promíscuo'],
            'T1558': ['Kerberos ticket attack: requer acesso ao KDC'],
            'T1558.003': ['Kerberoasting: SPN enumeration requer credencial de domínio'],
            'T1550': ['Pass-the-Hash: requer hash NTLM capturado previamente'],
            'T1021.001': ['RDP connectivity: testado via TCP port 3389'],
            'T1021.002': ['SMB Admin Shares: testado via TCP port 445'],
            'T1021.004': ['SSH: testado via TCP port 22'],
        }
        evidence = safe_map.get(tid, [])
        if not evidence:
            base = tid.split('.')[0]
            evidence = safe_map.get(base, [f'Técnica {tid} — {technique.name}: observação segura registrada'])
        return evidence

    def _collect_destructive_indicators(self, technique: MITRETechnique) -> list:
        """Para técnicas destrutivas: coleta indicadores de vulnerabilidade sem executar."""
        import subprocess, platform
        evidence = [f'[SAFE MODE] Técnica destrutiva {technique.technique_id} — execução bloqueada para segurança']
        try:
            if platform.system() == 'Windows':
                # Verifica se shadow copies existem (indicador de risco para T1490)
                if technique.technique_id in ('T1490', 'T1486'):
                    r = subprocess.run(['vssadmin', 'list', 'shadows'], capture_output=True, text=True, timeout=5,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
                    if 'No items found' in r.stdout:
                        evidence.append('Shadow copies: NENHUMA — sistema vulnerável a ransomware sem recovery point')
                    else:
                        lines = [l for l in r.stdout.splitlines() if 'Shadow Copy' in l]
                        evidence.append(f'Shadow copies existentes: {len(lines)} — {("recovery possível" if lines else "verificar")}')
                # Verifica se LSASS tem PPL habilitado (T1003.001)
                if technique.technique_id == 'T1003.001':
                    r = subprocess.run(['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa', '/v', 'RunAsPPL'],
                                       capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
                    if '0x1' in r.stdout:
                        evidence.append('LSASS PPL: HABILITADO — proteção contra dump ativa')
                    else:
                        evidence.append('LSASS PPL: DESABILITADO — dump de credenciais possível')
        except Exception:
            pass
        return evidence


class SeverityScorer:
    """Avalia severidade de achados"""

    SEVERITY_SCORES = {
        'critical': 9.0,
        'high': 7.0,
        'medium': 5.0,
        'low': 3.0,
        'info': 1.0,
    }

    def __init__(self):
        self.scored_findings = []

    def score_finding(self, technique: MITRETechnique, success: bool,
                     evidence_count: int) -> float:
        base_score = self.SEVERITY_SCORES.get(technique.severity, 5.0)
        if not success:
            base_score *= 0.5
        if evidence_count > 5:
            base_score += 1.0
        final_score = min(10.0, max(0.0, base_score))
        self.scored_findings.append({
            'technique': technique.technique_id,
            'score': final_score,
            'scored_at': datetime.now().isoformat(),
        })
        return final_score


class BASPlaybookRunner:
    """Runner de playbooks BAS"""

    def __init__(self):
        self.executor = TechniqueExecutor()
        self.scorer = SeverityScorer()
        self.execution_history = []

    def run_playbook(self, playbook: Playbook) -> dict:
        """Executa playbook completo"""
        playbook_execution = {
            'playbook_id': playbook.playbook_id,
            'playbook_name': playbook.name,
            'started_at': datetime.now().isoformat(),
            'technique_results': [],
            'findings': [],
        }

        detected_count = 0
        total_testable = len(playbook.techniques)

        for technique in playbook.techniques:
            tech_result = self.executor.execute(technique)
            playbook_execution['technique_results'].append(tech_result)

            if tech_result['detection_status'] == 'detected':
                detected_count += 1

            score = self.scorer.score_finding(
                technique, tech_result['success'], len(tech_result['evidence'])
            )

            if score >= 5.0:
                playbook_execution['findings'].append({
                    'technique_id': technique.technique_id,
                    'technique_name': technique.name,
                    'tactic': technique.tactic.name,
                    'severity_score': score,
                    'severity_label': self._score_to_label(score),
                    'evidence': tech_result['evidence'],
                    'detection_status': tech_result['detection_status'],
                })

        detection_coverage_pct = round((detected_count / max(total_testable, 1)) * 100, 1)
        playbook_execution['completed_at'] = datetime.now().isoformat()
        playbook_execution['total_findings'] = len(playbook_execution['findings'])
        playbook_execution['detection_coverage_pct'] = detection_coverage_pct

        self.execution_history.append(playbook_execution)
        return playbook_execution

    def _score_to_label(self, score: float) -> str:
        if score >= 9.0: return 'critical'
        elif score >= 7.0: return 'high'
        elif score >= 5.0: return 'medium'
        elif score >= 3.0: return 'low'
        return 'info'

    def run_full_assessment(self) -> dict:
        all_results = {
            'assessment_id': str(uuid.uuid4()),
            'started_at': datetime.now().isoformat(),
            'playbook_results': [],
        }
        for preset_name in Playbook.PREDEFINED_PLAYBOOKS.keys():
            playbook = Playbook.from_preset(preset_name)
            result = self.run_playbook(playbook)
            all_results['playbook_results'].append(result)

        all_results['completed_at'] = datetime.now().isoformat()
        all_results['total_findings'] = sum(r['total_findings'] for r in all_results['playbook_results'])
        return all_results

    def get_execution_history(self) -> List[dict]:
        return self.execution_history


def export_bas_config() -> dict:
    """Exporta configuração do BAS engine"""
    by_tactic = Playbook.get_all_techniques_by_tactic()
    return {
        'version': '4.0-bas-engine',
        'timestamp': datetime.now().isoformat(),
        'total_techniques': len(ALL_TECHNIQUES),
        'presets_available': list(Playbook.PREDEFINED_PLAYBOOKS.keys()),
        'tactics_covered': [t.value for t in MITRETactic],
        'techniques_per_tactic': {k: len(v) for k, v in by_tactic.items()},
        'severity_levels': list(SeverityScorer.SEVERITY_SCORES.keys()),
        'continuous_validation': True,
        'automated_scoring': True,
        'detection_coverage_tracking': True,
    }


BR_TECHNIQUE_IDS = {t.technique_id for t in ALL_TECHNIQUES if t.technique_id.startswith('BR-')}
BR_TECHNIQUES = [t for t in ALL_TECHNIQUES if t.technique_id.startswith('BR-')]


if __name__ == '__main__':
    print("[*] BAS Engine - PenteIA v4.0")
    config = export_bas_config()
    print(json.dumps(config, indent=2))
    print(f"\n[*] Total de técnicas MITRE ATT&CK: {config['total_techniques']}")
