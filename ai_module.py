"""Módulo de IA do PenteIA — motor de inferência para segurança ofensiva.

Prioridade de inferência:
  1. Modelo GGUF local via llama-cpp-python (mais rápido, zero custo, offline)
  2. Anthropic API — claude-haiku-4-5-20251001 (requer ANTHROPIC_API_KEY)
  3. Keyword matching hardcoded (demo mode, sempre funciona)

Modelos GGUF recomendados (Q4_K_M, baixar de HuggingFace):
  • Qwen2.5-3B-Instruct-Q4_K_M.gguf        (~1.9 GB) — mais rápido em CPU
  • Phi-3.5-mini-instruct-Q4_K_M.gguf      (~2.2 GB) — melhor qualidade
  • Llama-3.2-3B-Instruct-Q4_K_M.gguf      (~2.0 GB) — versão Meta
  • SmolLM2-1.7B-Instruct-Q4_K_M.gguf     (~1.1 GB) — super leve

Configuração via variáveis de ambiente:
  PENTEIA_AI_MODEL=/path/to/model.gguf
  PENTEIA_AI_THREADS=6          (default: 6)
  PENTEIA_AI_CTX=4096           (default: 4096)
  PENTEIA_AI_GPU_LAYERS=0       (default: 0 = CPU puro)
  PENTEIA_AI_DISABLED=1         (força modo demo sem LLM)
  PENTEIA_AI_TIMEOUT=60         (timeout por inferência em segundos)
  PENTEIA_AI_MAX_TOKENS=512     (máx tokens por resposta)
  ANTHROPIC_API_KEY=sk-ant-... (ativa fallback Anthropic quando sem GGUF local)
"""
from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import unicodedata
from typing import Any, Generator

# Carrega .env se python-dotenv estiver instalado
try:
    from dotenv import load_dotenv  # type: ignore[import-not-found]
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=False)
except ImportError:
    pass

log = logging.getLogger(__name__)

# ── Instância global ──────────────────────────────────────────────────────────
_LLM: Any | None = None
_LOAD_FAILED: bool = False
_ANTHROPIC_CLIENT: Any | None = None
_ANTHROPIC_FAILED: bool = False
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="penteia_ai"
)

# ── Config ────────────────────────────────────────────────────────────────────

def _cfg(key: str, default: str = "") -> str:
    return os.getenv(f"PENTEIA_AI_{key}", default).strip()

def _is_disabled() -> bool:
    return _cfg("DISABLED").lower() in ("1", "true", "yes")

def _model_path() -> str | None:
    p = _cfg("MODEL") or os.getenv("PENTEIA_LLM_MODEL_PATH", "")
    return p if p and os.path.exists(p) else None

def _timeout() -> int:
    try: return int(_cfg("TIMEOUT", "60"))
    except ValueError: return 60

def _max_tokens() -> int:
    try: return int(_cfg("MAX_TOKENS", "512"))
    except ValueError: return 512


# ── Carregamento lazy do modelo ───────────────────────────────────────────────

def get_llm():
    global _LLM, _LOAD_FAILED
    if _is_disabled() or _LOAD_FAILED:
        return None
    if _LLM is not None:
        return _LLM
    path = _model_path()
    if not path:
        return None
    try:
        from llama_cpp import Llama  # type: ignore[import-not-found]
        threads = int(_cfg("THREADS", "6"))
        ctx     = int(_cfg("CTX", "4096"))
        gpu_l   = int(_cfg("GPU_LAYERS", "0"))
        log.info(f"[AI] carregando modelo: {path} (threads={threads}, ctx={ctx})")
        _LLM = Llama(
            model_path=path, n_ctx=ctx,
            n_threads=threads, n_gpu_layers=gpu_l,
            verbose=False,
        )
        log.info("[AI] modelo carregado com sucesso")
        return _LLM
    except ImportError:
        log.warning("[AI] llama-cpp-python não instalado — modo demo ativo")
        _LOAD_FAILED = True
        return None
    except Exception as e:
        log.error(f"[AI] falha ao carregar: {e}")
        _LOAD_FAILED = True
        return None


def get_anthropic():
    global _ANTHROPIC_CLIENT, _ANTHROPIC_FAILED
    if _ANTHROPIC_FAILED or _is_disabled():
        return None
    if _ANTHROPIC_CLIENT is not None:
        return _ANTHROPIC_CLIENT
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        import anthropic  # type: ignore[import-not-found]
        _ANTHROPIC_CLIENT = anthropic.Anthropic(api_key=api_key)
        log.info("[AI] Anthropic API configurada — modelo: claude-haiku-4-5-20251001")
        return _ANTHROPIC_CLIENT
    except ImportError:
        log.warning("[AI] pacote 'anthropic' não instalado — pip install anthropic")
        _ANTHROPIC_FAILED = True
        return None
    except Exception as e:
        log.error(f"[AI] falha ao inicializar Anthropic: {e}")
        _ANTHROPIC_FAILED = True
        return None


def _infer_anthropic(user_msg: str, max_tokens: int = 512, system: str = "") -> str:
    client = get_anthropic()
    if client is None:
        return ""
    try:
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=max_tokens,
            system=system or _SYSTEM_PERSONA,
            messages=[{"role": "user", "content": user_msg}],
        )
        return resp.content[0].text.strip()
    except Exception as e:
        log.warning(f"[AI] erro Anthropic API: {e}")
        return ""


def status() -> dict:
    llm = get_llm()
    path = _model_path()
    anthropic_client = get_anthropic()

    if _is_disabled():
        return {"available": False, "reason": "disabled", "model": None, "demo_mode": True}
    if llm:
        model_name = os.path.basename(path or "")
        return {"available": True, "reason": "gguf_local", "model": model_name, "demo_mode": False, "backend": "llama_cpp"}
    if anthropic_client:
        return {"available": True, "reason": "anthropic_api", "model": "claude-haiku-4-5-20251001", "demo_mode": False, "backend": "anthropic"}
    if not path:
        return {
            "available": False,
            "reason": "no_model",
            "demo_mode": True,
            "model": None,
            "install_hint": (
                "Opção 1 — Anthropic API (recomendado): defina ANTHROPIC_API_KEY=sk-ant-...\n"
                "Opção 2 — GGUF local: defina PENTEIA_AI_MODEL=/caminho/para/modelo.gguf\n"
                "Modelos GGUF (Hugging Face):\n"
                "  • Qwen/Qwen2.5-3B-Instruct-GGUF  Q4_K_M  ~1.9 GB\n"
                "  • microsoft/Phi-3.5-mini-instruct-gguf  Q4_K_M  ~2.2 GB\n"
                "pip install anthropic  # para Anthropic API\n"
                "pip install llama-cpp-python  # para GGUF local"
            ),
        }
    return {"available": False, "reason": "load_failed", "model": path, "demo_mode": True}


# ── Utilitários ───────────────────────────────────────────────────────────────

_BAD_UNICODE = re.compile(r"[​‌‍‎‏‪-‮⁦-⁩﻿­]")

def _clean(text: str, max_len: int = 800) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("\r", " ").replace("\t", " ")
    text = "".join(
        ch if unicodedata.category(ch) not in ("Cc", "Cf") else " "
        for ch in text
    )
    text = _BAD_UNICODE.sub("", text)
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:max_len]


def _infer(prompt: str, max_tokens: int | None = None, temperature: float = 0.3) -> str:
    llm = get_llm()
    if llm is None:
        return ""
    mt = max_tokens or _max_tokens()
    out = llm(
        prompt, max_tokens=mt,
        temperature=temperature, top_p=0.92,
        stop=["\n\n\n", "###", "---", "USER:", "HUMAN:"],
        echo=False,
    )
    text = (out.get("choices") or [{}])[0].get("text", "").strip()
    return text[:mt * 5]


def _run_with_timeout(fn, *args, **kwargs) -> str | None:
    future = _EXECUTOR.submit(fn, *args, **kwargs)
    try:
        return future.result(timeout=_timeout())
    except concurrent.futures.TimeoutError:
        log.warning(f"[AI] timeout após {_timeout()}s")
        return None
    except Exception as e:
        log.warning(f"[AI] erro na inferência: {e}")
        return None


# ── Prompts ───────────────────────────────────────────────────────────────────

_SYSTEM_PERSONA = (
    "Você é o PenteIA Assistant, um especialista em segurança ofensiva e red team. "
    "Responda SEMPRE em português brasileiro. Seja técnico, direto e objetivo. "
    "Nunca execute ações reais — apenas analise, explique e recomende."
)


def _wrap_chat(user_msg: str, system: str = _SYSTEM_PERSONA) -> str:
    return (
        f"<|system|>{system}<|end|>\n"
        f"<|user|>{user_msg}<|end|>\n"
        f"<|assistant|>"
    )


# ── APIs públicas do módulo ───────────────────────────────────────────────────

def analyze_simulation(sim_data: dict) -> str:
    """Análise detalhada de uma simulação BAS."""
    target   = _clean(str(sim_data.get("target", "alvo")))
    score    = sim_data.get("score", 0)
    total    = sim_data.get("total", 0)
    found    = sim_data.get("found", 0)
    blocked  = sim_data.get("blocked", 0)
    techs    = sim_data.get("techniques", [])
    crits    = [t for t in techs if t.get("cvss_severity") in ("Critical", "High") and t.get("status") == "found"]

    llm = get_llm()

    tech_lines = "\n".join(
        f"  - [{t.get('cvss_severity','?')}] {t.get('id','?')} {t.get('name','?')} (CVSS {t.get('cvss',0)})"
        for t in crits[:8]
    )
    user_msg = (
        f"Analise os resultados desta simulação BAS:\n\n"
        f"Alvo: {target}\n"
        f"Score de risco: {score:.1f}/100\n"
        f"Técnicas testadas: {total} | Vulneráveis: {found} | Bloqueadas: {blocked}\n"
        f"Técnicas críticas/altas encontradas:\n{tech_lines or '  (nenhuma)'}\n\n"
        f"Escreva uma análise técnica com: (1) diagnóstico geral, (2) principais riscos, "
        f"(3) vetor de ataque mais crítico, (4) recomendações prioritárias. Máx 300 palavras."
    )

    if llm:
        result = _run_with_timeout(_infer, _wrap_chat(user_msg), 600, 0.3)
        if result:
            return result

    result = _infer_anthropic(user_msg, max_tokens=600)
    if result:
        return result

    # Fallback demo
    level = "crítico" if score >= 75 else "alto" if score >= 50 else "médio" if score >= 30 else "baixo"
    top = crits[0] if crits else None
    parts = [
        f"**Diagnóstico:** Simulação contra {target} revelou risco {level} (score {score:.0f}/100).",
        f"De {total} técnicas testadas, {found} vulnerabilidades foram confirmadas e {blocked} bloqueadas.",
    ]
    if top:
        parts.append(
            f"**Risco principal:** {top.get('name','?')} ({top.get('id','?')}) — "
            f"CVSS {top.get('cvss',0)}, tática: {top.get('tactic','?')}."
        )
    if score >= 70:
        parts.append(
            "**Ação urgente:** Revise configurações de controle de acesso, aplique patches críticos "
            "e habilite regras de detecção no SIEM para as técnicas encontradas."
        )
    elif score >= 40:
        parts.append(
            "**Recomendação:** Priorize remediação das vulnerabilidades críticas. "
            "Considere validar a cobertura de detecção do SOC com as técnicas identificadas."
        )
    else:
        parts.append(
            "**Postura positiva:** Os controles demonstraram boa efetividade. "
            "Mantenha o ciclo de simulação trimestral para garantir cobertura contínua."
        )
    return " ".join(parts)


def security_chat(question: str, context: str = "") -> str:
    """Assistente de segurança — responde perguntas técnicas."""
    q = _clean(question, 600)
    llm = get_llm()

    ctx_block = f"Contexto da plataforma: {_clean(context, 300)}\n\n" if context else ""
    user_msg = f"{ctx_block}Pergunta: {q}\n\nResponda de forma técnica e objetiva."

    if llm:
        result = _run_with_timeout(_infer, _wrap_chat(user_msg), 512, 0.4)
        if result:
            return result

    result = _infer_anthropic(user_msg, max_tokens=512)
    if result:
        return result

    # Fallback demo — respostas baseadas em palavras-chave
    q_lower = q.lower()

    if any(w in q_lower for w in ["mitre", "att&ck", "technique", "técnica", "tactic", "ttp"]):
        return (
            "O framework MITRE ATT&CK cataloga TTPs (Táticas, Técnicas e Procedimentos) "
            "usados por adversários reais. As 14 táticas vão de Reconhecimento até Impacto. "
            "No PenteIA, use o módulo BAS para testar cobertura de detecção por técnica. "
            "A ATT&CK Matrix visualiza quais técnicas foram testadas/detectadas na sua infraestrutura."
        )
    if any(w in q_lower for w in ["kerberoast", "kerberos", "spn", "ticket granting"]):
        return (
            "**Kerberoasting (T1558.003):** ataque contra o Kerberos do Active Directory. "
            "O atacante solicita TGS tickets para contas de serviço (SPNs) e tenta quebrar "
            "a senha offline com hashcat/john. Mitigações: use senhas longas (+25 chars) "
            "para service accounts, habilite Kerberos AES-256 (desabilite RC4), monitore "
            "Event ID 4769 com cifra 0x17 (RC4). Ative 'Protected Users' para contas privilegiadas."
        )
    if any(w in q_lower for w in ["credential", "credenci", "lsass", "dumping", "mimikatz", "hashdump"]):
        return (
            "**Dump de Credenciais (T1003):** técnicas incluem LSASS memory dump (mimikatz sekurlsa), "
            "SAM database dump, DCSync (T1003.006) e NTDS.dit extraction. "
            "Mitigações: habilite Credential Guard no Windows 10+, PPL para lsass.exe, "
            "monitore acesso ao processo lsass (Sysmon Event ID 10), "
            "bloqueie ferramentas como procdump.exe via WDAC/AppLocker."
        )
    if any(w in q_lower for w in ["active directory", "active-directory", "ad pentest", "domain", "domínio", "ldap"]):
        return (
            "**Pentest de Active Directory:** fluxo típico — enumeração (BloodHound, ldapdomaindump) "
            "→ AS-REP Roasting (T1558.004) para contas sem pré-auth → Kerberoasting (T1558.003) "
            "→ ACL abuse → DCSync para dump de hashes. Ferramentas: BloodHound/SharpHound, "
            "PowerView, Impacket. Defesas: tiering model, PAW, Privileged Access Groups, "
            "Microsoft Defender for Identity (MDI) para detecção de ataques Kerberos."
        )
    if any(w in q_lower for w in ["privilege", "escalada", "privesc", "escalation", "uac", "token"]):
        return (
            "**Escalada de Privilégios:** técnicas comuns — Bypass UAC (T1548.002), "
            "Token Impersonation (T1134.001), DLL Hijacking (T1574.001), "
            "AlwaysInstallElevated (T1546.016), Unquoted Service Path (T1574.009). "
            "No Windows, use WinPEAS/PowerUp para enumerar vetores. "
            "Mitigações: UAC no nível máximo, LAPS, Tiered Administration, "
            "monitorar criação de serviços e modificações de ACL (Event IDs 7045, 4670)."
        )
    if any(w in q_lower for w in ["phishing", "engenharia social", "spear", "email"]):
        return (
            "Phishing é a técnica de acesso inicial mais utilizada (T1566). "
            "O módulo Phishing do PenteIA simula campanhas com rastreamento de abertura, "
            "cliques e coleta de credenciais. Use templates reais (IT reset, HR docs) "
            "e acompanhe taxas por departamento para identificar grupos mais vulneráveis."
        )
    if any(w in q_lower for w in ["wazuh", "siem", "detec", "soc", "alerta"]):
        return (
            "Para maximizar detecção: exporte regras Wazuh via Integrations > Wazuh Export. "
            "As regras geradas incluem mapeamento MITRE e níveis de severidade. "
            "Valide a cobertura real com SOC Validation — selecione uma simulação BAS "
            "e veja quais técnicas seriam detectadas vs. não detectadas pelo seu SIEM."
        )
    if any(w in q_lower for w in ["lateral", "movimento", "pivot", "pass the hash", "pth", "psexec", "wmi"]):
        return (
            "**Movimento Lateral** inclui Pass-the-Hash (T1550.002), PsExec (T1569.002), "
            "WMI (T1047), SMB Admin Shares (T1021.002) e SSH pivoting (T1021.004). "
            "Controles: segmentação de rede (VLANs), LAPS para senhas locais únicas, "
            "monitoramento de autenticações anômalas (Event IDs 4624 tipo 3, 4648) "
            "e alertas para uso de psexec.exe/wmiexec em horários atípicos."
        )
    if any(w in q_lower for w in ["ransomware", "cripto", "criptograf", "encrypt"]):
        return (
            "**Ransomware** segue a cadeia: acesso inicial → escalada → exfiltração → criptografia. "
            "Indicadores críticos: deleção de shadow copies (T1490 — vssadmin/wmic), "
            "criptografia em massa (T1486), C2 via Cobalt Strike/Empire. "
            "Detecte com regras Wazuh para 'vssadmin delete' e 'wmic shadowcopy delete'. "
            "Defesa: backups offline imutáveis, EDR com anti-tamper, segmentação de rede."
        )
    if any(w in q_lower for w in ["sql injection", "sqli", "xss", "csrf", "ssrf", "web application", "owasp", "aplicação web"]):
        return (
            "**Vulnerabilidades Web (OWASP Top 10):** SQLi (A03) — use prepared statements e WAF; "
            "XSS (A03) — sanitize output, Content-Security-Policy; SSRF (A10) — allowlist de destinos; "
            "IDOR (A01) — validação de autorização por objeto; JWT flaws (A02) — valide alg/exp/iss. "
            "No PenteIA BAS, técnicas T1190/T1059 cobrem esses vetores. "
            "Exporte resultados para relatório com CVSS e compliance (OWASP, PCI-DSS)."
        )
    if any(w in q_lower for w in ["scanning", "scan", "nmap", "reconhec", "recon", "enumeração", "discovery"]):
        return (
            "**Reconhecimento (T1595/T1590):** fases — passiva (OSINT: Shodan, LinkedIn, Censys, "
            "certificados TLS, DNS) e ativa (port scan: nmap -sV -sC, masscan para velocidade). "
            "No PenteIA, use o módulo Recon para automação. Detecte scanners via "
            "regras Wazuh para User-Agents suspeitos (sqlmap, nikto) e "
            "volume anormal de conexões (>100 portas em 60s por IP)."
        )
    if any(w in q_lower for w in ["c2", "command and control", "beacon", "cobalt strike", "sliver", "empire"]):
        return (
            "**Command & Control (TA0011):** frameworks modernos — Cobalt Strike (beaconing HTTPS), "
            "Sliver (open source, mTLS), Empire (PowerShell), Brute Ratel C4. "
            "Técnicas de evasão: Domain Fronting (T1090.004), DNS tunneling (T1071.004), "
            "C2 over HTTP/S para domínios legítimos (T1071.001). "
            "Detecte: beaconing periódico, JA3/JA3S fingerprinting no tráfego TLS, "
            "resolução DNS para domínios recém-registrados (DGA)."
        )
    if any(w in q_lower for w in ["payload", "shellcode", "evasão", "evasion", "bypassar", "antivirus", "edr", "amsi"]):
        return (
            "**Evasão e Payloads (T1562/T1027):** técnicas comuns — AMSI bypass (memory patching), "
            "reflective DLL injection, process hollowing (T1055.012), "
            "signed binary proxy (T1218 — certutil, mshta, rundll32). "
            "Ofuscação: base64 + XOR, syscalls diretas (D/Invoke), sleep obfuscation. "
            "No PenteIA, o módulo Evasão gera payloads com opções de codificação e empacotamento. "
            "Valide com YARA + sandbox antes de testes em produção."
        )
    return (
        f"Sobre '{q}': Para análise contextualizada por IA, configure um modelo LLM local: "
        "PENTEIA_AI_MODEL=/caminho/modelo.gguf (reinicie após). "
        "Recomendados: Qwen2.5-3B-Instruct-Q4_K_M (~1.9GB) ou Phi-3.5-mini (~2.2GB) — "
        "ambos rodam 100% em CPU. Enquanto isso, use os módulos BAS, Recon e ATT&CK Matrix "
        "para análise baseada em ML sem necessidade de LLM."
    )


def generate_pentest_plan(target_info: dict) -> str:
    """Gera plano de pentest estruturado baseado no perfil do alvo."""
    target   = _clean(str(target_info.get("target", "")))
    scope    = _clean(str(target_info.get("scope", "")))
    tech     = _clean(str(target_info.get("technologies", "")))
    duration = _clean(str(target_info.get("duration", "5 dias")))
    obj_type = target_info.get("objective", "full")

    llm = get_llm()

    user_msg = (
        f"Crie um plano de pentest detalhado para:\n\n"
        f"Alvo: {target or 'infraestrutura corporativa'}\n"
        f"Escopo: {scope or 'rede interna + aplicações web'}\n"
        f"Tecnologias: {tech or 'Windows AD, Linux, Web Apps'}\n"
        f"Duração: {duration}\n"
        f"Objetivo: {obj_type}\n\n"
        f"Estruture como: Fase 1 Reconhecimento, Fase 2 Scanning, "
        f"Fase 3 Exploração, Fase 4 Pós-exploração, Fase 5 Relatório. "
        f"Inclua técnicas MITRE ATT&CK para cada fase. Máx 400 palavras."
    )

    if llm:
        result = _run_with_timeout(_infer, _wrap_chat(user_msg), 700, 0.35)
        if result:
            return result

    result = _infer_anthropic(user_msg, max_tokens=700)
    if result:
        return result

    # Fallback estruturado
    t = target or "infraestrutura"
    return f"""**Plano de Pentest — {t}** ({duration})

**Fase 1 — Reconhecimento Passivo** (Dia 1)
• OSINT: LinkedIn, Shodan, certificados TLS, DNS (T1596, T1589)
• Identificação de ASN, ranges IP, subdomínios expostos
• Ferramentas: Recon no PenteIA → Cloud Recon

**Fase 2 — Scanning Ativo** (Dia 1-2)
• Port scan completo: TCP/UDP (T1046)
• Fingerprinting de serviços e versões
• Enumeração de usuários, shares SMB, LDAP anônimo (T1018)

**Fase 3 — Exploração** (Dia 2-4)
• Exploração de vulnerabilidades identificadas (T1190, T1203)
• Ataques de credenciais: brute force, password spray (T1110)
• Phishing direcionado se no escopo (T1566)
• Teste de aplicações web: SQLi, XSS, IDOR

**Fase 4 — Pós-exploração** (Dia 4)
• Escalada de privilégios (T1548, T1134)
• Movimento lateral: Pass-the-Hash, PsExec (T1550, T1569)
• Persistência: serviços, scheduled tasks (T1543, T1053)
• Exfiltração simulada (T1041)

**Fase 5 — Relatório** (Dia 5)
• Relatório executivo + técnico via PenteIA > Relatórios
• Evidências, CVSS, remediação prioritizada
• Exportar regras Wazuh para técnicas encontradas"""


def remediation_steps(technique_id: str, technique_name: str, context: str = "") -> str:
    """Gera passos de remediação específicos para uma técnica MITRE."""
    tid  = _clean(technique_id, 20)
    name = _clean(technique_name, 100)
    ctx  = _clean(context, 200)

    llm = get_llm()

    user_msg = (
        f"Gere passos de remediação detalhados para a técnica MITRE ATT&CK:\n\n"
        f"ID: {tid}\nNome: {name}\n"
        f"{('Contexto adicional: ' + ctx) if ctx else ''}\n\n"
        f"Inclua: (1) configuração imediata, (2) monitoramento/detecção, "
        f"(3) hardening de longo prazo, (4) referências (CIS, NIST). "
        f"Formate como lista numerada. Máx 250 palavras."
    )

    if llm:
        result = _run_with_timeout(_infer, _wrap_chat(user_msg), 500, 0.2)
        if result:
            return result

    result = _infer_anthropic(user_msg, max_tokens=500)
    if result:
        return result

    # Fallback por categoria de técnica
    t = tid.upper()
    if t.startswith("T1110"):
        return (
            "**Remediação — Ataques de Credenciais (T1110)**\n"
            "1. Habilite MFA em todos os serviços expostos (prioridade: VPN, email, RDP)\n"
            "2. Configure account lockout: 5 tentativas → bloqueio 30 min\n"
            "3. Implemente política de senhas: mín. 14 chars + complexidade\n"
            "4. Detecte com: alertas SIEM para >5 falhas em 5 min por IP/usuário\n"
            "5. Hardening: desabilite autenticação Basic/NTLM onde possível\n"
            "6. Referência: CIS Control 5, NIST SP 800-63B"
        )
    if t.startswith("T1059"):
        return (
            "**Remediação — Execução via Interpretadores (T1059)**\n"
            "1. Restrinja PowerShell com Constrained Language Mode e AMSI\n"
            "2. Habilite Script Block Logging (GPO: Event ID 4104)\n"
            "3. Bloqueie macros Office em documentos de fontes externas\n"
            "4. Whitelist de scripts via AppLocker ou WDAC\n"
            "5. Detecte: alertas para powershell.exe com -EncodedCommand ou -IEX\n"
            "6. Referência: MITRE D3FEND: harden-interpreter"
        )
    if t.startswith("T1078"):
        return (
            "**Remediação — Uso de Contas Válidas (T1078)**\n"
            "1. Audite contas inativas (desabilite após 30 dias sem uso)\n"
            "2. Implemente PAM para contas privilegiadas\n"
            "3. Revise permissões excessivas (princípio do menor privilégio)\n"
            "4. Detecte: logins fora do horário comercial, geolocalização incomum\n"
            "5. Habilite auditoria de logon (Event IDs 4624, 4625, 4648)\n"
            "6. Referência: CIS Control 4, NIST SP 800-53 AC-2"
        )
    if t.startswith("T1190"):
        return (
            "**Remediação — Exploração de Serviços Públicos (T1190)**\n"
            "1. Patch imediato: identifique CVEs ativos via scan de vulnerabilidade\n"
            "2. WAF na frente de todas as aplicações expostas\n"
            "3. Reduza superfície: desabilite serviços desnecessários\n"
            "4. Segmentação: DMZ para serviços expostos, sem acesso direto à rede interna\n"
            "5. Detecte: alertas IDS/IPS para exploitation patterns, anomalias em logs de acesso\n"
            "6. Referência: OWASP Top 10, CIS Control 7"
        )
    return (
        f"**Remediação — {name} ({tid})**\n"
        "1. Consulte a página do MITRE ATT&CK para mitigações específicas\n"
        "2. Implemente logging e alertas para a técnica no SIEM\n"
        "3. Exporte regra Wazuh via Integrations > Wazuh Export\n"
        "4. Crie ticket de remediação via Remediation Tracker\n"
        "5. Valide cobertura pós-correção com nova simulação BAS\n"
        "Nota: configure PENTEIA_AI_MODEL para análise contextualizada por LLM."
    )


def threat_score(indicators: list[str]) -> dict:
    """Pontua uma lista de IOCs/indicadores e gera explicação."""
    clean_iocs = [_clean(i, 100) for i in indicators[:20]]

    HIGH_RISK = [
        r"mimikatz|sekurlsa|lsass",
        r"cobalt.?strike|cobaltstrike",
        r"empire|meterpreter|metasploit",
        r"vssadmin.*delete|shadowcopy.*delete",
        r"procdump|nanodump",
        r"\bT1059\b|\bT1110\b|\bT1486\b|\bT1003\b",
    ]
    MED_RISK = [
        r"powershell.*-enc|\biex\b|invoke-expression",
        r"certutil.*-urlcache|-decode",
        r"mshta|regsvr32|rundll32",
        r"net user|net localgroup|whoami /all",
    ]

    high, med = 0, 0
    matched_high, matched_med = [], []
    for ioc in clean_iocs:
        for pat in HIGH_RISK:
            if re.search(pat, ioc, re.I):
                high += 1
                matched_high.append(ioc[:60])
                break
        else:
            for pat in MED_RISK:
                if re.search(pat, ioc, re.I):
                    med += 1
                    matched_med.append(ioc[:60])
                    break

    total = len(clean_iocs)
    score = min(100, round((high * 25 + med * 10) / max(total, 1) * 4))

    llm = get_llm()
    explanation = ""
    if high or med:
        ioc_block = "\n".join(f"  - {i}" for i in matched_high[:4] + matched_med[:4])
        user_msg = (
            f"Analise estes indicadores de comprometimento (IOCs) e explique o risco:\n{ioc_block}\n\n"
            f"Score calculado: {score}/100. Dê um parágrafo de análise técnica. Máx 100 palavras."
        )
        if llm:
            explanation = _run_with_timeout(_infer, _wrap_chat(user_msg), 200, 0.3) or ""
        if not explanation:
            explanation = _infer_anthropic(user_msg, max_tokens=200)

    if not explanation:
        if high > 0:
            explanation = f"{high} indicador(es) de alta criticidade detectado(s): presença de ferramentas de ataque conhecidas (Mimikatz, Cobalt Strike, etc.) ou técnicas destrutivas (ransomware, dump de credenciais). Investigação imediata recomendada."
        elif med > 0:
            explanation = f"{med} indicador(es) de criticidade média: uso suspeito de LOLBaS (binários nativos do Windows) ou comandos de enumeração típicos de pós-exploração."
        else:
            explanation = "Nenhum IOC de alto risco identificado nos indicadores fornecidos."

    return {
        "score": score,
        "high_risk_count": high,
        "medium_risk_count": med,
        "total_analyzed": total,
        "matched_high": matched_high,
        "matched_medium": matched_med,
        "explanation": explanation,
        "verdict": "crítico" if score >= 75 else "alto" if score >= 50 else "médio" if score >= 25 else "baixo",
    }
