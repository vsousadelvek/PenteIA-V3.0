"""
compliance_engine.py — PenteIA V4.0
Maps MITRE ATT&CK technique IDs to Brazilian and international compliance requirements.

Frameworks covered:
  - LGPD (Lei Geral de Proteção de Dados — Lei 13.709/2018)
  - BACEN 4893/2021 (Política de segurança cibernética para IFs)
  - PCI DSS v4.0
  - ISO 27001:2022
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Compliance reference data
# ---------------------------------------------------------------------------

_LGPD_ART_46 = {
    "article": "Art. 46",
    "title": "Medidas técnicas e administrativas de segurança",
    "description": (
        "Os agentes de tratamento devem adotar medidas de segurança, técnicas e "
        "administrativas aptas a proteger os dados pessoais de acessos não autorizados "
        "e de situações acidentais ou ilícitas de destruição, perda, alteração, "
        "comunicação ou qualquer forma de tratamento inadequado ou ilícito."
    ),
}

_LGPD_ART_47 = {
    "article": "Art. 47",
    "title": "Dever de sigilo e confidencialidade",
    "description": (
        "Os agentes de tratamento ou qualquer outra pessoa que intervenha em uma das "
        "fases do tratamento obriga-se a garantir a segurança das informações em "
        "relação aos dados pessoais, mesmo após o seu término."
    ),
}

_LGPD_ART_48 = {
    "article": "Art. 48",
    "title": "Notificação de incidentes de segurança (72 h)",
    "description": (
        "O controlador deverá comunicar à autoridade nacional e ao titular a ocorrência "
        "de incidente de segurança que possa acarretar risco ou dano relevante aos "
        "titulares. A comunicação deve ser feita em prazo razoável, conforme definido "
        "pela ANPD — interpretado como 72 horas a partir do conhecimento do incidente."
    ),
}

_LGPD_ART_50 = {
    "article": "Art. 50",
    "title": "Boas práticas e governança em proteção de dados",
    "description": (
        "Os controladores e operadores, no âmbito das suas competências, pelo tratamento "
        "de dados pessoais, individualmente ou por meio de associações, poderão formular "
        "regras de boas práticas e de governança que estabeleçam as condições de "
        "organização, o regime de funcionamento, os procedimentos, incluindo reclamações "
        "e petições de titulares, as normas de segurança, os padrões técnicos, as "
        "obrigações específicas para os diversos envolvidos no tratamento, as ações "
        "educativas, os mecanismos internos de supervisão e de mitigação de riscos e "
        "outros aspectos relacionados ao tratamento de dados pessoais."
    ),
}

_BACEN_ART_2 = {
    "article": "Art. 2",
    "title": "Política de segurança cibernética",
    "description": (
        "As instituições financeiras devem implementar e manter política de segurança "
        "cibernética compatível com o porte e o perfil de risco da instituição, "
        "abrangendo objetivos de segurança da informação, procedimentos e controles "
        "para redução da vulnerabilidade a incidentes e mecanismos de autenticação."
    ),
}

_BACEN_ART_4 = {
    "article": "Art. 4",
    "title": "Testes e varreduras anuais",
    "description": (
        "A política de segurança cibernética deve contemplar a realização de testes e "
        "varreduras periodicamente, com no mínimo periodicidade anual, para detecção de "
        "vulnerabilidades nos sistemas de informação das instituições autorizadas a "
        "funcionar pelo Banco Central do Brasil."
    ),
}

_BACEN_ART_5 = {
    "article": "Art. 5",
    "title": "Plano de resposta a incidentes",
    "description": (
        "As instituições devem elaborar e implementar plano de ação e de resposta a "
        "incidentes, contendo procedimentos destinados a reduzir a vulnerabilidade a "
        "incidentes relacionados com o ambiente cibernético e atender aos princípios de "
        "razoabilidade e proporcionalidade, considerado o porte da instituição e o perfil "
        "de seus clientes e de suas transações."
    ),
}

_BACEN_ART_16 = {
    "article": "Art. 16",
    "title": "Continuidade de negócios e recuperação",
    "description": (
        "As instituições devem garantir a continuidade dos serviços de tecnologia da "
        "informação críticos, incluindo plano de continuidade de negócios e testes "
        "periódicos de recuperação de desastres, assegurando a disponibilidade e a "
        "integridade dos dados e dos sistemas."
    ),
}

_PCI_REQ_6_4 = {
    "req": "Req. 6.4",
    "title": "Proteção de aplicações web (WAF / revisão de código)",
    "description": (
        "Proteger aplicações web voltadas ao público contra ataques conhecidos, "
        "implantando um web application firewall (WAF) ou realizando revisão de código "
        "voltada à segurança, com base em metodologias de avaliação reconhecidas pelo "
        "setor (ex.: OWASP)."
    ),
}

_PCI_REQ_8_2 = {
    "req": "Req. 8.2",
    "title": "Identificação e autenticação de usuários",
    "description": (
        "Todos os usuários devem receber um ID único de usuário antes de permitir o "
        "acesso a componentes do sistema ou dados de titulares de cartões. Senhas e "
        "outros autenticadores devem atender a requisitos mínimos de complexidade, "
        "histórico e bloqueio após tentativas malsucedidas."
    ),
}

_PCI_REQ_11_3 = {
    "req": "Req. 11.3",
    "title": "Testes de penetração periódicos",
    "description": (
        "Executar testes de penetração externos e internos no mínimo uma vez por ano e "
        "após qualquer atualização ou modificação significativa de infraestrutura ou "
        "aplicação, incluindo componentes do ambiente de dados do portador de cartão (CDE)."
    ),
}

_PCI_REQ_11_4 = {
    "req": "Req. 11.4",
    "title": "Detecção e prevenção de intrusões na rede",
    "description": (
        "Utilizar técnicas de detecção e/ou prevenção de intrusões para detectar e/ou "
        "prevenir intrusões na rede. Monitorar todo o tráfego no perímetro do ambiente "
        "de dados do portador de cartão, bem como nos pontos críticos dentro desse "
        "ambiente."
    ),
}

_ISO_A5_24 = {
    "control": "A.5.24",
    "title": "Planejamento e preparação para gestão de incidentes de segurança",
    "description": (
        "A organização deve planejar e se preparar para gerenciar incidentes de "
        "segurança da informação, definindo, estabelecendo e comunicando processos, "
        "papéis e responsabilidades para gestão de incidentes de segurança da informação."
    ),
}

_ISO_A8_8 = {
    "control": "A.8.8",
    "title": "Gestão de vulnerabilidades técnicas",
    "description": (
        "Informações sobre vulnerabilidades técnicas dos sistemas de informação em uso "
        "devem ser obtidas em tempo hábil; a exposição da organização a essas "
        "vulnerabilidades deve ser avaliada; e medidas apropriadas devem ser tomadas "
        "para tratar o risco associado."
    ),
}

_ISO_A8_12 = {
    "control": "A.8.12",
    "title": "Prevenção de vazamento de dados (DLP)",
    "description": (
        "Medidas de prevenção de vazamento de dados devem ser aplicadas a sistemas, "
        "redes e outros dispositivos que processem, armazenem ou transmitam informações "
        "sensíveis, para reduzir o risco de exposição não autorizada de dados pessoais "
        "ou informações confidenciais."
    ),
}

_ISO_A8_23 = {
    "control": "A.8.23",
    "title": "Filtragem web",
    "description": (
        "O acesso a sites externos deve ser gerenciado para proteger os sistemas de "
        "informação contra infecção por malware e para evitar o acesso a recursos web "
        "não autorizados. Técnicas de filtragem devem ser aplicadas de forma adequada "
        "ao perfil de risco da organização."
    ),
}

# ---------------------------------------------------------------------------
# COMPLIANCE_MAP
# ---------------------------------------------------------------------------

COMPLIANCE_MAP: dict[str, dict] = {
    # -----------------------------------------------------------------------
    # T1566 — Phishing
    # -----------------------------------------------------------------------
    "T1566": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4, _BACEN_ART_5],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A5_24, _ISO_A8_8, _ISO_A8_23],
    },
    # -----------------------------------------------------------------------
    # T1566.001 — Spearphishing Attachment
    # -----------------------------------------------------------------------
    "T1566.001": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4, _BACEN_ART_5],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A5_24, _ISO_A8_8, _ISO_A8_23],
    },
    # -----------------------------------------------------------------------
    # T1078 — Valid Accounts
    # -----------------------------------------------------------------------
    "T1078": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5],
        "pci": [_PCI_REQ_8_2, _PCI_REQ_11_3],
        "iso27001": [_ISO_A5_24, _ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1190 — Exploit Public-Facing Application
    # -----------------------------------------------------------------------
    "T1190": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_48, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4, _BACEN_ART_5],
        "pci": [_PCI_REQ_6_4, _PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1059 — Command and Scripting Interpreter
    # -----------------------------------------------------------------------
    "T1059": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1003 — OS Credential Dumping
    # -----------------------------------------------------------------------
    "T1003": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5],
        "pci": [_PCI_REQ_8_2, _PCI_REQ_11_3],
        "iso27001": [_ISO_A8_8, _ISO_A8_12, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1021 — Remote Services
    # -----------------------------------------------------------------------
    "T1021": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4],
        "pci": [_PCI_REQ_8_2, _PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1486 — Data Encrypted for Impact (Ransomware)
    # -----------------------------------------------------------------------
    "T1486": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5, _BACEN_ART_16],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A5_24, _ISO_A8_8, _ISO_A8_12],
    },
    # -----------------------------------------------------------------------
    # T1133 — External Remote Services
    # -----------------------------------------------------------------------
    "T1133": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4, _BACEN_ART_5],
        "pci": [_PCI_REQ_8_2, _PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1110 — Brute Force
    # -----------------------------------------------------------------------
    "T1110": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5],
        "pci": [_PCI_REQ_8_2, _PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1595 — Active Scanning
    # -----------------------------------------------------------------------
    "T1595": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_50],
        "bacen": [_BACEN_ART_4, _BACEN_ART_5],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1592 — Gather Victim Host Information
    # -----------------------------------------------------------------------
    "T1592": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_50],
        "bacen": [_BACEN_ART_4],
        "pci": [_PCI_REQ_11_3],
        "iso27001": [_ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1589 — Gather Victim Identity Information
    # -----------------------------------------------------------------------
    "T1589": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4],
        "pci": [_PCI_REQ_11_3],
        "iso27001": [_ISO_A8_8, _ISO_A8_12],
    },
    # -----------------------------------------------------------------------
    # T1590 — Gather Victim Network Information
    # -----------------------------------------------------------------------
    "T1590": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_50],
        "bacen": [_BACEN_ART_4],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1055 — Process Injection
    # -----------------------------------------------------------------------
    "T1055": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1543 — Create or Modify System Process
    # -----------------------------------------------------------------------
    "T1543": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5, _BACEN_ART_16],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1547 — Boot or Logon Autostart Execution (Persistence)
    # -----------------------------------------------------------------------
    "T1547": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5, _BACEN_ART_16],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1070 — Indicator Removal
    # -----------------------------------------------------------------------
    "T1070": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A5_24, _ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1562 — Impair Defenses
    # -----------------------------------------------------------------------
    "T1562": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5, _BACEN_ART_16],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A5_24, _ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1083 — File and Directory Discovery
    # -----------------------------------------------------------------------
    "T1083": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47],
        "bacen": [_BACEN_ART_4],
        "pci": [_PCI_REQ_11_3],
        "iso27001": [_ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1087 — Account Discovery
    # -----------------------------------------------------------------------
    "T1087": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4],
        "pci": [_PCI_REQ_8_2, _PCI_REQ_11_3],
        "iso27001": [_ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1046 — Network Service Discovery
    # -----------------------------------------------------------------------
    "T1046": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_50],
        "bacen": [_BACEN_ART_4],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8],
    },
    # -----------------------------------------------------------------------
    # T1040 — Network Sniffing
    # -----------------------------------------------------------------------
    "T1040": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4, _BACEN_ART_5],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A8_12, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1557 — Adversary-in-the-Middle
    # -----------------------------------------------------------------------
    "T1557": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_4, _BACEN_ART_5],
        "pci": [_PCI_REQ_8_2, _PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A8_12, _ISO_A5_24],
    },
    # -----------------------------------------------------------------------
    # T1041 — Exfiltration Over C2 Channel
    # -----------------------------------------------------------------------
    "T1041": {
        "lgpd": [_LGPD_ART_46, _LGPD_ART_47, _LGPD_ART_48, _LGPD_ART_50],
        "bacen": [_BACEN_ART_2, _BACEN_ART_5, _BACEN_ART_16],
        "pci": [_PCI_REQ_11_3, _PCI_REQ_11_4],
        "iso27001": [_ISO_A8_8, _ISO_A8_12, _ISO_A5_24],
    },
}

_ALL_FRAMEWORKS = ("lgpd", "bacen", "pci", "iso27001")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _risk_level(violation_count: int) -> str:
    """Convert violation count to Portuguese risk label."""
    if violation_count > 3:
        return "Alto"
    if violation_count >= 1:
        return "Médio"
    return "Baixo"


def _dedupe_violations(violations: list[dict]) -> list[dict]:
    """Remove duplicate compliance items while preserving insertion order."""
    seen: set[str] = set()
    result: list[dict] = []
    for item in violations:
        # Use first available identifier key as deduplication key
        key = item.get("article") or item.get("req") or item.get("control") or str(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_techniques_to_compliance(
    technique_ids: list[str],
    frameworks: Optional[list[str]] = None,
) -> dict:
    """
    Map a list of MITRE ATT&CK technique IDs to compliance violations.

    Parameters
    ----------
    technique_ids:
        One or more technique IDs, e.g. ["T1566", "T1078"].
        Unknown IDs are silently skipped.
    frameworks:
        Optional allowlist of framework keys to include.
        Defaults to all four: lgpd, bacen, pci, iso27001.

    Returns
    -------
    dict keyed by framework name, each value a dict::

        {
            "risk_level": "Alto" | "Médio" | "Baixo",
            "violations": [<compliance item dicts>],
            "technique_ids": [<matched technique ids>]
        }
    """
    if frameworks is None:
        frameworks = list(_ALL_FRAMEWORKS)

    # Normalise to lowercase for comparison
    frameworks_lower = [f.lower() for f in frameworks]

    collected: dict[str, list[dict]] = {fw: [] for fw in frameworks_lower}
    matched_per_fw: dict[str, list[str]] = {fw: [] for fw in frameworks_lower}

    for tid in technique_ids:
        entry = COMPLIANCE_MAP.get(tid)
        if entry is None:
            continue
        for fw in frameworks_lower:
            fw_items = entry.get(fw, [])
            if fw_items:
                collected[fw].extend(fw_items)
                if tid not in matched_per_fw[fw]:
                    matched_per_fw[fw].append(tid)

    result: dict = {}
    for fw in frameworks_lower:
        deduped = _dedupe_violations(collected[fw])
        result[fw] = {
            "risk_level": _risk_level(len(deduped)),
            "violations": deduped,
            "technique_ids": matched_per_fw[fw],
        }

    return result


def generate_evidence_report(simulation_data: dict) -> dict:
    """
    Build a full compliance evidence report from simulation output.

    Parameters
    ----------
    simulation_data:
        Dict with keys:
          - target (str): target host / URL
          - score (int | float): overall simulation score (0-100)
          - techniques (list[dict]): each item has id, name, status, tactic

    Returns
    -------
    Full evidence report dict suitable for JSON serialisation or PDF generation.
    """
    target: str = simulation_data.get("target", "N/A")
    score: float = float(simulation_data.get("score", 0))
    techniques: list[dict] = simulation_data.get("techniques", [])

    # Split techniques by status
    successful = [t for t in techniques if t.get("status", "").lower() in ("success", "sucesso")]
    failed = [t for t in techniques if t.get("status", "").lower() in ("failed", "falha", "error", "erro")]

    technique_ids = [t["id"] for t in techniques if "id" in t]
    successful_ids = [t["id"] for t in successful if "id" in t]

    compliance_results = map_techniques_to_compliance(technique_ids)

    # Group techniques by tactic
    tactics_map: dict[str, list[dict]] = {}
    for tech in techniques:
        tactic = tech.get("tactic", "Unknown")
        tactics_map.setdefault(tactic, []).append(tech)

    # Overall risk: highest risk_level across frameworks
    _risk_order = {"Alto": 3, "Médio": 2, "Baixo": 1}
    overall_risk_score = max(
        (_risk_order.get(v["risk_level"], 0) for v in compliance_results.values()),
        default=1,
    )
    overall_risk = {3: "Alto", 2: "Médio", 1: "Baixo"}.get(overall_risk_score, "Baixo")

    # Framework summary counts
    framework_summary = get_framework_summary(technique_ids)

    report: dict = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "PenteIA V4.0",
            "report_type": "Compliance Evidence Report",
            "target": target,
        },
        "simulation_summary": {
            "target": target,
            "overall_score": score,
            "total_techniques": len(techniques),
            "successful_techniques": len(successful),
            "failed_techniques": len(failed),
            "overall_risk": overall_risk,
        },
        "techniques_by_tactic": {
            tactic: [
                {
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "status": t.get("status"),
                }
                for t in techs
            ]
            for tactic, techs in sorted(tactics_map.items())
        },
        "successful_technique_ids": successful_ids,
        "compliance_analysis": compliance_results,
        "framework_summary": framework_summary,
        "recommendations": _build_recommendations(compliance_results, successful),
    }

    return report


def get_framework_summary(technique_ids: list[str]) -> dict:
    """
    Return aggregated violation counts and risk levels per framework.

    Parameters
    ----------
    technique_ids:
        List of MITRE ATT&CK technique IDs.

    Returns
    -------
    dict::

        {
            "lgpd":     {"violation_count": N, "risk_level": str, "techniques_matched": N},
            "bacen":    {...},
            "pci":      {...},
            "iso27001": {...},
            "overall_risk": str,
            "total_techniques_analysed": N,
            "total_unique_violations": N,
        }
    """
    compliance_results = map_techniques_to_compliance(technique_ids)

    summary: dict = {}
    total_violations = 0

    for fw in _ALL_FRAMEWORKS:
        fw_data = compliance_results.get(fw, {})
        count = len(fw_data.get("violations", []))
        total_violations += count
        summary[fw] = {
            "violation_count": count,
            "risk_level": fw_data.get("risk_level", "Baixo"),
            "techniques_matched": len(fw_data.get("technique_ids", [])),
        }

    _risk_order = {"Alto": 3, "Médio": 2, "Baixo": 1}
    overall_risk_score = max(
        (_risk_order.get(summary[fw]["risk_level"], 0) for fw in _ALL_FRAMEWORKS),
        default=1,
    )
    overall_risk = {3: "Alto", 2: "Médio", 1: "Baixo"}.get(overall_risk_score, "Baixo")

    summary["overall_risk"] = overall_risk
    summary["total_techniques_analysed"] = len(technique_ids)
    summary["total_unique_violations"] = total_violations

    return summary


# ---------------------------------------------------------------------------
# Private helper — build actionable recommendations
# ---------------------------------------------------------------------------

def _build_recommendations(
    compliance_results: dict,
    successful_techniques: list[dict],
) -> list[dict]:
    """Produce a prioritised list of remediation recommendations."""
    recommendations: list[dict] = []

    risk_order = {"Alto": 3, "Médio": 2, "Baixo": 1}

    for fw, data in compliance_results.items():
        risk = data.get("risk_level", "Baixo")
        if risk == "Baixo":
            continue
        for violation in data.get("violations", []):
            identifier = (
                violation.get("article")
                or violation.get("req")
                or violation.get("control")
                or "N/A"
            )
            recommendations.append(
                {
                    "priority": risk,
                    "framework": fw.upper(),
                    "reference": identifier,
                    "title": violation.get("title", ""),
                    "action": (
                        f"Revisar conformidade com {fw.upper()} {identifier} — "
                        f"{violation.get('title', '')}. Risco atual: {risk}."
                    ),
                }
            )

    # Sort: Alto first, then Médio; stable within same level
    recommendations.sort(key=lambda r: risk_order.get(r["priority"], 0), reverse=True)

    # Deduplicate by (framework, reference)
    seen: set[tuple] = set()
    unique: list[dict] = []
    for rec in recommendations:
        key = (rec["framework"], rec["reference"])
        if key not in seen:
            seen.add(key)
            unique.append(rec)

    return unique
