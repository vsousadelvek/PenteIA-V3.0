"""
br_fiscal_engine.py — PenteIA V4.0
Exclusive Brazilian threat simulations:
- NF-e / SPED fiscal system attacks
- DREX (Brazilian CBDC) security scenarios
- Gov.br digital identity attacks
- Serpro infrastructure attacks
- Brazilian banking sector specifics

These are zero-competition differentiators for the Brazilian market.
"""
from typing import List, Dict

# ── NF-e / SPED Fiscal Attack Scenarios ─────────────────────────────────────

NFE_SCENARIOS = [
    {
        "id": "BR-NFE-001",
        "name": "NF-e XML Injection via SEFAZ Proxy",
        "tactic": "INITIAL_ACCESS",
        "severity": "critical",
        "description": "Injeção de campos maliciosos em XML de NF-e enviado à SEFAZ via proxy MitM",
        "mitre_references": ["T1190", "T1557"],
        "regulatory_impact": ["SPED", "BACEN 4893", "LGPD Art. 48"],
        "affected_systems": ["ERP SAP", "TOTVS Protheus", "Oracle Fiscal"],
        "iocs": ["sefaz.fazenda.gov.br", "nfe.fazenda.gov.br"],
        "kill_chain": [
            {"step": 1, "action": "Reconhecimento do proxy NF-e corporativo"},
            {"step": 2, "action": "MitM no canal HTTPS para SEFAZ"},
            {"step": 3, "action": "Injeção de XML com campos extras não validados"},
            {"step": 4, "action": "Exfiltração de dados fiscais via resposta SEFAZ"},
        ]
    },
    {
        "id": "BR-NFE-002",
        "name": "DANFE PDF com Macro Maliciosa",
        "tactic": "EXECUTION",
        "severity": "high",
        "description": "PDF de DANFE (Documento Auxiliar da NF-e) weaponizado com macro/JS para execução de código",
        "mitre_references": ["T1566.001", "T1204.002"],
        "regulatory_impact": ["LGPD Art. 48"],
        "affected_systems": ["Adobe Reader", "Foxit", "LibreOffice"],
        "kill_chain": [
            {"step": 1, "action": "Geração de DANFE legítimo com formato alterado"},
            {"step": 2, "action": "Embedding de JavaScript/macro no PDF"},
            {"step": 3, "action": "Envio por e-mail fiscal corporativo"},
            {"step": 4, "action": "Execução de payload ao abrir DANFE"},
        ]
    },
    {
        "id": "BR-SPED-001",
        "name": "SPED Contábil/Fiscal Data Tampering",
        "tactic": "IMPACT",
        "severity": "critical",
        "description": "Adulteração de arquivos SPED antes da assinatura digital para envio à Receita Federal",
        "mitre_references": ["T1565", "T1070"],
        "regulatory_impact": ["SPED", "Código Tributário Nacional", "BACEN 4893"],
        "affected_systems": ["Validador SPED", "PGE", "Contador Digital"],
        "kill_chain": [
            {"step": 1, "action": "Acesso ao servidor de geração SPED"},
            {"step": 2, "action": "Intercepção do arquivo .txt antes da assinatura"},
            {"step": 3, "action": "Adulteração de valores de receita/despesa"},
            {"step": 4, "action": "Re-assinatura com certificado digital roubado"},
        ]
    },
]

# ── DREX (Brazilian CBDC) Attack Scenarios ───────────────────────────────────

DREX_SCENARIOS = [
    {
        "id": "BR-DREX-001",
        "name": "DREX Smart Contract Exploit",
        "tactic": "IMPACT",
        "severity": "critical",
        "description": "Exploração de vulnerabilidades em smart contracts da plataforma DREX (Hyperledger Besu)",
        "mitre_references": ["T1190", "T1059"],
        "regulatory_impact": ["BACEN Resolução 4893", "BACEN DREX Pilot"],
        "affected_systems": ["Hyperledger Besu", "DREX Piloto", "RSFN"],
        "technology": "blockchain",
        "kill_chain": [
            {"step": 1, "action": "Análise de smart contracts DREX publicados"},
            {"step": 2, "action": "Identificação de reentrancy/overflow vulnerabilities"},
            {"step": 3, "action": "Exploit em ambiente piloto"},
            {"step": 4, "action": "Double-spend ou mint não autorizado"},
        ]
    },
    {
        "id": "BR-DREX-002",
        "name": "RSFN Node Compromise",
        "tactic": "LATERAL_MOVEMENT",
        "severity": "critical",
        "description": "Comprometimento de nó participante da Rede do Sistema Financeiro Nacional (RSFN)",
        "mitre_references": ["T1190", "T1021"],
        "regulatory_impact": ["BACEN Circular 4283", "LGPD"],
        "affected_systems": ["RSFN", "Nós bancários DREX", "HSM certificados"],
        "kill_chain": [
            {"step": 1, "action": "Reconhecimento de nós RSFN expostos"},
            {"step": 2, "action": "Exploração de vulnerabilidade no nó Besu"},
            {"step": 3, "action": "Acesso às chaves privadas do nó"},
            {"step": 4, "action": "Assinar transações fraudulentas como nó legítimo"},
        ]
    },
    {
        "id": "BR-DREX-003",
        "name": "DREX Wallet Key Exfiltration",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "critical",
        "description": "Roubo de chaves privadas de carteiras DREX corporativas em custodiantes",
        "mitre_references": ["T1552", "T1003"],
        "regulatory_impact": ["BACEN 4893", "LGPD Art. 7"],
        "affected_systems": ["HSM custódia", "Carteiras DREX corporativas"],
        "kill_chain": [
            {"step": 1, "action": "Comprometimento do sistema de gestão de chaves"},
            {"step": 2, "action": "Dump de chaves privadas do HSM via API"},
            {"step": 3, "action": "Transfer de DREX para endereço externo"},
        ]
    },
]

# ── Gov.br / Serpro Attack Scenarios ─────────────────────────────────────────

GOVBR_SCENARIOS = [
    {
        "id": "BR-GOVBR-001",
        "name": "Gov.br OAuth2 Token Hijacking",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "critical",
        "description": "Interceptação de tokens OAuth2 do Gov.br para impersonação de cidadão/servidor",
        "mitre_references": ["T1528", "T1539"],
        "regulatory_impact": ["LGPD Art. 46", "Decreto 10.046/2019", "LGPD Art. 48"],
        "affected_systems": ["Gov.br IdP", "Acesso Gov.br", "Conecta Gov"],
        "kill_chain": [
            {"step": 1, "action": "Phishing direcionado a servidor com acesso Gov.br"},
            {"step": 2, "action": "Captura de token de acesso Gov.br"},
            {"step": 3, "action": "Reutilização de token para acessar sistemas integrados"},
            {"step": 4, "action": "Exfiltração de dados pessoais de cidadãos"},
        ]
    },
    {
        "id": "BR-GOVBR-002",
        "name": "Serpro API Key Compromise",
        "tactic": "INITIAL_ACCESS",
        "severity": "critical",
        "description": "Comprometimento de API key Serpro para acesso não autorizado a bases CPF/CNPJ/RG",
        "mitre_references": ["T1078.004", "T1552.001"],
        "regulatory_impact": ["LGPD Art. 16", "Decreto 9.745/2019"],
        "affected_systems": ["Serpro DataValid", "Serpro CPF API", "Serpro NFe"],
        "kill_chain": [
            {"step": 1, "action": "Reconhecimento de credenciais Serpro expostas"},
            {"step": 2, "action": "Extração de API keys de repositórios/configs"},
            {"step": 3, "action": "Enumeração de CPFs/CNPJs via Serpro API"},
            {"step": 4, "action": "Venda/uso de PII em fraudes de identidade"},
        ]
    },
    {
        "id": "BR-GOVBR-003",
        "name": "Certificado Digital A3 Clonagem",
        "tactic": "CREDENTIAL_ACCESS",
        "severity": "critical",
        "description": "Clonagem/exfiltração de certificado digital A3 de empresa ou servidor público",
        "mitre_references": ["T1552.004", "T1553.004"],
        "regulatory_impact": ["MP 2.200-2/2001", "ICP-Brasil", "BACEN 4893"],
        "affected_systems": ["Token A3", "HSM corporativo", "Certisign/Serasa CA"],
        "kill_chain": [
            {"step": 1, "action": "Instalação de keylogger em estação com token A3"},
            {"step": 2, "action": "Captura de PIN do token durante uso legítimo"},
            {"step": 3, "action": "Exportação da chave privada do token comprometido"},
            {"step": 4, "action": "Assinatura digital de documentos fraudulentos"},
        ]
    },
]

# ── All BR Exclusive Scenarios ───────────────────────────────────────────────

ALL_BR_FISCAL_SCENARIOS = NFE_SCENARIOS + DREX_SCENARIOS + GOVBR_SCENARIOS

SCENARIO_CATEGORIES = {
    "nfe_sped": {"label": "NF-e / SPED Fiscal", "count": len(NFE_SCENARIOS), "icon": "FileText"},
    "drex_cbdc": {"label": "DREX / CBDC", "count": len(DREX_SCENARIOS), "icon": "Coins"},
    "govbr":     {"label": "Gov.br / Serpro", "count": len(GOVBR_SCENARIOS), "icon": "Building2"},
}


def list_scenarios(category: str = None) -> list:
    if category == "nfe_sped":
        return NFE_SCENARIOS
    elif category == "drex_cbdc":
        return DREX_SCENARIOS
    elif category == "govbr":
        return GOVBR_SCENARIOS
    return ALL_BR_FISCAL_SCENARIOS


def get_scenario(scenario_id: str) -> dict | None:
    return next((s for s in ALL_BR_FISCAL_SCENARIOS if s["id"] == scenario_id), None)


def simulate_scenario(scenario_id: str, target: str) -> dict:
    """Run a BR fiscal/DREX/Gov.br attack simulation (simulated output)."""
    scenario = get_scenario(scenario_id)
    if not scenario:
        raise ValueError(f"Scenario {scenario_id} not found")

    steps = scenario.get("kill_chain", [])
    results = []
    for step in steps:
        results.append({
            "step": step["step"],
            "action": step["action"],
            "status": "simulated",
            "evidence": f"[PenteIA] Simulação de: {step['action']} contra {target}",
        })

    return {
        "scenario_id": scenario_id,
        "scenario_name": scenario["name"],
        "target": target,
        "tactic": scenario["tactic"],
        "severity": scenario["severity"],
        "regulatory_impact": scenario.get("regulatory_impact", []),
        "steps_executed": len(results),
        "kill_chain_results": results,
        "status": "completed",
    }


def get_regulatory_exposure(scenario_ids: list) -> dict:
    """Calculate regulatory exposure from a list of scenario IDs."""
    all_impacts: dict = {}
    for sid in scenario_ids:
        scenario = get_scenario(sid)
        if scenario:
            for impact in scenario.get("regulatory_impact", []):
                all_impacts[impact] = all_impacts.get(impact, 0) + 1

    return {
        "frameworks_at_risk": list(all_impacts.keys()),
        "exposure_count": all_impacts,
        "highest_risk": max(all_impacts, key=all_impacts.get) if all_impacts else None,
    }
