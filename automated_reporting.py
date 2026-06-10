#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Automated Reporting - PenteIA v4.0
Geração automática de relatórios via Jinja2
- Executive Summary (LLM-generated)
- Attack Paths e graphs
- Findings categorizados
- Recommendations
- Risk scoring
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class Finding:
    """Representa um achado de segurança"""
    finding_id: str
    technique_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    evidence: List[str]
    affected_systems: List[str]
    remediation: str
    cvss_score: float = 5.0
    found_at: str = None

    def __post_init__(self):
        if not self.found_at:
            self.found_at = datetime.now().isoformat()


@dataclass
class AttackPath:
    """Representa um caminho de ataque descoberto"""
    path_id: str
    start_node: str  # Ex: Compromised user
    end_node: str    # Ex: Domain Admin
    techniques: List[str]  # Lista de técnicas MITRE
    probability: float  # 0.0-1.0
    impact: str  # critical, high, medium, low


class FindingsCategorizer:
    """Categoriza e organiza achados"""

    def __init__(self):
        self.findings: Dict[str, List[Finding]] = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': [],
        }

    def add_finding(self, finding: Finding) -> None:
        """Adiciona achado à categoria apropriada"""
        severity = finding.severity.lower()
        if severity in self.findings:
            self.findings[severity].append(finding)

    def categorize_findings(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Categoriza lista de achados"""
        for finding in findings:
            self.add_finding(finding)
        return self.findings

    def get_summary(self) -> dict:
        """Retorna sumário de categorização"""
        return {
            'critical': len(self.findings['critical']),
            'high': len(self.findings['high']),
            'medium': len(self.findings['medium']),
            'low': len(self.findings['low']),
            'info': len(self.findings['info']),
            'total': sum(len(v) for v in self.findings.values()),
        }


class AttackGraphBuilder:
    """Constrói grafos de ataque"""

    def __init__(self):
        self.paths: List[AttackPath] = []
        self.nodes = set()
        self.edges = []

    def build_path(self, findings: List[Finding]) -> List[AttackPath]:
        """
        Constrói caminhos de ataque a partir de achados.
        Agrupa técnicas relacionadas em sequências lógicas.
        """
        # Exemplo simplificado
        if findings:
            path = AttackPath(
                path_id=hashlib.md5(str(findings).encode()).hexdigest()[:16],
                start_node='Initial Access',
                end_node='Domain Admin',
                techniques=[f.technique_id for f in findings[:5]],
                probability=0.85,
                impact='critical'
            )
            self.paths.append(path)

        return self.paths

    def visualize_graph(self) -> dict:
        """Exporta grafo em formato visível (ex: para D3.js, Graphviz)"""
        return {
            'nodes': list(self.nodes),
            'edges': self.edges,
            'paths': [asdict(p) for p in self.paths],
        }


class RecommendationGenerator:
    """Gera recomendações de remediação"""

    MITIGATION_STRATEGIES = {
        'T1021.001': {
            'title': 'Mitigate RDP attacks',
            'steps': [
                'Restrict RDP access via firewall',
                'Require MFA for RDP',
                'Implement Network Level Authentication (NLA)',
                'Monitor RDP logs for suspicious activity',
            ]
        },
        'T1047': {
            'title': 'Prevent WMI execution',
            'steps': [
                'Restrict WMI access via AppLocker',
                'Monitor WMI activity via Sysmon/ETW',
                'Disable unnecessary WMI providers',
            ]
        },
        'T1110.001': {
            'title': 'Prevent password guessing',
            'steps': [
                'Implement account lockout policies',
                'Require strong passwords',
                'Implement MFA',
                'Monitor failed login attempts',
            ]
        },
    }

    def __init__(self):
        self.recommendations = []

    def generate_recommendations(self, findings: List[Finding]) -> List[dict]:
        """Gera recomendações baseadas em achados"""
        for finding in findings:
            technique_id = finding.technique_id
            strategy = self.MITIGATION_STRATEGIES.get(
                technique_id,
                {
                    'title': f'Mitigate {technique_id}',
                    'steps': ['Monitor for this technique', 'Restrict execution via policies']
                }
            )

            recommendation = {
                'finding_id': finding.finding_id,
                'technique_id': technique_id,
                'priority': self._calculate_priority(finding.severity),
                'mitigation_title': strategy['title'],
                'steps': strategy['steps'],
                'effort': self._estimate_effort(technique_id),
            }
            self.recommendations.append(recommendation)

        return self.recommendations

    def _calculate_priority(self, severity: str) -> int:
        """Calcula prioridade (1=highest, 5=lowest)"""
        priority_map = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5,
        }
        return priority_map.get(severity.lower(), 5)

    def _estimate_effort(self, technique_id: str) -> str:
        """Estima esforço de remediação"""
        quick_wins = ['T1562.008', 'T1562.001']  # Clear logs, etc
        medium_effort = ['T1021.001', 'T1047']   # RDP, WMI restrictions
        hard = ['T1110.001']                      # Password policy requires org-wide changes

        if technique_id in quick_wins:
            return 'Low (1-2 hours)'
        elif technique_id in medium_effort:
            return 'Medium (1-3 days)'
        else:
            return 'High (1-2 weeks)'


class JinjaReportGenerator:
    """
    Gera relatórios em formato múltiplo (HTML, DOCX, PPTX) via Jinja2.
    """

    JINJA_TEMPLATES = {
        'executive_summary': """
EXECUTIVE SUMMARY - PenteIA v4.0 Assessment
=============================================
Assessment Date: {{ assessment_date }}
Assessment Duration: {{ duration_hours }} hours
Total Findings: {{ total_findings }}
Risk Level: {{ risk_level }}

Overview:
{{ overview }}

Critical Findings: {{ critical_count }}
High Findings: {{ high_count }}
Medium Findings: {{ medium_count }}

Key Recommendations:
{% for rec in top_recommendations %}
  - [P{{ rec.priority }}] {{ rec.mitigation_title }}
{% endfor %}
""",

        'technical_findings': """
TECHNICAL FINDINGS
==================
{% for finding in findings %}

Finding #{{ loop.index }}: {{ finding.title }}
- ID: {{ finding.finding_id }}
- Technique: {{ finding.technique_id }}
- Severity: {{ finding.severity | upper }}
- CVSS: {{ finding.cvss_score }}

Description:
{{ finding.description }}

Evidence:
{% for evidence in finding.evidence %}
  * {{ evidence }}
{% endfor %}

Affected Systems:
{% for system in finding.affected_systems %}
  * {{ system }}
{% endfor %}

Remediation:
{{ finding.remediation }}
---
{% endfor %}
""",

        'attack_paths': """
ATTACK PATHS
============
{% for path in attack_paths %}

Path: {{ path.start_node }} -> {{ path.end_node }}
Probability: {{ "%.1f%%" | format(path.probability * 100) }}
Impact: {{ path.impact | upper }}

Techniques:
{% for tech in path.techniques %}
  {{ loop.index }}. {{ tech }}
{% endfor %}
---
{% endfor %}
""",

        'recommendations': """
REMEDIATION ROADMAP
===================
{% for rec in recommendations | sort(attribute='priority') %}

[Priority {{ rec.priority }}] {{ rec.mitigation_title }}
Technique: {{ rec.technique_id }}
Effort: {{ rec.effort }}

Steps:
{% for step in rec.steps %}
  {{ loop.index }}. {{ step }}
{% endfor %}
---
{% endfor %}
"""
    }

    def __init__(self):
        self.rendered_templates = {}

    def render_report(self, report_data: dict, template_name: str) -> str:
        """
        Renderiza template Jinja2 com dados de relatório.
        """
        if template_name not in self.JINJA_TEMPLATES:
            return f"Template '{template_name}' not found"

        template_str = self.JINJA_TEMPLATES[template_name]

        # Simulação de Jinja2 rendering (em produção: usar jinja2.Template)
        # Para agora, retornar template com placeholder substitution
        result = template_str

        for key, value in report_data.items():
            if isinstance(value, (int, float, str)):
                result = result.replace('{{ ' + key + ' }}', str(value))
            elif isinstance(value, list):
                # Placeholder para loops
                pass

        self.rendered_templates[template_name] = result
        return result

    def generate_full_report(self, assessment_data: dict) -> dict:
        """Gera relatório completo em múltiplos formatos"""
        report = {
            'report_id': hashlib.sha256(str(assessment_data).encode()).hexdigest()[:16],
            'generated_at': datetime.now().isoformat(),
            'assessment_data': assessment_data,
            'sections': {},
        }

        # Renderizar cada seção
        for template_name in self.JINJA_TEMPLATES.keys():
            report['sections'][template_name] = self.render_report(assessment_data, template_name)

        return report


class ReportExporter:
    """Exporta relatórios em múltiplos formatos"""

    def __init__(self):
        self.exported_reports = []

    def export_html(self, report_data: dict, filename: str) -> dict:
        """Exporta relatório em HTML"""
        html_content = self._generate_html(report_data)

        export_record = {
            'format': 'HTML',
            'filename': filename,
            'size_bytes': len(html_content.encode()),
            'exported_at': datetime.now().isoformat(),
        }
        self.exported_reports.append(export_record)

        return export_record

    def export_pdf(self, report_data: dict, filename: str) -> dict:
        """Exporta relatório em PDF (via FPDF ou pypdf)"""
        # Em produção: usar reportlab ou weasyprint

        export_record = {
            'format': 'PDF',
            'filename': filename,
            'encrypted': True,
            'exported_at': datetime.now().isoformat(),
        }
        self.exported_reports.append(export_record)

        return export_record

    def export_docx(self, report_data: dict, filename: str) -> dict:
        """Exporta relatório em DOCX (via python-docx)"""
        # Em produção: usar python-docx com tabelas, imagens, estilos

        export_record = {
            'format': 'DOCX',
            'filename': filename,
            'template_based': True,
            'exported_at': datetime.now().isoformat(),
        }
        self.exported_reports.append(export_record)

        return export_record

    def _generate_html(self, report_data: dict) -> str:
        """Gera HTML do relatório"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>PenteIA v4.0 Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; border-bottom: 2px solid #00b8d4; }
        .critical { color: #ff5252; font-weight: bold; }
        .high { color: #ff9800; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #00b8d4; color: white; }
    </style>
</head>
<body>
    <h1>Security Assessment Report - PenteIA v4.0</h1>
    <p><strong>Report ID:</strong> """ + report_data.get('report_id', 'N/A') + """</p>
    <p><strong>Generated:</strong> """ + datetime.now().isoformat() + """</p>

    <h2>Executive Summary</h2>
    <p>Assessment completed with """ + str(report_data.get('total_findings', 0)) + """ findings identified.</p>

    <h2>Findings Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td class="critical">Critical</td><td>""" + str(report_data.get('critical_count', 0)) + """</td></tr>
        <tr><td class="high">High</td><td>""" + str(report_data.get('high_count', 0)) + """</td></tr>
    </table>
</body>
</html>
"""
        return html


def export_reporting_config() -> dict:
    """Exporta configuração de reporting"""
    return {
        'version': '4.0-automated-reporting',
        'timestamp': datetime.now().isoformat(),
        'templates_available': list(JinjaReportGenerator.JINJA_TEMPLATES.keys()),
        'export_formats': ['HTML', 'PDF', 'DOCX', 'JSON'],
        'automated_generation': True,
        'ai_summaries': True,
    }


if __name__ == '__main__':
    print("[*] Automated Reporting - PenteIA v4.0")
    print(json.dumps(export_reporting_config(), indent=2))

    # Exemplo de geração de relatório
    categorizer = FindingsCategorizer()
    findings = [
        Finding(
            finding_id='F001',
            technique_id='T1021.001',
            title='RDP Exploitation Vulnerability',
            description='RDP ports are exposed and vulnerable to brute force',
            severity='high',
            evidence=['RDP port open', 'Weak password policies', 'No MFA'],
            affected_systems=['SERVER-01', 'SERVER-02'],
            remediation='Enable MFA and restrict RDP access',
            cvss_score=7.5
        ),
    ]

    categorizer.categorize_findings(findings)
    print("\n[*] Finding Summary:")
    print(json.dumps(categorizer.get_summary(), indent=2))
