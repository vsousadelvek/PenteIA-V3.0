#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
BAS Engine - PenteIA v4.0
Breach and Attack Simulation / Continuous Security Validation
- MITRE ATT&CK playbook automation
- Technique execution
- Evidence collection
- Severity scoring
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
            'description': self.description,
            'severity': self.severity,
        }


class Playbook:
    """
    Playbook BAS: conjunto de técnicas a executar.
    Baseado em MITRE ATT&CK framework.
    """

    PREDEFINED_PLAYBOOKS = {
        'lateral_movement': [
            MITRETechnique('T1021.001', 'RDP', MITRETactic.LATERAL_MOVEMENT,
                          'Remote Desktop Protocol exploitation'),
            MITRETechnique('T1047', 'WMI Execution', MITRETactic.EXECUTION,
                          'Execute commands via WMI'),
            MITRETechnique('T1570', 'SMB Lateral Movement', MITRETactic.LATERAL_MOVEMENT,
                          'Lateral movement via SMB shares'),
        ],
        'credential_harvesting': [
            MITRETechnique('T1110.001', 'Password Guessing', MITRETactic.CREDENTIAL_ACCESS,
                          'Guess default/weak passwords'),
            MITRETechnique('T1187', 'LLMNR/NBNS Poisoning', MITRETactic.CREDENTIAL_ACCESS,
                          'Poison LLMNR/mDNS queries'),
            MITRETechnique('T1040', 'Network Sniffing', MITRETactic.DISCOVERY,
                          'Sniff network traffic for credentials'),
        ],
        'persistence': [
            MITRETechnique('T1547.001', 'Registry Run Keys', MITRETactic.PERSISTENCE,
                          'Add persistence via registry'),
            MITRETechnique('T1053.005', 'Scheduled Task', MITRETactic.PERSISTENCE,
                          'Create scheduled task for persistence'),
            MITRETechnique('T1137.006', 'Office Add-ins', MITRETactic.PERSISTENCE,
                          'Create Office Add-in for persistence'),
        ],
        'defense_evasion': [
            MITRETechnique('T1548.004', 'Elevated Execution', MITRETactic.PRIVILEGE_ESCALATION,
                          'Elevated execution with elevated privileges'),
            MITRETechnique('T1036.005', 'Match Legitimate Name/Location', MITRETactic.DEFENSE_EVASION,
                          'Hide malicious process'),
            MITRETechnique('T1562.008', 'Clear Event Logs', MITRETactic.DEFENSE_EVASION,
                          'Clear Windows event logs'),
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
        techniques = Playbook.PREDEFINED_PLAYBOOKS[preset_name]
        return Playbook(preset_name, techniques)


class TechniqueExecutor:
    """Executa técnicas individuais do MITRE ATT&CK"""

    def __init__(self):
        self.executions = []

    def execute(self, technique: MITRETechnique) -> dict:
        """Executa técnica e coleta evidências"""
        execution_id = str(uuid.uuid4())

        # Simular execução
        success = self._simulate_execution(technique)

        execution_result = {
            'execution_id': execution_id,
            'technique_id': technique.technique_id,
            'technique_name': technique.name,
            'executed_at': datetime.now().isoformat(),
            'success': success,
            'severity': technique.severity,
            'evidence': self._collect_evidence(technique),
            'artifacts': self._collect_artifacts(technique),
        }

        self.executions.append(execution_result)
        return execution_result

    def _simulate_execution(self, technique: MITRETechnique) -> bool:
        """Simula execução (em produção seria real)"""
        return True

    def _collect_evidence(self, technique: MITRETechnique) -> List[str]:
        """Coleta evidências de execução"""
        evidence_map = {
            'T1021.001': ['RDP connection logs', 'netstat output', 'process creation events'],
            'T1047': ['WMI event logs', 'command execution logs', 'registry modifications'],
            'T1110.001': ['Failed login attempts', 'brute force detections', 'account lockouts'],
        }
        return evidence_map.get(technique.technique_id, ['Generic evidence collected'])

    def _collect_artifacts(self, technique: MITRETechnique) -> dict:
        """Coleta artefatos (files, registry, etc)"""
        return {
            'files_created': [],
            'registry_modified': [],
            'processes_spawned': [],
            'network_connections': [],
        }


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
        """
        Calcula score de severidade (0-10).
        Baseado em: Severidade da técnica + qualidade de evidência
        """
        base_score = self.SEVERITY_SCORES.get(technique.severity, 5.0)

        if not success:
            base_score *= 0.5  # Falha reduz score

        if evidence_count > 5:
            base_score += 1.0  # Mais evidências = score mais alto

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

        for technique in playbook.techniques:
            # Executar técnica
            tech_result = self.executor.execute(technique)
            playbook_execution['technique_results'].append(tech_result)

            # Calcular score
            score = self.scorer.score_finding(
                technique,
                tech_result['success'],
                len(tech_result['evidence'])
            )

            # Adicionar ao findings
            if score >= 5.0:  # Apenas achados com score >= medium
                playbook_execution['findings'].append({
                    'technique_id': technique.technique_id,
                    'technique_name': technique.name,
                    'severity_score': score,
                    'severity_label': self._score_to_label(score),
                    'evidence': tech_result['evidence'],
                })

        playbook_execution['completed_at'] = datetime.now().isoformat()
        playbook_execution['total_findings'] = len(playbook_execution['findings'])

        self.execution_history.append(playbook_execution)
        return playbook_execution

    def _score_to_label(self, score: float) -> str:
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 5.0:
            return 'medium'
        elif score >= 3.0:
            return 'low'
        return 'info'

    def run_full_assessment(self) -> dict:
        """Executa avaliação completa: todos os playbooks"""
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
        all_results['total_findings'] = sum(
            r['total_findings'] for r in all_results['playbook_results']
        )

        return all_results

    def get_execution_history(self) -> List[dict]:
        return self.execution_history


def export_bas_config() -> dict:
    """Exporta configuração do BAS engine"""
    runner = BASPlaybookRunner()

    return {
        'version': '4.0-bas-engine',
        'timestamp': datetime.now().isoformat(),
        'presets_available': list(Playbook.PREDEFINED_PLAYBOOKS.keys()),
        'tactics_covered': [t.value for t in MITRETactic],
        'severity_levels': list(SeverityScorer.SEVERITY_SCORES.keys()),
        'continuous_validation': True,
        'automated_scoring': True,
    }


if __name__ == '__main__':
    print("[*] BAS Engine - PenteIA v4.0")
    print(json.dumps(export_bas_config(), indent=2))

    # Exemplo de execução
    runner = BASPlaybookRunner()
    result = runner.run_full_assessment()
    print("\n[*] Full Assessment Results:")
    print(f"    Total Findings: {result['total_findings']}")
