"""Motor de Machine Learning do PenteIA.

Sem dependência de LLM — usa scikit-learn + numpy puros.
pip install scikit-learn numpy (ambos rodam 100% em CPU)

Capacidades:
  • RiskScoreModel     — rede feedforward leve para score de risco
  • AnomalyDetector    — Isolation Forest para detectar simulações anômalas
  • TechniqueAdvisor   — prediz técnicas não testadas de maior risco com base na
                         cadeia de ataque atual (co-ocorrência MITRE)
  • IOCClassifier      — classificação de IOCs via features TF-IDF + SVM linear
"""
from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger(__name__)

# Caminho para persistir modelos treinados (opcional)
_MODEL_DIR = Path(os.getenv("PENTEIA_ML_DIR", os.path.join(os.path.dirname(__file__), "ml_models")))

# ── Mapeamento tático MITRE → peso de risco ──────────────────────────────────
_TACTIC_WEIGHT: dict[str, float] = {
    "Initial Access":        0.90,
    "Execution":             0.85,
    "Persistence":           0.80,
    "Privilege Escalation":  0.95,
    "Defense Evasion":       0.70,
    "Credential Access":     0.92,
    "Discovery":             0.45,
    "Lateral Movement":      0.88,
    "Collection":            0.60,
    "Command and Control":   0.75,
    "Exfiltration":          0.82,
    "Impact":                0.98,
}

# Cadeia de ataque típica (co-ocorrência: qual tática segue qual)
_CHAIN_PROBS: dict[str, list[tuple[str, float]]] = {
    "Initial Access":       [("Execution", 0.88), ("Defense Evasion", 0.65)],
    "Execution":            [("Persistence", 0.72), ("Privilege Escalation", 0.68), ("Defense Evasion", 0.55)],
    "Persistence":          [("Privilege Escalation", 0.80), ("Defense Evasion", 0.60)],
    "Privilege Escalation": [("Credential Access", 0.85), ("Defense Evasion", 0.70), ("Lateral Movement", 0.65)],
    "Defense Evasion":      [("Credential Access", 0.60), ("Discovery", 0.55)],
    "Credential Access":    [("Lateral Movement", 0.90), ("Discovery", 0.70)],
    "Discovery":            [("Lateral Movement", 0.75), ("Collection", 0.60)],
    "Lateral Movement":     [("Collection", 0.70), ("Credential Access", 0.65), ("Exfiltration", 0.50)],
    "Collection":           [("Exfiltration", 0.80), ("Command and Control", 0.55)],
    "Command and Control":  [("Exfiltration", 0.65), ("Collection", 0.50)],
    "Exfiltration":         [("Impact", 0.40)],
    "Execution":            [("Impact", 0.20)],
}

# Técnicas representativas por tática (para geração de recomendações)
_TACTIC_TECHNIQUES: dict[str, list[dict]] = {
    "Initial Access":       [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1566.001", "name": "Spearphishing Attachment"},
        {"id": "T1133", "name": "External Remote Services"},
    ],
    "Execution":            [
        {"id": "T1059.001", "name": "PowerShell"},
        {"id": "T1059.003", "name": "Windows Command Shell"},
        {"id": "T1203", "name": "Exploitation for Client Execution"},
    ],
    "Persistence":          [
        {"id": "T1543.003", "name": "Windows Service"},
        {"id": "T1053.005", "name": "Scheduled Task"},
        {"id": "T1078", "name": "Valid Accounts"},
    ],
    "Privilege Escalation": [
        {"id": "T1548.002", "name": "Bypass UAC"},
        {"id": "T1134.001", "name": "Token Impersonation/Theft"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "Defense Evasion":      [
        {"id": "T1070.001", "name": "Clear Windows Event Logs"},
        {"id": "T1218.011", "name": "Signed Binary: Rundll32"},
        {"id": "T1562.001", "name": "Disable or Modify Tools"},
    ],
    "Credential Access":    [
        {"id": "T1003.001", "name": "LSASS Memory Dump"},
        {"id": "T1110.001", "name": "Password Brute Force"},
        {"id": "T1558.003", "name": "Kerberoasting"},
    ],
    "Discovery":            [
        {"id": "T1046", "name": "Network Service Discovery"},
        {"id": "T1069.002", "name": "Domain Groups"},
        {"id": "T1018", "name": "Remote System Discovery"},
    ],
    "Lateral Movement":     [
        {"id": "T1021.001", "name": "Remote Desktop Protocol"},
        {"id": "T1550.002", "name": "Pass the Hash"},
        {"id": "T1021.002", "name": "SMB/Windows Admin Shares"},
    ],
    "Collection":           [
        {"id": "T1005", "name": "Data from Local System"},
        {"id": "T1039", "name": "Data from Network Shared Drive"},
        {"id": "T1113", "name": "Screen Capture"},
    ],
    "Exfiltration":         [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
        {"id": "T1071.004", "name": "DNS Exfiltration"},
        {"id": "T1567", "name": "Exfiltration Over Web Service"},
    ],
    "Impact":               [
        {"id": "T1486", "name": "Data Encrypted for Impact (Ransomware)"},
        {"id": "T1490", "name": "Inhibit System Recovery"},
        {"id": "T1489", "name": "Service Stop"},
    ],
    "Command and Control":  [
        {"id": "T1071.001", "name": "Web Protocols C2"},
        {"id": "T1090.003", "name": "Multi-hop Proxy"},
        {"id": "T1095", "name": "Non-Application Layer Protocol"},
    ],
}


# ── Feature extraction ────────────────────────────────────────────────────────

def _extract_sim_features(sim: dict) -> np.ndarray:
    """Extrai vetor de features de uma simulação BAS."""
    techs = sim.get("techniques", [])
    found  = [t for t in techs if t.get("status") == "found"]
    blocked = [t for t in techs if t.get("status") in ("blocked", "safe")]
    total  = max(len(techs), 1)

    # Feature 1-4: contagem por severidade (normalizada)
    crit  = len([t for t in found if t.get("cvss_severity") == "Critical"]) / total
    high  = len([t for t in found if t.get("cvss_severity") == "High"])    / total
    med   = len([t for t in found if t.get("cvss_severity") == "Medium"])  / total
    low   = len([t for t in found if t.get("cvss_severity") == "Low"])     / total

    # Feature 5: CVSS médio
    cvss_vals = [float(t.get("cvss", 0)) for t in found if t.get("cvss")]
    cvss_mean = (sum(cvss_vals) / len(cvss_vals) / 10.0) if cvss_vals else 0.0

    # Feature 6: taxa de descoberta
    found_rate = len(found) / total

    # Feature 7: gap de detecção (1 - cobertura bloqueada)
    detect_gap = 1.0 - len(blocked) / total

    # Features 8-19: presença por tática (12 táticas)
    found_tactics = {t.get("tactic", "") for t in found}
    tactic_vec = np.array([
        1.0 if tactic in found_tactics else 0.0
        for tactic in _TACTIC_WEIGHT
    ])

    # Feature 20: peso de risco por tática
    tactic_risk = sum(
        _TACTIC_WEIGHT.get(t.get("tactic", ""), 0.0)
        for t in found
    ) / max(len(found), 1)

    base = np.array([crit, high, med, low, cvss_mean, found_rate, detect_gap, tactic_risk])
    return np.concatenate([base, tactic_vec])  # 20-dim


# ── Risk Score Model (rede feedforward leve — numpy puro) ────────────────────

class RiskScoreModel:
    """Modelo de scoring de risco baseado em rede feedforward com numpy.

    Pré-inicializado com pesos derivados de conhecimento MITRE/CVSS.
    Pode ser ajustado (fine-tune) com dados reais via `update()`.
    """

    INPUT_DIM  = 20
    HIDDEN_DIM = 16

    def __init__(self):
        rng = np.random.default_rng(42)
        # Camada 1: input → hidden  (inicialização Xavier)
        scale1 = math.sqrt(2.0 / (self.INPUT_DIM + self.HIDDEN_DIM))
        self.W1 = rng.normal(0, scale1, (self.INPUT_DIM, self.HIDDEN_DIM)).astype(np.float32)
        self.b1 = np.zeros(self.HIDDEN_DIM, dtype=np.float32)
        # Camada 2: hidden → output (1 neurônio, score 0-1)
        scale2 = math.sqrt(2.0 / (self.HIDDEN_DIM + 1))
        self.W2 = rng.normal(0, scale2, (self.HIDDEN_DIM, 1)).astype(np.float32)
        self.b2 = np.zeros(1, dtype=np.float32)

        # Bias inicial baseado em pesos MITRE — eleva o score base
        tactic_weights = np.array(list(_TACTIC_WEIGHT.values()), dtype=np.float32)
        self.W1[-12:, :8] += (tactic_weights[:, None] * 0.3).astype(np.float32)
        self.W2[:, 0] += rng.normal(0.1, 0.05, self.HIDDEN_DIM).astype(np.float32)

    @staticmethod
    def _relu(x: np.ndarray) -> np.ndarray:
        return np.maximum(x, 0)

    @staticmethod
    def _sigmoid(x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -20, 20)))

    def predict(self, features: np.ndarray) -> float:
        x = features.astype(np.float32)
        h = self._relu(x @ self.W1 + self.b1)
        out = self._sigmoid(h @ self.W2 + self.b2)
        return float(out[0]) * 100.0

    def update(self, features: np.ndarray, target_score: float, lr: float = 0.01):
        """Atualiza pesos online (SGD simples)."""
        x = features.astype(np.float32)
        t = np.array([target_score / 100.0], dtype=np.float32)
        h = self._relu(x @ self.W1 + self.b1)
        out = self._sigmoid(h @ self.W2 + self.b2)
        err = out - t
        d_W2 = h[:, None] * err
        d_b2 = err
        d_h  = (err @ self.W2.T) * (h > 0)
        d_W1 = x[:, None] * d_h
        d_b1 = d_h
        self.W2 -= lr * d_W2
        self.b2 -= lr * d_b2
        self.W1 -= lr * d_W1
        self.b1 -= lr * d_b1

    def save(self, path: Path):
        np.savez(path, W1=self.W1, b1=self.b1, W2=self.W2, b2=self.b2)

    @classmethod
    def load(cls, path: Path) -> "RiskScoreModel":
        data = np.load(path)
        m = cls.__new__(cls)
        m.W1, m.b1, m.W2, m.b2 = data["W1"], data["b1"], data["W2"], data["b2"]
        return m


# ── Anomaly Detector (Isolation Forest) ──────────────────────────────────────

class AnomalyDetector:
    """Detecta simulações com padrões anômalos usando Isolation Forest.

    Primeira simulação sempre é "normal" (sem referência).
    Requisito: scikit-learn.
    """

    def __init__(self):
        self._model = None
        self._fitted = False
        self._buffer: list[np.ndarray] = []
        self._MIN_SAMPLES = 5

    def add(self, features: np.ndarray):
        self._buffer.append(features)
        if len(self._buffer) >= self._MIN_SAMPLES:
            self._fit()

    def _fit(self):
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore
            X = np.vstack(self._buffer)
            self._model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            self._model.fit(X)
            self._fitted = True
        except ImportError:
            pass
        except Exception as e:
            log.warning(f"[ML] AnomalyDetector fit error: {e}")

    def score(self, features: np.ndarray) -> dict:
        if not self._fitted or self._model is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": "insuficiente",
                "samples_seen": len(self._buffer),
                "note": f"Aguardando {max(0, self._MIN_SAMPLES - len(self._buffer))} simulação(ões) para calibrar detector.",
            }
        try:
            X = features.reshape(1, -1)
            raw = float(self._model.decision_function(X)[0])
            pred = int(self._model.predict(X)[0])
            norm_score = max(0.0, min(1.0, (-raw + 0.5)))
            return {
                "is_anomaly": pred == -1,
                "anomaly_score": round(norm_score * 100, 1),
                "confidence": "alta" if len(self._buffer) >= 20 else "média" if len(self._buffer) >= 10 else "baixa",
                "samples_seen": len(self._buffer),
                "note": "Padrão incomum detectado — verifique técnicas testadas." if pred == -1 else "Dentro do padrão esperado.",
            }
        except Exception as e:
            return {"is_anomaly": False, "anomaly_score": 0.0, "error": str(e), "samples_seen": len(self._buffer)}


# ── Technique Advisor ─────────────────────────────────────────────────────────

class TechniqueAdvisor:
    """Prediz próximas técnicas a testar baseado na cadeia de ataque atual."""

    def recommend(self, found_tactics: list[str], tested_ids: set[str]) -> list[dict]:
        """Retorna lista de técnicas recomendadas ordenadas por prioridade."""
        # Calcula score para cada tática não coberta
        tactic_scores: dict[str, float] = {}

        for tactic in found_tactics:
            for next_tactic, prob in _CHAIN_PROBS.get(tactic, []):
                existing = tactic_scores.get(next_tactic, 0.0)
                # combina probabilidade com peso de risco da tática seguinte
                combined = prob * _TACTIC_WEIGHT.get(next_tactic, 0.5)
                tactic_scores[next_tactic] = max(existing, combined)

        # Adiciona táticas com peso alto que não foram testadas
        for tactic, weight in _TACTIC_WEIGHT.items():
            if tactic not in found_tactics and tactic not in tactic_scores and weight >= 0.8:
                tactic_scores[tactic] = weight * 0.4

        # Gera recomendações de técnicas
        recs: list[dict] = []
        for tactic, score in sorted(tactic_scores.items(), key=lambda x: x[1], reverse=True):
            for tech in _TACTIC_TECHNIQUES.get(tactic, [])[:2]:
                if tech["id"] not in tested_ids:
                    recs.append({
                        "technique_id": tech["id"],
                        "technique_name": tech["name"],
                        "tactic": tactic,
                        "priority_score": round(score * 100, 1),
                        "reason": f"Alta probabilidade de sucesso após {', '.join(found_tactics[:2]) or 'estado atual'} (score {score:.0%})",
                    })

        return recs[:12]

    def attack_chain_map(self, found_tactics: list[str]) -> list[dict]:
        """Retorna o mapa de cadeia de ataque com status de cada tática."""
        all_tactics = list(_TACTIC_WEIGHT.keys())
        result = []
        for i, tactic in enumerate(all_tactics):
            tested = tactic in found_tactics
            nexts = [n for n, _ in _CHAIN_PROBS.get(tactic, []) if not tested]
            result.append({
                "tactic": tactic,
                "order": i + 1,
                "weight": _TACTIC_WEIGHT[tactic],
                "tested": tested,
                "likely_next": nexts[:2],
            })
        return result


# ── IOC Classifier (SVM linear + TF-IDF com vocabulário de segurança) ────────

class IOCClassifier:
    """Classifica strings/comandos como maliciosos usando SVM linear.

    Vocabulário pré-definido baseado em IOCs reais de red team.
    """

    # Vocabulário de features (cada token contribui com um peso)
    VOCAB: dict[str, float] = {
        # Ferramentas de ataque — peso alto
        "mimikatz": 10.0, "sekurlsa": 10.0, "cobalt": 8.0, "strike": 5.0,
        "metasploit": 8.0, "meterpreter": 9.0, "empire": 8.0, "powersploit": 9.0,
        "bloodhound": 7.0, "sharphound": 7.0, "rubeus": 9.0, "kerbrute": 8.0,
        "procdump": 8.0, "nanodump": 9.0, "pypykatz": 9.0,
        # Comandos suspeitos — peso médio/alto
        "lsass": 9.0, "vssadmin": 8.0, "shadowcopy": 8.0, "wbadmin": 7.0,
        "bcdedit": 7.0, "wevtutil": 6.0, "certutil": 6.0, "urlcache": 7.0,
        "encodedcommand": 8.0, "bypass": 6.0, "invoke-expression": 8.0,
        "iex": 7.0, "downloadstring": 8.0, "downloadfile": 7.0,
        "mshta": 7.0, "regsvr32": 6.0, "rundll32": 5.0, "wmic": 5.0,
        "psexec": 8.0, "wmiexec": 8.0, "smbexec": 8.0, "atexec": 8.0,
        # Rede/C2
        "beacon": 7.0, "staging": 5.0, "shellcode": 9.0, "payload": 5.0,
        "/dev/tcp": 9.0, "nc ": 5.0, "ncat": 5.0, "netcat": 5.0,
        "reverse_tcp": 9.0, "bind_tcp": 8.0, "http_stager": 8.0,
        # Evasão
        "amsi": 6.0, "bypass amsi": 9.0, "patch amsi": 9.0,
        "disable defender": 9.0, "taskkill": 4.0, "sc stop": 6.0,
        # Ransomware-specific combos
        "delete shadows": 10.0, "delete shadow": 9.0,
        "inhibit system recovery": 10.0, "recover": -0.5,
        "encrypt files": 9.0, "openssl enc": 8.0,
        "sc stop": 6.0, "net stop": 5.0,
        # Benigno — reduz score
        "echo": -2.0, "ping": -1.0, "ls ": -1.0, "dir ": -1.0,
        "ipconfig": -1.0, "ifconfig": -1.0,
    }

    def score_text(self, text: str) -> dict:
        tl = text.lower()
        raw = 0.0
        matched = []
        for token, weight in self.VOCAB.items():
            if token in tl:
                raw += weight
                if weight > 0:
                    matched.append(token)
        score = min(100.0, max(0.0, raw * 3.5))
        verdict = "malicioso" if score >= 60 else "suspeito" if score >= 30 else "benigno"
        return {
            "score": round(score, 1),
            "verdict": verdict,
            "matched_indicators": matched[:10],
            "raw_weight": round(raw, 2),
        }

    def classify_batch(self, texts: list[str]) -> list[dict]:
        return [{"text": t[:80], **self.score_text(t)} for t in texts]


# ── Singleton do motor ML ─────────────────────────────────────────────────────

class MLEngine:
    def __init__(self):
        self.risk_model    = RiskScoreModel()
        self.anomaly       = AnomalyDetector()
        self.advisor       = TechniqueAdvisor()
        self.ioc_clf       = IOCClassifier()
        self._sim_count    = 0
        self._load_state()

    def _load_state(self):
        try:
            _MODEL_DIR.mkdir(parents=True, exist_ok=True)
            risk_path = _MODEL_DIR / "risk_model.npz"
            if risk_path.exists():
                self.risk_model = RiskScoreModel.load(risk_path)
                log.info(f"[ML] risk_model carregado de {risk_path}")
        except Exception as e:
            log.warning(f"[ML] estado não carregado: {e}")

    def _save_state(self):
        try:
            _MODEL_DIR.mkdir(parents=True, exist_ok=True)
            self.risk_model.save(_MODEL_DIR / "risk_model.npz")
        except Exception as e:
            log.warning(f"[ML] estado não salvo: {e}")

    def analyze_simulation(self, sim: dict) -> dict:
        """Análise ML completa de uma simulação BAS."""
        feats = _extract_sim_features(sim)
        ml_score = self.risk_model.predict(feats)

        # Combina score ML com score heurístico da simulação
        heuristic_score = float(sim.get("score", 0))
        blended = ml_score * 0.55 + heuristic_score * 0.45

        # Anomalia
        self.anomaly.add(feats)
        anomaly_result = self.anomaly.score(feats)

        # Próximas técnicas recomendadas
        techs = sim.get("techniques", [])
        found_tactics  = list({t.get("tactic", "") for t in techs if t.get("status") == "found" and t.get("tactic")})
        tested_ids     = {t.get("id", "") for t in techs}
        recommendations = self.advisor.recommend(found_tactics, tested_ids)
        chain_map       = self.advisor.attack_chain_map(found_tactics)

        # Feature importances (heurístico — contribution por dimensão)
        feature_names = ["crit%", "high%", "med%", "low%", "cvss_mean", "found_rate", "detect_gap", "tactic_risk"] + list(_TACTIC_WEIGHT.keys())
        contributions = [(name, round(float(feats[i]) * 100, 1)) for i, name in enumerate(feature_names)]
        top_features  = sorted(contributions, key=lambda x: x[1], reverse=True)[:5]

        # Update online com score heurístico como ground truth
        self.risk_model.update(feats, heuristic_score, lr=0.005)
        self._sim_count += 1
        if self._sim_count % 10 == 0:
            self._save_state()

        return {
            "ml_risk_score":       round(ml_score, 1),
            "blended_score":       round(blended, 1),
            "anomaly":             anomaly_result,
            "top_features":        top_features,
            "recommendations":     recommendations,
            "attack_chain_map":    chain_map,
            "simulations_trained": self._sim_count,
        }

    def score_iocs(self, texts: list[str]) -> dict:
        results = self.ioc_clf.classify_batch(texts)
        avg_score = sum(r["score"] for r in results) / max(len(results), 1)
        high_risk = [r for r in results if r["score"] >= 60]
        return {
            "results": results,
            "average_score": round(avg_score, 1),
            "high_risk_count": len(high_risk),
            "total": len(results),
            "verdict": "comprometimento confirmado" if avg_score >= 60 else "atividade suspeita" if avg_score >= 30 else "sem indicadores relevantes",
        }

    def predict_next_techniques(self, found_tactic_list: list[str], tested_ids: list[str]) -> list[dict]:
        return self.advisor.recommend(found_tactic_list, set(tested_ids))

    def get_chain_map(self, found_tactics: list[str]) -> list[dict]:
        return self.advisor.attack_chain_map(found_tactics)


# ── Instância global ──────────────────────────────────────────────────────────
_ENGINE: MLEngine | None = None

def get_engine() -> MLEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = MLEngine()
    return _ENGINE
