"""LLM narrativa para relatórios PenteIA.

Adaptado de sec365-Org/Sentinel/src/narrative/llm.py.
Standalone — sem dependências externas do Sentinel.

Configuração via env:
    PENTEIA_LLM_MODEL_PATH=/path/to/model.gguf
    PENTEIA_LLM_THREADS=4
    PENTEIA_LLM_CTX=2048
    PENTEIA_LLM_DISABLED=1     # força fallback template
    PENTEIA_LLM_TIMEOUT_S=30

Modelos recomendados (GGUF Q4_K_M, CPU-friendly):
    - Qwen2.5-0.5B-Instruct (~500MB)
    - SmolLM2-1.7B-Instruct (~1GB)
    - Llama-3.2-1B-Instruct (~700MB)

Sem modelo: gera sumário por template automaticamente.
"""
from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import unicodedata
from typing import Any

log = logging.getLogger(__name__)

_LLM_INSTANCE: Any | None = None
_LLM_LOAD_FAILED: bool = False
_DEFAULT_TIMEOUT_S = 30

_UNICODE_PROBLEM_RE = re.compile(
    "[​‌‍‎‏‪-‮⁦-⁩﻿­]"
)

_INFERENCE_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="penteia_llm"
)


def _is_disabled() -> bool:
    return os.getenv("PENTEIA_LLM_DISABLED", "").lower() in ("1", "true", "yes")


def _model_path() -> str | None:
    p = os.getenv("PENTEIA_LLM_MODEL_PATH", "")
    return p if p and os.path.exists(p) else None


def _timeout() -> int:
    try:
        return int(os.getenv("PENTEIA_LLM_TIMEOUT_S", str(_DEFAULT_TIMEOUT_S)))
    except ValueError:
        return _DEFAULT_TIMEOUT_S


def get_llm():
    global _LLM_INSTANCE, _LLM_LOAD_FAILED
    if _is_disabled() or _LLM_LOAD_FAILED:
        return None
    if _LLM_INSTANCE is not None:
        return _LLM_INSTANCE
    path = _model_path()
    if not path:
        _LLM_LOAD_FAILED = True
        return None
    try:
        from llama_cpp import Llama  # type: ignore[import-not-found]
        threads = int(os.getenv("PENTEIA_LLM_THREADS", "4"))
        ctx = int(os.getenv("PENTEIA_LLM_CTX", "2048"))
        _LLM_INSTANCE = Llama(model_path=path, n_ctx=ctx, n_threads=threads, verbose=False, n_gpu_layers=0)
        log.info(f"[LLM] carregado: {path}")
        return _LLM_INSTANCE
    except ImportError:
        log.warning("llama-cpp-python não instalado — usando template fallback")
        _LLM_LOAD_FAILED = True
        return None
    except Exception as e:
        log.error(f"[LLM] falha ao carregar: {e}")
        _LLM_LOAD_FAILED = True
        return None


def is_available() -> bool:
    return get_llm() is not None


def _sanitize(text: str, max_len: int = 200) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = "".join(ch if unicodedata.category(ch) not in ("Cc", "Cf") else " " for ch in text)
    text = _UNICODE_PROBLEM_RE.sub("", text)
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:max_len] if len(text) > max_len else text


_REPORT_PROMPT = """Você é um analista de segurança sênior. Escreva um sumário executivo em PORTUGUÊS
BRASILEIRO com base nos dados abaixo. Máx 150 palavras. Seja técnico, direto e objetivo.

DADOS DO RELATÓRIO PENTEIA:
{data}

SUMÁRIO EXECUTIVO:"""


def _template_summary(data: dict) -> str:
    """Fallback quando LLM não disponível."""
    score = data.get("risk_score", 0)
    total = data.get("total_tests", 0)
    found = data.get("found", 0)
    blocked = data.get("blocked", 0)
    target = _sanitize(str(data.get("target", "alvo")))
    top_techs = data.get("top_critical_techniques", [])

    level = "crítico" if score >= 80 else "alto" if score >= 60 else "médio" if score >= 40 else "baixo"

    parts = [
        f"A simulação BAS contra {target} revelou um nível de risco {level} (score {score}/100).",
        f"De {total} técnicas testadas, {found} vulnerabilidades foram confirmadas e {blocked} foram bloqueadas.",
    ]

    if top_techs:
        names = ", ".join(_sanitize(str(t)) for t in top_techs[:3])
        parts.append(f"As técnicas de maior criticidade identificadas foram: {names}.")

    if score >= 70:
        parts.append("Recomenda-se ação imediata: revisão de configurações de segurança, aplicação de patches e reforço do monitoramento SOC.")
    elif score >= 40:
        parts.append("Recomenda-se priorizar a remediação das vulnerabilidades críticas e revisar as políticas de detecção do SIEM.")
    else:
        parts.append("Os controles de segurança demonstraram boa efetividade. Mantenha o ciclo de simulação para garantir cobertura contínua.")

    return " ".join(parts)


def summarize_simulation(data: dict, timeout: int | None = None) -> str:
    """Gera sumário narrativo de uma simulação BAS.

    Args:
        data: dict com keys: target, risk_score, total_tests, found, blocked,
              top_critical_techniques (list[str]), detection_coverage_pct, compliance (list[str])
        timeout: segundos para aguardar LLM (default: PENTEIA_LLM_TIMEOUT_S)

    Returns:
        String narrativa (LLM ou template fallback).
    """
    llm = get_llm()
    if llm is None:
        return _template_summary(data)

    timeout_s = timeout if timeout is not None else _timeout()

    def _fmt_data(d: dict) -> str:
        lines = [
            f"Alvo: {_sanitize(str(d.get('target', '')))}",
            f"Score de risco: {d.get('risk_score', 0)}/100",
            f"Testes realizados: {d.get('total_tests', 0)}",
            f"Vulnerabilidades encontradas: {d.get('found', 0)}",
            f"Ataques bloqueados: {d.get('blocked', 0)}",
            f"Cobertura de detecção: {d.get('detection_coverage_pct', 0)}%",
        ]
        techs = d.get("top_critical_techniques", [])
        if techs:
            lines.append(f"Técnicas críticas: {', '.join(_sanitize(str(t)) for t in techs[:5])}")
        comp = d.get("compliance", [])
        if comp:
            lines.append(f"Frameworks impactados: {', '.join(_sanitize(str(c)) for c in comp[:5])}")
        return "\n".join(lines)

    def _infer() -> str:
        prompt = _REPORT_PROMPT.format(data=_fmt_data(data))
        out = llm(prompt, max_tokens=250, temperature=0.25, top_p=0.9, stop=["\n\n\n", "DADOS:", "###"])
        text = out.get("choices", [{}])[0].get("text", "").strip()
        if text.startswith("SUMÁRIO"):
            text = text.split(":", 1)[-1].strip()
        return text[:1200]

    try:
        future = _INFERENCE_EXECUTOR.submit(_infer)
        return future.result(timeout=timeout_s)
    except concurrent.futures.TimeoutError:
        log.warning(f"[LLM] timeout após {timeout_s}s — usando template")
        return _template_summary(data)
    except Exception as e:
        log.warning(f"[LLM] erro: {e}")
        return _template_summary(data)
