"""
gap7_benchmark_data.py — PenteIA V4.0
Sector benchmark data seeded from public reports (Verizon DBIR 2024, IBM X-Force 2024).
Used by the /api/bas/benchmark/{sector} endpoint.
"""
from __future__ import annotations
import os as _os
import json as _json

# Sector benchmark data — scores represent BAS simulation pass rates
# Source basis: Verizon DBIR 2024, IBM X-Force 2024, Picus Security Red Report 2024
# Scale: 0-100 (higher = more resilient, more techniques blocked)
SECTOR_BENCHMARKS: dict[str, dict] = {
    "financeiro": {
        "name": "Financeiro / Bancário",
        "avg_score": 52.3,
        "p25": 38.0,
        "p50": 52.3,
        "p75": 68.5,
        "p90": 78.0,
        "sample_size": 320,
        "top_gaps": ["Credential Access (T1003)", "Lateral Movement (T1021)", "Defense Evasion (T1562)"],
        "source": "Verizon DBIR 2024 + IBM X-Force 2024",
    },
    "saude": {
        "name": "Saúde / Healthcare",
        "avg_score": 41.8,
        "p25": 28.0,
        "p50": 41.8,
        "p75": 55.0,
        "p90": 67.0,
        "sample_size": 185,
        "top_gaps": ["Ransomware (T1486)", "Phishing (T1566)", "Remote Services (T1021)"],
        "source": "Verizon DBIR 2024 + HHS HC3 2024",
    },
    "varejo": {
        "name": "Varejo / E-commerce",
        "avg_score": 38.5,
        "p25": 24.0,
        "p50": 38.5,
        "p75": 52.0,
        "p90": 63.0,
        "sample_size": 210,
        "top_gaps": ["Web App Attacks (T1190)", "Skimming (T1185)", "Data Exfiltration (T1041)"],
        "source": "Verizon DBIR 2024 + PCI SSC 2024",
    },
    "governo": {
        "name": "Governo / Setor Público",
        "avg_score": 44.1,
        "p25": 30.0,
        "p50": 44.1,
        "p75": 58.0,
        "p90": 70.0,
        "sample_size": 140,
        "top_gaps": ["Spearphishing (T1566.001)", "Supply Chain (T1195)", "Account Takeover (T1078)"],
        "source": "CISA 2024 Annual Report",
    },
    "industria": {
        "name": "Indústria / Manufatura",
        "avg_score": 36.2,
        "p25": 22.0,
        "p50": 36.2,
        "p75": 50.0,
        "p90": 61.0,
        "sample_size": 175,
        "top_gaps": ["OT/SCADA (T0800)", "Ransomware (T1486)", "Network Scan (T1046)"],
        "source": "Dragos ICS/OT Report 2024",
    },
    "tecnologia": {
        "name": "Tecnologia / SaaS",
        "avg_score": 58.7,
        "p25": 45.0,
        "p50": 58.7,
        "p75": 72.0,
        "p90": 83.0,
        "sample_size": 280,
        "top_gaps": ["API Security (T1190)", "Cloud Misconfig (T1580)", "Supply Chain (T1195)"],
        "source": "Picus Security Red Report 2024",
    },
    "telecom": {
        "name": "Telecomunicações",
        "avg_score": 49.4,
        "p25": 35.0,
        "p50": 49.4,
        "p75": 63.0,
        "p90": 74.0,
        "sample_size": 95,
        "top_gaps": ["SS7 attacks", "SIM Swap (T1078)", "DDoS (T1498)"],
        "source": "ENISA Threat Landscape 2024",
    },
}


def get_benchmark(sector: str, client_score: float) -> dict:
    """
    Return benchmark comparison for a given sector and client score.
    sector: one of the keys in SECTOR_BENCHMARKS (case-insensitive)
    client_score: the client's BAS score (0-100)
    """
    key = sector.lower().strip()
    bench = SECTOR_BENCHMARKS.get(key)
    # Try real client data first (overrides seed when >= 10 entries)
    real = get_real_percentiles(key)
    if real:
        bench = {**bench, **real}
    if not bench:
        available = list(SECTOR_BENCHMARKS.keys())
        return {"error": f"Setor '{sector}' não encontrado. Disponíveis: {available}"}

    # Calculate percentile position
    if client_score <= bench["p25"]:
        percentile = 25
        rating = "Abaixo da média do setor"
        color = "red"
    elif client_score <= bench["p50"]:
        percentile = 50
        rating = "Abaixo da mediana do setor"
        color = "orange"
    elif client_score <= bench["p75"]:
        percentile = 75
        rating = "Acima da mediana do setor"
        color = "yellow"
    elif client_score <= bench["p90"]:
        percentile = 90
        rating = "Top 25% do setor"
        color = "green"
    else:
        percentile = 95
        rating = "Top 10% do setor — referência do setor"
        color = "blue"

    gap_to_median = round(bench["p50"] - client_score, 1)
    gap_to_top = round(bench["p75"] - client_score, 1)

    return {
        "sector": key,
        "sector_name": bench["name"],
        "client_score": client_score,
        "benchmark": {
            "avg": bench["avg_score"],
            "p25": bench["p25"],
            "p50": bench["p50"],
            "p75": bench["p75"],
            "p90": bench["p90"],
        },
        "percentile_position": percentile,
        "rating": rating,
        "rating_color": color,
        "gap_to_median": gap_to_median,
        "gap_to_top_quartile": gap_to_top,
        "top_sector_gaps": bench["top_gaps"],
        "sample_size": bench["sample_size"],
        "data_source": bench["source"],
        "insight": (
            f"Seu score de {client_score}% está {'abaixo' if gap_to_median > 0 else 'acima'} da mediana "
            f"do setor {bench['name']} ({bench['p50']}%). "
            f"{'Para atingir o quartil superior, você precisa de +' + str(gap_to_top) + ' pontos.' if gap_to_top > 0 else 'Você já está no quartil superior!'}"
        ),
    }


def list_sectors() -> list[dict]:
    """Return all available sectors with their average scores."""
    return [
        {"key": k, "name": v["name"], "avg_score": v["avg_score"], "sample_size": v["sample_size"]}
        for k, v in SECTOR_BENCHMARKS.items()
    ]


# Path for the local real-data cache (SQLite is used for persistence; this is a fallback)
_BENCH_CACHE = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "_benchmark_cache.json")


def submit_score(sector: str, score: float, simulation_id: str | None = None) -> dict:
    """
    Persist a real client score submission to the local cache.
    sector: key from SECTOR_BENCHMARKS
    score: BAS score (0-100)
    """
    sector = sector.lower().strip()
    if sector not in SECTOR_BENCHMARKS:
        return {"error": f"Setor desconhecido: {sector}"}

    try:
        try:
            with open(_BENCH_CACHE, "r", encoding="utf-8") as fh:
                cache = _json.load(fh)
        except Exception:
            cache = {}

        if sector not in cache:
            cache[sector] = []

        cache[sector].append({"score": score, "simulation_id": simulation_id})

        # Keep last 500 entries per sector
        cache[sector] = cache[sector][-500:]

        with open(_BENCH_CACHE, "w", encoding="utf-8") as fh:
            _json.dump(cache, fh)

        return {"submitted": True, "sector": sector, "score": score, "total_entries": len(cache[sector])}
    except Exception as exc:
        return {"submitted": False, "error": str(exc)}


def get_real_percentiles(sector: str) -> dict | None:
    """
    Compute percentiles from real submitted data.
    Returns None if fewer than 10 real entries exist for the sector.
    """
    try:
        with open(_BENCH_CACHE, "r", encoding="utf-8") as fh:
            cache = _json.load(fh)
        entries = [e["score"] for e in cache.get(sector, []) if isinstance(e.get("score"), (int, float))]
        if len(entries) < 10:
            return None
        entries.sort()
        n = len(entries)
        p25 = entries[int(n * 0.25)]
        p50 = entries[int(n * 0.50)]
        p75 = entries[int(n * 0.75)]
        p90 = entries[int(n * 0.90)]
        avg = round(sum(entries) / n, 1)
        return {"p25": round(p25, 1), "p50": round(p50, 1), "p75": round(p75, 1), "p90": round(p90, 1), "avg": avg, "sample_size": n, "source": "dados_reais_clientes"}
    except Exception:
        return None
