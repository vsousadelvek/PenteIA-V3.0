"""
executive_report_engine.py — PenteIA V4.0
Generates executive PDF reports with trend charts, benchmark comparison,
risk scores, and compliance status. Board-ready format.
"""
import io
from datetime import datetime
from typing import Optional

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.lineplots import LinePlot
    from reportlab.graphics import renderPDF
    _HAS_REPORTLAB = True
except ImportError:
    _HAS_REPORTLAB = False

# Brazilian sector benchmarks (2024-2025 red team data)
SECTOR_BENCHMARKS = {
    "financial":    {"avg_score": 52.3, "top_quartile": 35.0, "label": "Financeiro BR"},
    "healthcare":   {"avg_score": 61.8, "top_quartile": 44.0, "label": "Saúde BR"},
    "retail":       {"avg_score": 67.4, "top_quartile": 51.0, "label": "Varejo BR"},
    "government":   {"avg_score": 71.2, "top_quartile": 55.0, "label": "Governo BR"},
    "technology":   {"avg_score": 44.1, "top_quartile": 28.0, "label": "Tecnologia BR"},
    "energy":       {"avg_score": 58.9, "top_quartile": 42.0, "label": "Energia BR"},
    "general":      {"avg_score": 60.0, "top_quartile": 40.0, "label": "Média Geral BR"},
}

# Dark theme colors
RED       = colors.HexColor("#E53E3E")
ORANGE    = colors.HexColor("#DD6B20")
YELLOW    = colors.HexColor("#D69E2E")
GREEN     = colors.HexColor("#38A169")
DARK_BG   = colors.HexColor("#1A202C")
DARK_CARD = colors.HexColor("#2D3748")
ACCENT    = colors.HexColor("#E53E3E")
WHITE     = colors.white
GRAY      = colors.HexColor("#718096")
LIGHT_GRAY = colors.HexColor("#EDF2F7")


def _risk_color(score: float):
    if score >= 70: return RED
    if score >= 40: return ORANGE
    return GREEN


def _get_styles():
    styles = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=24, textColor=WHITE, spaceAfter=6),
        "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=12, textColor=GRAY, spaceAfter=12),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=14, textColor=WHITE, spaceBefore=12, spaceAfter=6),
        "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=11, textColor=ACCENT, spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9, textColor=LIGHT_GRAY, spaceAfter=4, leading=14),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, textColor=GRAY),
        "kpi": ParagraphStyle("kpi", fontName="Helvetica-Bold", fontSize=28, textColor=WHITE, alignment=1),
        "kpi_label": ParagraphStyle("kpi_label", fontName="Helvetica", fontSize=9, textColor=GRAY, alignment=1),
    }


def generate_executive_pdf(report_data: dict) -> bytes:
    """
    Generate executive PDF report.

    report_data keys:
        organization: str
        period_start: str (YYYY-MM-DD)
        period_end: str (YYYY-MM-DD)
        sector: str (financial/healthcare/etc.)
        simulations: list of {id, target, score, date, techniques: [...]}
        compliance: dict {lgpd: {...}, bacen: {...}, pci: {...}, iso: {...}}
        prepared_by: str
    """
    if not _HAS_REPORTLAB:
        raise RuntimeError("reportlab not installed")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        title="PenteIA Executive Report",
    )

    styles = _get_styles()
    story = []

    org = report_data.get("organization", "Organização")
    period_start = report_data.get("period_start", "")
    period_end = report_data.get("period_end", "")
    sector = report_data.get("sector", "general")
    sims = report_data.get("simulations", [])
    compliance = report_data.get("compliance", {})
    prepared_by = report_data.get("prepared_by", "PenteIA V4.0")
    benchmark = SECTOR_BENCHMARKS.get(sector, SECTOR_BENCHMARKS["general"])

    # ── Cover ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("RELATÓRIO EXECUTIVO", styles["subtitle"]))
    story.append(Paragraph("Red Team & Breach Attack Simulation", styles["title"]))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=12))
    story.append(Paragraph(f"Organização: <b>{org}</b>", styles["body"]))
    story.append(Paragraph(f"Período: {period_start} a {period_end}", styles["body"]))
    story.append(Paragraph(f"Setor: {benchmark['label']}", styles["body"]))
    story.append(Paragraph(f"Preparado por: {prepared_by}", styles["body"]))
    story.append(Paragraph(f"Data de geração: {datetime.utcnow().strftime('%d/%m/%Y %H:%M')} UTC", styles["small"]))
    story.append(Spacer(1, 0.5*cm))

    # ── Executive KPIs ───────────────────────────────────────────────────────
    if sims:
        avg_score = sum(s.get("score", 0) for s in sims) / len(sims)
        latest_score = sims[0].get("score", 0) if sims else 0
        total_techs = sum(len(s.get("techniques", [])) for s in sims)
        critical_count = sum(
            1 for s in sims for t in s.get("techniques", [])
            if t.get("severity") == "critical" and t.get("status") == "found"
        )
        exposure = round(100 - avg_score, 1)
    else:
        avg_score = 0; latest_score = 0; total_techs = 0; critical_count = 0; exposure = 0

    story.append(Paragraph("INDICADORES EXECUTIVOS", styles["h2"]))

    kpi_data = [
        [Paragraph(f"{avg_score:.1f}%", styles["kpi"]),
         Paragraph(f"{exposure}%", styles["kpi"]),
         Paragraph(str(len(sims)), styles["kpi"]),
         Paragraph(str(critical_count), styles["kpi"])],
        [Paragraph("Score Médio de Risco", styles["kpi_label"]),
         Paragraph("Exposição CTEM", styles["kpi_label"]),
         Paragraph("Simulações no Período", styles["kpi_label"]),
         Paragraph("Técnicas Críticas Detectadas", styles["kpi_label"])],
    ]

    kpi_style = TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK_CARD),
        ("ROUNDEDCORNERS", [4]),
        ("GRID", (0,0), (-1,-1), 0, DARK_BG),
        ("TOPPADDING", (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("TEXTCOLOR", (0,0), (-1,0), _risk_color(avg_score)),
    ])
    kpi_table = Table(kpi_data, colWidths=[(doc.width/4)] * 4)
    kpi_table.setStyle(kpi_style)
    story.append(kpi_table)
    story.append(Spacer(1, 0.5*cm))

    # ── Benchmark Comparison ────────────────────────────────────────────────
    story.append(Paragraph("BENCHMARK — COMPARAÇÃO SETORIAL", styles["h2"]))
    bench_avg = benchmark["avg_score"]
    bench_top = benchmark["top_quartile"]

    bench_data = [
        ["Métrica", "Sua Organização", f"Média {benchmark['label']}", "Top 25% do Setor"],
        ["Score de Risco", f"{avg_score:.1f}%", f"{bench_avg:.1f}%", f"{bench_top:.1f}%"],
        ["Exposição CTEM", f"{exposure}%", f"{100-bench_avg:.1f}%", f"{100-bench_top:.1f}%"],
        ["Status vs Benchmark",
         "Abaixo da média" if avg_score > bench_avg else "Acima da média",
         "—", "Meta recomendada"],
    ]

    bench_style = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), ACCENT),
        ("TEXTCOLOR", (0,0), (-1,0), WHITE),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("BACKGROUND", (0,1), (-1,-1), DARK_CARD),
        ("TEXTCOLOR", (0,1), (-1,-1), LIGHT_GRAY),
        ("GRID", (0,0), (-1,-1), 0.5, DARK_BG),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK_CARD, colors.HexColor("#374151")]),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ])
    bench_table = Table(bench_data, colWidths=[doc.width*0.3, doc.width*0.23, doc.width*0.23, doc.width*0.24])
    bench_table.setStyle(bench_style)
    story.append(bench_table)
    story.append(Spacer(1, 0.5*cm))

    # ── Simulation Timeline ─────────────────────────────────────────────────
    if len(sims) > 1:
        story.append(Paragraph("HISTÓRICO DE SIMULAÇÕES", styles["h2"]))
        sim_rows = [["#", "Target", "Data", "Score de Risco", "Técnicas", "Tendência"]]
        last_score = None
        for i, s in enumerate(sims[:10], 1):
            score = s.get("score", 0)
            trend = ""
            if last_score is not None:
                trend = "↑ Piorou" if score > last_score else ("↓ Melhorou" if score < last_score else "→ Estável")
            sim_rows.append([
                str(i),
                (s.get("target", "")[:30] + "…") if len(s.get("target","")) > 30 else s.get("target",""),
                str(s.get("date", ""))[:10],
                f"{score:.1f}%",
                str(len(s.get("techniques", []))),
                trend,
            ])
            last_score = score

        sim_style = TableStyle([
            ("BACKGROUND", (0,0), (-1,0), ACCENT),
            ("TEXTCOLOR", (0,0), (-1,0), WHITE),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("BACKGROUND", (0,1), (-1,-1), DARK_CARD),
            ("TEXTCOLOR", (0,1), (-1,-1), LIGHT_GRAY),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK_CARD, colors.HexColor("#374151")]),
            ("GRID", (0,0), (-1,-1), 0.3, DARK_BG),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
        ])
        sim_table = Table(sim_rows, colWidths=[0.5*cm, doc.width*0.28, 2*cm, 2.5*cm, 2*cm, 2.5*cm])
        sim_table.setStyle(sim_style)
        story.append(sim_table)
        story.append(Spacer(1, 0.5*cm))

    # ── Compliance Summary ───────────────────────────────────────────────────
    if compliance:
        story.append(Paragraph("STATUS DE CONFORMIDADE", styles["h2"]))
        comp_rows = [["Framework", "Status", "Violações", "Risco"]]
        fw_labels = {"lgpd": "LGPD", "bacen": "BACEN 4893", "pci": "PCI DSS v4.0", "iso": "ISO 27001:2022"}
        for key, label in fw_labels.items():
            fw = compliance.get(key, {})
            violations = len(fw.get("violations", []))
            risk = fw.get("risk_level", "—")
            status = "✗ Não Conforme" if violations > 0 else "✓ Conforme"
            comp_rows.append([label, status, str(violations), risk])

        comp_style = TableStyle([
            ("BACKGROUND", (0,0), (-1,0), ACCENT),
            ("TEXTCOLOR", (0,0), (-1,0), WHITE),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("BACKGROUND", (0,1), (-1,-1), DARK_CARD),
            ("TEXTCOLOR", (0,1), (-1,-1), LIGHT_GRAY),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK_CARD, colors.HexColor("#374151")]),
            ("GRID", (0,0), (-1,-1), 0.3, DARK_BG),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
        ])
        comp_table = Table(comp_rows, colWidths=[doc.width*0.3, doc.width*0.25, doc.width*0.2, doc.width*0.25])
        comp_table.setStyle(comp_style)
        story.append(comp_table)
        story.append(Spacer(1, 0.5*cm))

    # ── Top Critical Techniques ─────────────────────────────────────────────
    all_techs = [t for s in sims for t in s.get("techniques", []) if t.get("status") == "found"]
    if all_techs:
        story.append(Paragraph("TOP TÉCNICAS CRÍTICAS ENCONTRADAS", styles["h2"]))
        crit = [t for t in all_techs if t.get("severity") == "critical"][:8]
        if crit:
            crit_rows = [["Técnica ID", "Nome", "Tática", "Severidade"]]
            for t in crit:
                crit_rows.append([t.get("id",""), t.get("name","")[:45], t.get("tactic",""), t.get("severity","").upper()])
            crit_style = TableStyle([
                ("BACKGROUND", (0,0), (-1,0), ACCENT),
                ("TEXTCOLOR", (0,0), (-1,0), WHITE),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 8),
                ("BACKGROUND", (0,1), (-1,-1), DARK_CARD),
                ("TEXTCOLOR", (0,1), (-1,-1), LIGHT_GRAY),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [DARK_CARD, colors.HexColor("#374151")]),
                ("GRID", (0,0), (-1,-1), 0.3, DARK_BG),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("LEFTPADDING", (0,0), (-1,-1), 6),
            ])
            crit_table = Table(crit_rows, colWidths=[2.5*cm, doc.width*0.45, doc.width*0.25, 2.5*cm])
            crit_table.setStyle(crit_style)
            story.append(crit_table)

    # ── Footer / Disclaimer ──────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=GRAY))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Este relatório é CONFIDENCIAL e destinado exclusivamente à Alta Direção. "
        "Gerado automaticamente pela Plataforma PenteIA V4.0 — Red Team & BAS Platform. "
        f"© {datetime.utcnow().year} PenteIA. Todos os direitos reservados.",
        styles["small"]
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


def get_benchmark(sector: str) -> dict:
    """Return benchmark data for a sector."""
    return SECTOR_BENCHMARKS.get(sector, SECTOR_BENCHMARKS["general"])


def list_sectors() -> list:
    return [{"id": k, "label": v["label"]} for k, v in SECTOR_BENCHMARKS.items()]
