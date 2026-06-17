"""
bacen_pdf_engine.py — PenteIA V4.0
Generates compliance PDF documents:
  1. BACEN Resolution 4.893/2021 Evidence Report
  2. ANPD Incident Notification (Resolution 15/2024)
"""

from __future__ import annotations

import io
import math
from datetime import datetime, date, timezone
from typing import Optional

def _now_utc() -> datetime:
    """Return current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)
from reportlab.platypus import Flowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

# ---------------------------------------------------------------------------
# Brand palette
# ---------------------------------------------------------------------------

DARK_BG = colors.HexColor("#1a1a2e")       # deep navy / charcoal
ACCENT_RED = colors.HexColor("#c0392b")    # PenteIA red
LIGHT_RED = colors.HexColor("#e74c3c")     # lighter red
GOLD = colors.HexColor("#f39c12")          # amber / warning
GREEN_OK = colors.HexColor("#27ae60")
GRAY_DARK = colors.HexColor("#2c3e50")
GRAY_MED = colors.HexColor("#7f8c8d")
GRAY_LIGHT = colors.HexColor("#ecf0f1")
WHITE = colors.white
BLACK = colors.black

# ---------------------------------------------------------------------------
# Severity / risk helpers
# ---------------------------------------------------------------------------

_SEVERITY_CVSS = {
    "critical": "9.0–10.0",
    "high": "7.0–8.9",
    "medium": "4.0–6.9",
    "low": "0.1–3.9",
    "info": "0.0",
}

_RISK_COLOR = {
    "critico": ACCENT_RED,
    "crítico": ACCENT_RED,
    "alto": colors.HexColor("#e67e22"),
    "médio": GOLD,
    "medio": GOLD,
    "baixo": GREEN_OK,
    "low": GREEN_OK,
    "medium": GOLD,
    "high": colors.HexColor("#e67e22"),
    "critical": ACCENT_RED,
}

# ---------------------------------------------------------------------------
# BACEN 4.893 article reference table
# ---------------------------------------------------------------------------

_BACEN_ARTICLES = [
    {
        "article": "Art. 4º §2",
        "title": "Testes anuais de segurança",
        "description": (
            "Realização de testes de penetração e avaliação de vulnerabilidades "
            "em sistemas críticos com periodicidade mínima anual."
        ),
    },
    {
        "article": "Art. 5º",
        "title": "Plano de resposta a incidentes",
        "description": (
            "Manutenção de plano documentado de resposta e recuperação de incidentes "
            "cibernéticos, com papéis e responsabilidades definidos."
        ),
    },
    {
        "article": "Art. 7º",
        "title": "Relatório ao BCB",
        "description": (
            "Comunicação ao Banco Central do Brasil de incidentes relevantes "
            "e dos resultados dos testes de segurança realizados."
        ),
    },
    {
        "article": "Art. 16",
        "title": "Continuidade de negócios",
        "description": (
            "Garantia de continuidade operacional e recuperação de serviços essenciais "
            "em cenários de incidentes cibernéticos graves."
        ),
    },
]

# ---------------------------------------------------------------------------
# Shared style builder
# ---------------------------------------------------------------------------

def _build_styles() -> dict:
    base = getSampleStyleSheet()

    styles = {
        "Normal": base["Normal"],
        "h1": ParagraphStyle(
            "PIA_H1",
            parent=base["Normal"],
            fontSize=18,
            fontName="Helvetica-Bold",
            textColor=WHITE,
            spaceAfter=4,
            alignment=TA_CENTER,
        ),
        "h2": ParagraphStyle(
            "PIA_H2",
            parent=base["Normal"],
            fontSize=10,
            fontName="Helvetica",
            textColor=colors.HexColor("#bdc3c7"),
            spaceAfter=2,
            alignment=TA_CENTER,
        ),
        "section": ParagraphStyle(
            "PIA_Section",
            parent=base["Normal"],
            fontSize=11,
            fontName="Helvetica-Bold",
            textColor=WHITE,
            backColor=GRAY_DARK,
            spaceBefore=10,
            spaceAfter=6,
            leftIndent=6,
            rightIndent=6,
            leading=18,
        ),
        "body": ParagraphStyle(
            "PIA_Body",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            textColor=GRAY_DARK,
            spaceAfter=4,
            leading=13,
        ),
        "body_justify": ParagraphStyle(
            "PIA_BodyJ",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            textColor=GRAY_DARK,
            spaceAfter=4,
            leading=13,
            alignment=TA_JUSTIFY,
        ),
        "bullet": ParagraphStyle(
            "PIA_Bullet",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            textColor=GRAY_DARK,
            spaceAfter=3,
            leftIndent=14,
            bulletIndent=4,
            leading=13,
        ),
        "small": ParagraphStyle(
            "PIA_Small",
            parent=base["Normal"],
            fontSize=7,
            fontName="Helvetica",
            textColor=GRAY_MED,
            alignment=TA_CENTER,
        ),
        "footer": ParagraphStyle(
            "PIA_Footer",
            parent=base["Normal"],
            fontSize=7,
            fontName="Helvetica",
            textColor=GRAY_MED,
            alignment=TA_CENTER,
        ),
        "badge_red": ParagraphStyle(
            "PIA_BadgeRed",
            parent=base["Normal"],
            fontSize=10,
            fontName="Helvetica-Bold",
            textColor=WHITE,
            backColor=ACCENT_RED,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "badge_amber": ParagraphStyle(
            "PIA_BadgeAmber",
            parent=base["Normal"],
            fontSize=10,
            fontName="Helvetica-Bold",
            textColor=WHITE,
            backColor=GOLD,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "badge_green": ParagraphStyle(
            "PIA_BadgeGreen",
            parent=base["Normal"],
            fontSize=10,
            fontName="Helvetica-Bold",
            textColor=WHITE,
            backColor=GREEN_OK,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "label": ParagraphStyle(
            "PIA_Label",
            parent=base["Normal"],
            fontSize=8,
            fontName="Helvetica-Bold",
            textColor=GRAY_DARK,
        ),
        "value": ParagraphStyle(
            "PIA_Value",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            textColor=GRAY_DARK,
        ),
        "checkbox": ParagraphStyle(
            "PIA_Checkbox",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            textColor=GRAY_DARK,
            leading=14,
        ),
    }
    return styles


# ---------------------------------------------------------------------------
# Header banner flowable
# ---------------------------------------------------------------------------

class _HeaderBanner(Flowable):
    """Dark banner with title and subtitle for the top of each PDF type."""

    def __init__(self, title: str, subtitle: str, width: float, height: float = 2.5 * cm):
        super().__init__()
        self.title = title
        self.subtitle = subtitle
        self.banner_width = width
        self.banner_height = height

    def wrap(self, available_width, available_height):
        return self.banner_width, self.banner_height

    def draw(self):
        c = self.canv
        w, h = self.banner_width, self.banner_height

        # Background
        c.setFillColor(DARK_BG)
        c.rect(0, 0, w, h, fill=1, stroke=0)

        # Red accent bar on left
        c.setFillColor(ACCENT_RED)
        c.rect(0, 0, 6, h, fill=1, stroke=0)

        # Title
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(16, h - 24, self.title)

        # Subtitle
        c.setFillColor(colors.HexColor("#bdc3c7"))
        c.setFont("Helvetica", 9)
        c.drawString(16, 10, self.subtitle)

        # Red line at bottom
        c.setStrokeColor(ACCENT_RED)
        c.setLineWidth(1.5)
        c.line(0, 0, w, 0)


# ---------------------------------------------------------------------------
# Page numbering
# ---------------------------------------------------------------------------

def _page_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(GRAY_MED)
    width, _ = A4
    footer_text = "Gerado automaticamente pelo PenteIA v4.0  |  Confidencial"
    canvas.drawCentredString(width / 2, 1.0 * cm, footer_text)
    canvas.drawRightString(width - 2 * cm, 1.0 * cm, f"Página {doc.page}")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Table style helpers
# ---------------------------------------------------------------------------

def _std_table_style(header_bg=GRAY_DARK, header_fg=WHITE) -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), header_fg),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TEXTCOLOR", (0, 1), (-1, -1), GRAY_DARK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, GRAY_LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c0c0c0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("WORDWRAP", (0, 0), (-1, -1), True),
    ])


def _ident_table_style() -> TableStyle:
    """Two-column label/value table."""
    return TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("TEXTCOLOR", (0, 0), (0, -1), GRAY_DARK),
        ("TEXTCOLOR", (1, 0), (1, -1), GRAY_DARK),
        ("BACKGROUND", (0, 0), (0, -1), GRAY_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c0c0c0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ])


# ---------------------------------------------------------------------------
# Section title helper
# ---------------------------------------------------------------------------

def _section(text: str, styles: dict) -> Paragraph:
    return Paragraph(f"  {text}", styles["section"])


# ---------------------------------------------------------------------------
# 1. BACEN 4.893 Evidence PDF
# ---------------------------------------------------------------------------

def generate_bacen_pdf(simulation_data: dict, output_path: str = None) -> bytes:
    """
    Generate a BACEN Resolution 4.893/2021 evidence PDF from a BAS simulation result.

    Parameters
    ----------
    simulation_data : dict
        Keys: target, date, score, techniques, compliance
    output_path : str, optional
        If provided, the PDF is also written to this path.

    Returns
    -------
    bytes
        Raw PDF bytes.
    """
    buf = io.BytesIO()
    PAGE_W, PAGE_H = A4
    MARGIN = 2 * cm

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=2 * cm,
        title="Relatório BACEN 4.893/2021",
        author="PenteIA v4.0",
    )

    styles = _build_styles()
    content_width = PAGE_W - 2 * MARGIN
    story = []

    # ---- Header banner ----
    story.append(
        _HeaderBanner(
            title="RELATÓRIO DE CONFORMIDADE",
            subtitle="Resolução BCB n.º 4.893/2021  |  Evidência de Testes de Segurança Cibernética — Art. 4º",
            width=content_width,
            height=2.6 * cm,
        )
    )
    story.append(Spacer(1, 0.3 * cm))

    # ---- Extract data ----
    target = simulation_data.get("target", "N/A")
    raw_date = simulation_data.get("date", _now_utc().isoformat())
    try:
        parsed_date = datetime.fromisoformat(raw_date)
        fmt_date = parsed_date.strftime("%d/%m/%Y %H:%M UTC")
    except Exception:
        fmt_date = raw_date

    score = float(simulation_data.get("score", 0.0))
    techniques: list[dict] = simulation_data.get("techniques", [])
    compliance_info: dict = simulation_data.get("compliance", {})
    bacen_info: dict = compliance_info.get("bacen", {})
    risk_level: str = bacen_info.get("risk_level", "Desconhecido")
    violations: list[dict] = bacen_info.get("violations", [])

    # ---- Section 1: IDENTIFICAÇÃO DO TESTE ----
    story.append(_section("1. IDENTIFICAÇÃO DO TESTE", styles))
    story.append(Spacer(1, 0.2 * cm))

    ident_data = [
        ["Campo", "Valor"],
        ["Data do Teste", fmt_date],
        ["Alvo (Target)", target],
        ["Score de Risco", f"{score:.1f} / 10.0"],
        ["Responsável Técnico", "PenteIA v4.0 — Plataforma BAS Automatizada"],
        ["Framework de Referência", "MITRE ATT&CK Enterprise v14 + BACEN 4.893/2021"],
        ["Classificação", "CONFIDENCIAL — Uso interno e regulatório"],
    ]

    t_ident = Table(ident_data, colWidths=[5 * cm, content_width - 5 * cm])
    t_ident.setStyle(_ident_table_style())
    story.append(t_ident)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 2: RESUMO EXECUTIVO ----
    story.append(_section("2. RESUMO EXECUTIVO", styles))
    story.append(Spacer(1, 0.2 * cm))

    total = len(techniques)
    found = sum(1 for t in techniques if t.get("status") == "found")
    blocked = sum(1 for t in techniques if t.get("status") == "blocked")
    safe = total - found - blocked

    gap_pct = round((found / total * 100) if total > 0 else 0.0, 1)

    # Risk badge
    rl_key = risk_level.lower()
    badge_style = _RISK_COLOR.get(rl_key, GRAY_MED)
    badge_text = f"NÍVEL DE RISCO: {risk_level.upper()}"

    badge_data = [
        [Paragraph(badge_text, ParagraphStyle(
            "badge_dyn",
            parent=styles["body"],
            fontSize=11,
            fontName="Helvetica-Bold",
            textColor=WHITE,
            alignment=TA_CENTER,
        ))]
    ]
    t_badge = Table(badge_data, colWidths=[content_width])
    t_badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), badge_style),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 1, GRAY_DARK),
    ]))
    story.append(t_badge)
    story.append(Spacer(1, 0.3 * cm))

    exec_summary_data = [
        ["Métrica", "Valor"],
        ["Técnicas Testadas", str(total)],
        ["Técnicas Detectadas / Bloqueadas", str(blocked)],
        ["Técnicas NÃO Detectadas (Gap)", str(found)],
        ["Gap de Detecção", f"{gap_pct}%"],
        ["Técnicas sem impacto", str(safe)],
        ["Score de Risco Calculado", f"{score:.1f} / 10.0"],
    ]

    t_exec = Table(exec_summary_data, colWidths=[8 * cm, content_width - 8 * cm])
    t_exec.setStyle(_ident_table_style())
    story.append(t_exec)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 3: MAPEAMENTO BACEN 4.893 ----
    story.append(_section("3. MAPEAMENTO BACEN 4.893 — Art. 4º §2", styles))
    story.append(Spacer(1, 0.2 * cm))

    story.append(Paragraph(
        "A tabela abaixo mapeia os requisitos da Resolução BCB n.º 4.893/2021 "
        "para os resultados deste teste de segurança cibernética.",
        styles["body_justify"],
    ))
    story.append(Spacer(1, 0.2 * cm))

    violated_articles = {v.get("article", "") for v in violations}

    bacen_table_data = [["Artigo", "Requisito", "Status"]]
    col_w = [2.5 * cm, content_width - 5.5 * cm, 3 * cm]

    for art in _BACEN_ARTICLES:
        art_id = art["article"]
        status_str = "NÃO CONFORME" if art_id in violated_articles else "CONFORME"
        status_color = ACCENT_RED if art_id in violated_articles else GREEN_OK

        bacen_table_data.append([
            Paragraph(art_id, ParagraphStyle(
                "art_id", parent=styles["body"], fontName="Helvetica-Bold", fontSize=8,
            )),
            Paragraph(
                f"<b>{art['title']}</b><br/>"
                f"<font size='7' color='#7f8c8d'>{art['description']}</font>",
                styles["body"],
            ),
            Paragraph(status_str, ParagraphStyle(
                "status_cell",
                parent=styles["body"],
                fontSize=8,
                fontName="Helvetica-Bold",
                textColor=status_color,
                alignment=TA_CENTER,
            )),
        ])

    t_bacen = Table(bacen_table_data, colWidths=col_w)
    ts = _std_table_style(header_bg=ACCENT_RED)
    ts.add("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, GRAY_LIGHT])
    t_bacen.setStyle(ts)
    story.append(t_bacen)

    # If violations exist, list custom descriptions
    if violations:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "<b>Violações Identificadas pelo Controlador de Risco:</b>",
            styles["body"],
        ))
        for v in violations:
            story.append(Paragraph(
                f"<b>{v.get('article', '')}</b> — {v.get('title', '')}: "
                f"{v.get('description', '')}",
                styles["bullet"],
            ))

    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 4: TÉCNICAS ENCONTRADAS ----
    story.append(_section("4. TÉCNICAS ENCONTRADAS (Gap de Detecção)", styles))
    story.append(Spacer(1, 0.2 * cm))

    found_techniques = [t for t in techniques if t.get("status") == "found"]

    if not found_techniques:
        story.append(Paragraph(
            "Nenhuma técnica com gap de detecção identificada nesta simulação.",
            styles["body"],
        ))
    else:
        tech_data = [["ID MITRE", "Nome", "Tática", "Severidade", "CVSS Est."]]
        col_w_tech = [2.2 * cm, 5 * cm, 3.5 * cm, 2.5 * cm, content_width - 13.2 * cm]

        for tech in found_techniques:
            tid = tech.get("id", "—")
            tname = tech.get("name", "—")
            tactic = tech.get("tactic", "—")
            severity = tech.get("severity", "info")
            cvss = _SEVERITY_CVSS.get(severity.lower(), "N/A")

            sev_color = _RISK_COLOR.get(severity.lower(), GRAY_MED)
            tech_data.append([
                Paragraph(tid, styles["body"]),
                Paragraph(tname, styles["body"]),
                Paragraph(tactic, styles["body"]),
                Paragraph(
                    severity.upper(),
                    ParagraphStyle(
                        "sev_cell",
                        parent=styles["body"],
                        fontSize=7,
                        fontName="Helvetica-Bold",
                        textColor=sev_color,
                    ),
                ),
                Paragraph(cvss, styles["body"]),
            ])

        t_tech = Table(tech_data, colWidths=col_w_tech)
        t_tech.setStyle(_std_table_style(header_bg=ACCENT_RED))
        story.append(t_tech)

    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 5: RECOMENDAÇÕES ----
    story.append(_section("5. RECOMENDAÇÕES", styles))
    story.append(Spacer(1, 0.2 * cm))

    recommendations = _build_bacen_recommendations(found_techniques, risk_level, gap_pct)
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", styles["bullet"]))

    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width=content_width, thickness=0.5, color=GRAY_MED))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        "Este relatório foi gerado automaticamente pela plataforma PenteIA v4.0 "
        "como evidência de conformidade com a Resolução BCB n.º 4.893/2021. "
        "A reprodução ou distribuição não autorizada é proibida.",
        styles["small"],
    ))

    # Build PDF
    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    pdf_bytes = buf.getvalue()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes


def _build_bacen_recommendations(found_techniques: list, risk_level: str, gap_pct: float) -> list[str]:
    """Derive top remediation recommendations from simulation findings."""
    recs = []

    if gap_pct > 50:
        recs.append(
            "Implementar ou revisar urgentemente a solução SIEM/EDR, pois mais da metade "
            "das técnicas testadas não foram detectadas."
        )
    elif gap_pct > 20:
        recs.append(
            "Revisar regras de detecção no SIEM e correlacionar eventos com o framework "
            "MITRE ATT&CK para cobrir os gaps identificados."
        )

    tactics_found = {t.get("tactic", "").lower() for t in found_techniques}

    if "initial-access" in tactics_found or "initial access" in tactics_found:
        recs.append(
            "Fortalecer controles de acesso no perímetro: MFA obrigatório, revisão de "
            "regras de firewall e segmentação de rede."
        )
    if "credential-access" in tactics_found or "credential access" in tactics_found:
        recs.append(
            "Implementar gestão de senhas privilegiadas (PAM) e monitoramento de credenciais "
            "comprometidas com alertas em tempo real."
        )
    if "lateral-movement" in tactics_found or "lateral movement" in tactics_found:
        recs.append(
            "Aplicar princípio de menor privilégio e micro-segmentação para limitar "
            "movimentação lateral entre sistemas."
        )
    if "exfiltration" in tactics_found:
        recs.append(
            "Implementar DLP (Data Loss Prevention) e monitoramento de tráfego de saída "
            "para detectar exfiltração de dados."
        )
    if "persistence" in tactics_found:
        recs.append(
            "Revisar mecanismos de inicialização e tarefas agendadas; implementar "
            "integridade de arquivos críticos (FIM)."
        )
    if "defense-evasion" in tactics_found or "defense evasion" in tactics_found:
        recs.append(
            "Atualizar assinaturas de antivírus/EDR e habilitar detecção comportamental "
            "para identificar evasão de controles."
        )

    recs.append(
        "Executar novo ciclo de testes de penetração em até 90 dias para validar "
        "a eficácia das correções implementadas."
    )
    recs.append(
        "Elaborar Relatório de Conformidade Anual conforme Art. 7º da Resolução "
        "BCB n.º 4.893/2021 e encaminhar ao Banco Central do Brasil."
    )
    recs.append(
        "Revisar e atualizar o Plano de Resposta a Incidentes (Art. 5º) com base "
        "nos cenários de ataque identificados nesta simulação."
    )

    return recs if recs else [
        "Manter os programas de testes periódicos conforme exigido pelo Art. 4º §2.",
        "Documentar todos os resultados e encaminhar relatório ao BCB (Art. 7º).",
    ]


# ---------------------------------------------------------------------------
# 2. ANPD Notification PDF
# ---------------------------------------------------------------------------

def generate_anpd_notification(incident_data: dict, output_path: str = None) -> bytes:
    """
    Generate an ANPD incident notification PDF based on Resolution 15/2024.

    Parameters
    ----------
    incident_data : dict
        Incident and controller metadata (see module docstring).
    output_path : str, optional
        If provided, the PDF is also written to this path.

    Returns
    -------
    bytes
        Raw PDF bytes.
    """
    buf = io.BytesIO()
    PAGE_W, PAGE_H = A4
    MARGIN = 2 * cm

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=2 * cm,
        title="Comunicação de Incidente ANPD",
        author="PenteIA v4.0",
    )

    styles = _build_styles()
    content_width = PAGE_W - 2 * MARGIN
    story = []

    # ---- Header banner ----
    story.append(
        _HeaderBanner(
            title="COMUNICAÇÃO DE INCIDENTE DE SEGURANÇA",
            subtitle="Autoridade Nacional de Proteção de Dados — Resolução CD/ANPD n.º 15/2024  |  LGPD Art. 48",
            width=content_width,
            height=2.6 * cm,
        )
    )
    story.append(Spacer(1, 0.4 * cm))

    # Deadline banner
    deadline_data = [[
        Paragraph(
            "PRAZO LEGAL: 72 HORAS ÚTEIS A PARTIR DO CONHECIMENTO DO INCIDENTE",
            ParagraphStyle(
                "deadline",
                parent=styles["body"],
                fontSize=9,
                fontName="Helvetica-Bold",
                textColor=WHITE,
                alignment=TA_CENTER,
            ),
        )
    ]]
    t_deadline = Table(deadline_data, colWidths=[content_width])
    t_deadline.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ACCENT_RED),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 1, GRAY_DARK),
    ]))
    story.append(t_deadline)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 1: IDENTIFICAÇÃO DO CONTROLADOR ----
    story.append(_section("1. IDENTIFICAÇÃO DO CONTROLADOR", styles))
    story.append(Spacer(1, 0.2 * cm))

    ctrl_name = incident_data.get("controller_name", "N/A")
    ctrl_cnpj = incident_data.get("controller_cnpj", "N/A")
    dpo_name = incident_data.get("dpo_name", "N/A")
    dpo_email = incident_data.get("dpo_email", "N/A")

    ctrl_data = [
        ["Campo", "Informação"],
        ["Razão Social / Nome do Controlador", ctrl_name],
        ["CNPJ / CPF do Controlador", ctrl_cnpj],
        ["Setor de Atividade", incident_data.get("sector", "Serviços Financeiros / Tecnologia")],
        ["Nome do Encarregado (DPO)", dpo_name],
        ["E-mail do Encarregado (DPO)", dpo_email],
        ["Telefone de Contato", incident_data.get("dpo_phone", "N/A")],
    ]

    t_ctrl = Table(ctrl_data, colWidths=[6.5 * cm, content_width - 6.5 * cm])
    t_ctrl.setStyle(_ident_table_style())
    story.append(t_ctrl)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 2: DADOS DO INCIDENTE ----
    story.append(_section("2. DADOS DO INCIDENTE", styles))
    story.append(Spacer(1, 0.2 * cm))

    def _fmt_date(d: str) -> str:
        if not d:
            return "N/A"
        try:
            return datetime.fromisoformat(d).strftime("%d/%m/%Y %H:%M")
        except Exception:
            return d

    inc_data = [
        ["Campo", "Data / Informação"],
        ["Data e Hora do Incidente", _fmt_date(incident_data.get("incident_date", ""))],
        ["Data e Hora da Detecção", _fmt_date(incident_data.get("detection_date", ""))],
        ["Data e Hora da Notificação (este documento)", _fmt_date(incident_data.get("notification_date", ""))],
        ["Número estimado de titulares afetados", str(incident_data.get("estimated_holders", "Desconhecido"))],
    ]

    t_inc = Table(inc_data, colWidths=[8 * cm, content_width - 8 * cm])
    t_inc.setStyle(_ident_table_style())
    story.append(t_inc)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 3: CATEGORIAS DE DADOS ----
    story.append(_section("3. CATEGORIAS DE DADOS AFETADOS", styles))
    story.append(Spacer(1, 0.2 * cm))

    data_categories = incident_data.get("data_categories", [])
    _all_categories = [
        ("dados_pessoais_comuns", "Dados Pessoais Comuns (nome, endereço, e-mail, telefone)"),
        ("dados_sensiveis", "Dados Pessoais Sensíveis (saúde, biometria, raça/etnia, religião, etc.)"),
        ("dados_financeiros", "Dados Financeiros (conta bancária, cartão de crédito, transações)"),
        ("dados_criancas", "Dados de Crianças e Adolescentes"),
        ("dados_funcionarios", "Dados de Funcionários / Colaboradores"),
        ("credenciais", "Credenciais de Acesso (senhas, tokens, chaves)"),
        ("outros", "Outros"),
    ]

    _lower_cats = [c.lower() for c in data_categories]

    cat_rows = []
    for cat_key, cat_label in _all_categories:
        is_checked = any(
            cat_key in c.lower() or c.lower() in cat_key or c.lower() in cat_label.lower()
            for c in data_categories
        )
        mark = "[X]" if is_checked else "[  ]"
        cat_rows.append([
            Paragraph(mark, ParagraphStyle(
                "mark", parent=styles["body"], fontName="Helvetica-Bold",
                textColor=ACCENT_RED if is_checked else GRAY_MED,
                fontSize=9,
            )),
            Paragraph(cat_label, styles["body"]),
        ])

    t_cats = Table(cat_rows, colWidths=[1.2 * cm, content_width - 1.2 * cm])
    t_cats.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, GRAY_LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c0c0c0")),
    ]))
    story.append(t_cats)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 4: DESCRIÇÃO DO INCIDENTE ----
    story.append(_section("4. DESCRIÇÃO DO INCIDENTE", styles))
    story.append(Spacer(1, 0.2 * cm))

    description = incident_data.get("incident_description", "Sem descrição fornecida.")
    story.append(Paragraph(description, styles["body_justify"]))
    story.append(Spacer(1, 0.2 * cm))

    affected_systems = incident_data.get("affected_systems", [])
    if affected_systems:
        story.append(Paragraph("<b>Sistemas Afetados:</b>", styles["body"]))
        for sys_item in affected_systems:
            story.append(Paragraph(f"• {sys_item}", styles["bullet"]))
        story.append(Spacer(1, 0.2 * cm))

    story.append(Spacer(1, 0.2 * cm))

    # ---- Section 5: MEDIDAS ADOTADAS ----
    story.append(_section("5. MEDIDAS ADOTADAS", styles))
    story.append(Spacer(1, 0.2 * cm))

    measures = incident_data.get("measures_taken", [])
    if measures:
        for measure in measures:
            story.append(Paragraph(f"• {measure}", styles["bullet"]))
    else:
        story.append(Paragraph(
            "Medidas de contenção e remediação em andamento. Detalhes a serem informados "
            "em comunicação suplementar.",
            styles["body"],
        ))

    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 6: COMUNICAÇÃO AOS TITULARES ----
    story.append(_section("6. COMUNICAÇÃO AOS TITULARES", styles))
    story.append(Spacer(1, 0.2 * cm))

    comm_to_holders: bool = incident_data.get("communication_to_holders", False)
    comm_reason: str = incident_data.get("communication_reason", "")

    comm_status = "[X] SIM" if comm_to_holders else "[  ] SIM"
    no_status = "[  ] NÃO" if comm_to_holders else "[X] NÃO"

    comm_data = [
        [
            Paragraph(comm_status, ParagraphStyle(
                "comm_yes",
                parent=styles["body"],
                fontSize=10,
                fontName="Helvetica-Bold",
                textColor=GREEN_OK if comm_to_holders else GRAY_MED,
            )),
            Paragraph(no_status, ParagraphStyle(
                "comm_no",
                parent=styles["body"],
                fontSize=10,
                fontName="Helvetica-Bold",
                textColor=ACCENT_RED if not comm_to_holders else GRAY_MED,
            )),
            Paragraph(
                comm_reason if comm_reason else (
                    "Os titulares foram notificados pelos canais oficiais da organização."
                    if comm_to_holders
                    else "Avaliação de risco em andamento; comunicação será realizada se confirmada necessidade."
                ),
                styles["body"],
            ),
        ]
    ]
    t_comm = Table(comm_data, colWidths=[2 * cm, 2 * cm, content_width - 4 * cm])
    t_comm.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c0c0c0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 0), (-1, -1), GRAY_LIGHT),
    ]))
    story.append(t_comm)
    story.append(Spacer(1, 0.5 * cm))

    # ---- Signature line ----
    story.append(HRFlowable(width=content_width, thickness=0.5, color=GRAY_MED))
    story.append(Spacer(1, 0.3 * cm))

    today_str = _now_utc().strftime("%d/%m/%Y")
    sig_data = [
        [
            Paragraph(
                "_" * 40 + "<br/>Assinatura do Encarregado (DPO)<br/>"
                f"<font size='8' color='#7f8c8d'>{dpo_name}</font>",
                ParagraphStyle("sig_l", parent=styles["body"], alignment=TA_CENTER),
            ),
            Paragraph(
                "_" * 40 + f"<br/>Data: {today_str}<br/>"
                "<font size='8' color='#7f8c8d'>Local: ________________</font>",
                ParagraphStyle("sig_r", parent=styles["body"], alignment=TA_CENTER),
            ),
        ]
    ]
    t_sig = Table(sig_data, colWidths=[content_width / 2, content_width / 2])
    t_sig.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_sig)
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "Prazo ANPD: 72 horas úteis a partir do conhecimento do incidente  |  "
        "Resolução CD/ANPD n.º 15/2024  |  LGPD Art. 48<br/>"
        "Gerado automaticamente pelo PenteIA v4.0  |  Confidencial",
        styles["footer"],
    ))

    # Build PDF
    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    pdf_bytes = buf.getvalue()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes


# ---------------------------------------------------------------------------
# Helper: build ANPD incident_data from BAS simulation
# ---------------------------------------------------------------------------

def build_anpd_from_simulation(simulation_data: dict, controller_info: dict) -> dict:
    """
    Build an ``incident_data`` dict suitable for ``generate_anpd_notification``
    from a BAS simulation result and controller metadata.

    Parameters
    ----------
    simulation_data : dict
        Standard PenteIA simulation output (same shape as ``generate_bacen_pdf``).
    controller_info : dict
        Minimum keys: controller_name, controller_cnpj, dpo_name, dpo_email.
        Optional: dpo_phone, sector, communication_to_holders, communication_reason.

    Returns
    -------
    dict
        Ready-to-use ``incident_data`` for ``generate_anpd_notification``.
    """
    now_iso = _now_utc().isoformat()
    techniques: list[dict] = simulation_data.get("techniques", [])
    found = [t for t in techniques if t.get("status") == "found"]

    # Infer data categories from tactics observed
    cats = []
    tactic_set = {t.get("tactic", "").lower() for t in found}
    if any("credential" in t for t in tactic_set):
        cats.append("credenciais")
    if any("exfil" in t for t in tactic_set):
        cats.append("dados_pessoais_comuns")
        cats.append("dados_financeiros")
    if any("collection" in t for t in tactic_set):
        cats.append("dados_pessoais_comuns")
    if not cats:
        cats = ["dados_pessoais_comuns"]

    # Affected systems = target
    target = simulation_data.get("target", "Sistema não especificado")
    affected_systems = [target] if target else ["Sistema não especificado"]

    # Build description
    score = simulation_data.get("score", 0.0)
    gap_count = len(found)
    techniques_list = "; ".join(
        f"{t.get('id', '?')} ({t.get('name', '?')})" for t in found[:5]
    )
    description = (
        f"Simulação adversarial automatizada (BAS — Breach and Attack Simulation) "
        f"identificou {gap_count} técnica(s) com gap de detecção no ambiente '{target}'. "
        f"Score de risco calculado: {score:.1f}/10.0. "
    )
    if techniques_list:
        description += f"Técnicas não detectadas incluem: {techniques_list}. "
    description += (
        "A ausência de detecção das técnicas listadas indica potencial exposição dos dados "
        "tratados pela organização a atores maliciosos, caracterizando incidente de segurança "
        "com risco de violação de dados pessoais conforme LGPD Art. 46."
    )

    # Default measures
    measures = [
        "Isolamento imediato dos sistemas afetados para contenção do incidente.",
        "Acionamento da equipe de resposta a incidentes (CSIRT/SOC).",
        "Coleta de logs e evidências forenses para análise posterior.",
        "Notificação às áreas jurídica e de compliance da organização.",
        "Revisão dos controles de segurança e regras de detecção SIEM/EDR.",
        "Monitoramento intensificado do ambiente nas próximas 72 horas.",
    ]

    incident_data = {
        "controller_name": controller_info.get("controller_name", "N/A"),
        "controller_cnpj": controller_info.get("controller_cnpj", "N/A"),
        "dpo_name": controller_info.get("dpo_name", "N/A"),
        "dpo_email": controller_info.get("dpo_email", "N/A"),
        "dpo_phone": controller_info.get("dpo_phone", "N/A"),
        "sector": controller_info.get("sector", "Serviços Financeiros / Tecnologia"),
        "incident_date": simulation_data.get("date", now_iso),
        "detection_date": now_iso,
        "notification_date": now_iso,
        "incident_description": description,
        "data_categories": cats,
        "estimated_holders": controller_info.get("estimated_holders", 0),
        "affected_systems": affected_systems,
        "measures_taken": measures,
        "communication_to_holders": controller_info.get("communication_to_holders", False),
        "communication_reason": controller_info.get("communication_reason", ""),
    }

    return incident_data


# ---------------------------------------------------------------------------
# CLI quick-test (python bacen_pdf_engine.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    _sample_simulation = {
        "target": "api.banco-exemplo.com.br",
        "date": "2026-06-15T10:30:00",
        "score": 7.4,
        "techniques": [
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "status": "found", "severity": "high"},
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "status": "found", "severity": "medium"},
            {"id": "T1059", "name": "Command Scripting", "tactic": "Execution", "status": "blocked", "severity": "high"},
            {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "status": "found", "severity": "critical"},
            {"id": "T1041", "name": "Exfiltration Over C2", "tactic": "Exfiltration", "status": "found", "severity": "critical"},
            {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion", "status": "blocked", "severity": "high"},
        ],
        "compliance": {
            "bacen": {
                "risk_level": "Alto",
                "violations": [
                    {
                        "article": "Art. 4 §2",
                        "title": "Testes anuais de segurança",
                        "description": "Gap de detecção superior a 30% evidencia controles insuficientes.",
                    },
                    {
                        "article": "Art. 5º",
                        "title": "Plano de resposta a incidentes",
                        "description": "Técnicas de movimentação lateral e exfiltração não foram detectadas.",
                    },
                ],
            }
        },
    }

    _sample_controller = {
        "controller_name": "Banco Exemplo S.A.",
        "controller_cnpj": "00.000.000/0001-99",
        "dpo_name": "Maria da Silva",
        "dpo_email": "dpo@banco-exemplo.com.br",
        "dpo_phone": "+55 11 9999-0000",
        "sector": "Instituição Financeira",
        "estimated_holders": 50000,
        "communication_to_holders": False,
        "communication_reason": "Avaliação de risco em andamento.",
    }

    print("Generating BACEN PDF...")
    bacen_bytes = generate_bacen_pdf(_sample_simulation, "test_bacen_4893.pdf")
    print(f"  -> {len(bacen_bytes):,} bytes written to test_bacen_4893.pdf")

    print("Building ANPD incident data from simulation...")
    anpd_data = build_anpd_from_simulation(_sample_simulation, _sample_controller)
    print(json.dumps(anpd_data, ensure_ascii=False, indent=2))

    print("Generating ANPD notification PDF...")
    anpd_bytes = generate_anpd_notification(anpd_data, "test_anpd_notification.pdf")
    print(f"  -> {len(anpd_bytes):,} bytes written to test_anpd_notification.pdf")

    print("Done.")
