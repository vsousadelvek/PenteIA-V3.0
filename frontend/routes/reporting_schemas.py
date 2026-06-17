"""
Additional Pydantic schemas for reporting endpoints.
These schemas provide response examples and additional validation.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum


class ReportTypeEnum(str, Enum):
    PENETRATION_TEST = "penetration_test"
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_FINDINGS = "technical_findings"
    REMEDIATION_ROADMAP = "remediation_roadmap"


class ReportFormatEnum(str, Enum):
    PDF = "pdf"
    DOCX = "docx"
    HTML = "html"
    JSON = "json"


class ReportSection(BaseModel):
    name: str
    content: str


class ReportContentSchema(BaseModel):
    title: str
    type: str
    format: str
    sections: List[ReportSection]
    generated_at: str


class PaginatedReportResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: List[Dict[str, Any]]


class ErrorResponse(BaseModel):
    detail: str
    status_code: int = 400


class ReportStats(BaseModel):
    total_reports: int
    by_type: Dict[str, int]
    by_format: Dict[str, int]
    by_date: Dict[str, int]
