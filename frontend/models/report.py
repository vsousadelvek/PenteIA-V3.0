from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum


class ReportType(str, Enum):
    PENETRATION_TEST = "penetration_test"
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_FINDINGS = "technical_findings"
    REMEDIATION_ROADMAP = "remediation_roadmap"


class ReportFormat(str, Enum):
    PDF = "pdf"
    DOCX = "docx"
    HTML = "html"
    JSON = "json"


class ReportBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    type: ReportType
    format: ReportFormat
    content: Optional[dict] = None


class ReportCreate(ReportBase):
    pass


class ReportUpdate(BaseModel):
    title: Optional[str] = None
    format: Optional[ReportFormat] = None


class ReportResponse(ReportBase):
    id: str
    user_id: str
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    id: str
    title: str
    type: ReportType
    format: ReportFormat
    created_at: datetime
    user_id: str


class ReportDetailResponse(ReportResponse):
    pass


class ReportDownloadResponse(BaseModel):
    filename: str
    content_type: str
    size: int


class TemplateResponse(BaseModel):
    name: str
    type: ReportType
    description: str
    fields: List[str]


class ReportGenerateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    type: ReportType
    format: ReportFormat
    data: Optional[dict] = Field(default_factory=dict)
