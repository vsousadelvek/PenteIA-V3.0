from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import Optional, List

from db.database import get_db
from models.report import (
    ReportType,
    ReportFormat,
    ReportResponse,
    ReportListResponse,
    ReportDetailResponse,
    ReportDownloadResponse,
    TemplateResponse,
    ReportGenerateRequest,
)
from services.report_service import ReportService
from templates.report_templates import REPORT_TEMPLATES
from auth.dependencies import get_current_user
from core.schemas import UserResponse

router = APIRouter(prefix="/api/reporting", tags=["reporting"])


@router.post("/generate", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    request: ReportGenerateRequest,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ReportResponse:
    """
    Generate a new report.

    - **title**: Report title
    - **type**: Report type (penetration_test, executive_summary, technical_findings, remediation_roadmap)
    - **format**: Output format (pdf, docx, html, json)
    - **data**: Optional data dict to customize report content
    """
    try:
        report = ReportService.create_report(
            db=db,
            user_id=current_user.id,
            title=request.title,
            report_type=request.type,
            format=request.format,
            data=request.data,
        )
        return ReportResponse.from_attributes(report)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.get("/reports", response_model=dict)
async def list_reports(
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    report_type: Optional[ReportType] = Query(None),
) -> dict:
    """
    List all reports for the current user with pagination.

    - **skip**: Number of records to skip (default: 0)
    - **limit**: Number of records to return (default: 20, max: 100)
    - **report_type**: Filter by report type (optional)
    """
    try:
        reports, total = ReportService.get_user_reports(
            db=db,
            user_id=current_user.id,
            skip=skip,
            limit=limit,
            report_type=report_type,
        )

        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "items": [
                ReportListResponse(
                    id=r.id,
                    title=r.title,
                    type=r.type,
                    format=r.format,
                    created_at=r.created_at,
                    user_id=r.user_id,
                )
                for r in reports
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to retrieve reports")


@router.get("/reports/{report_id}", response_model=ReportDetailResponse)
async def get_report(
    report_id: str,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ReportDetailResponse:
    """Get detailed information about a specific report."""
    report = ReportService.get_report(db, report_id, current_user.id)

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not found"
        )

    return ReportDetailResponse(
        id=report.id,
        user_id=report.user_id,
        title=report.title,
        type=report.type,
        format=report.format,
        content=report.content,
        created_at=report.created_at,
        updated_at=report.updated_at,
    )


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download report in its specified format."""
    try:
        file_content, content_type, filename = ReportService.get_report_file(
            db, report_id, current_user.id
        )

        return FileResponse(
            content=file_content,
            media_type=content_type,
            filename=filename,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(e)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to download report")


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: str,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Delete a report."""
    success = ReportService.delete_report(db, report_id, current_user.id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not found"
        )


@router.get("/templates", response_model=List[TemplateResponse])
async def list_templates() -> List[TemplateResponse]:
    """
    Get list of available report templates.

    Returns information about all available template types that can be used for report generation.
    """
    templates = []

    for template_key, template_data in REPORT_TEMPLATES.items():
        templates.append(
            TemplateResponse(
                name=template_data.get("title", ""),
                type=ReportType(template_key),
                description=template_data.get("description", ""),
                fields=template_data.get("fields", []),
            )
        )

    return templates


@router.get("/templates/{template_type}")
async def get_template(template_type: ReportType) -> dict:
    """Get detailed information about a specific template."""
    template = REPORT_TEMPLATES.get(template_type.value)

    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Template not found"
        )

    return {
        "type": template_type.value,
        "title": template.get("title", ""),
        "description": template.get("description", ""),
        "fields": template.get("fields", []),
        "defaults": template.get("defaults", {}),
        "sections": [
            {"name": s.get("name", ""), "description": s.get("template", "")[:100]}
            for s in template.get("sections", [])
        ],
    }
