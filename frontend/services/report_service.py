from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import desc
from db.models.report import Report
from models.report import ReportType, ReportFormat, ReportResponse, ReportListResponse
from templates.report_templates import REPORT_TEMPLATES
from utils.report_generators import (
    generate_pdf,
    generate_docx,
    generate_html,
    generate_json_report,
)


class ReportService:
    @staticmethod
    def create_report(
        db: Session,
        user_id: str,
        title: str,
        report_type: ReportType,
        format: ReportFormat,
        data: Optional[Dict[str, Any]] = None,
    ) -> Report:
        """Create a new report with generated content."""

        # Get template
        template = REPORT_TEMPLATES.get(report_type.value)
        if not template:
            raise ValueError(f"Template not found for type: {report_type.value}")

        # Merge data with template defaults
        report_data = {**template.get("defaults", {}), **(data or {})}

        # Generate content based on template and data
        content = ReportService._render_content(
            report_type, format, template, report_data
        )

        # Create report record
        report = Report(
            id=str(uuid.uuid4()),
            user_id=user_id,
            title=title,
            type=report_type,
            format=format,
            content=content,
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        return report

    @staticmethod
    def get_report(db: Session, report_id: str, user_id: str) -> Optional[Report]:
        """Get a report by ID."""
        return db.query(Report).filter(
            Report.id == report_id, Report.user_id == user_id
        ).first()

    @staticmethod
    def get_user_reports(
        db: Session,
        user_id: str,
        skip: int = 0,
        limit: int = 20,
        report_type: Optional[ReportType] = None,
    ) -> tuple[List[Report], int]:
        """Get all reports for a user with pagination."""
        query = db.query(Report).filter(Report.user_id == user_id)

        if report_type:
            query = query.filter(Report.type == report_type)

        total = query.count()
        reports = (
            query.order_by(desc(Report.created_at)).offset(skip).limit(limit).all()
        )

        return reports, total

    @staticmethod
    def delete_report(db: Session, report_id: str, user_id: str) -> bool:
        """Delete a report."""
        report = db.query(Report).filter(
            Report.id == report_id, Report.user_id == user_id
        ).first()

        if not report:
            return False

        db.delete(report)
        db.commit()
        return True

    @staticmethod
    def get_report_file(
        db: Session, report_id: str, user_id: str
    ) -> tuple[bytes, str, str]:
        """Get report file content and metadata for download."""
        report = ReportService.get_report(db, report_id, user_id)
        if not report:
            raise ValueError("Report not found")

        format = report.format.value

        if format == "pdf":
            file_content = generate_pdf(report.title, report.content or {})
            content_type = "application/pdf"
            filename = f"{report.title.replace(' ', '_')}.pdf"
        elif format == "docx":
            file_content = generate_docx(report.title, report.content or {})
            content_type = (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
            filename = f"{report.title.replace(' ', '_')}.docx"
        elif format == "html":
            file_content = generate_html(report.title, report.content or {}).encode(
                "utf-8"
            )
            content_type = "text/html"
            filename = f"{report.title.replace(' ', '_')}.html"
        elif format == "json":
            file_content = generate_json_report(report.title, report.content or {})
            content_type = "application/json"
            filename = f"{report.title.replace(' ', '_')}.json"
        else:
            raise ValueError(f"Unsupported format: {format}")

        return file_content, content_type, filename

    @staticmethod
    def _render_content(
        report_type: ReportType,
        format: ReportFormat,
        template: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Render report content using template."""
        from jinja2 import Template

        content = {
            "title": template.get("title", ""),
            "type": report_type.value,
            "format": format.value,
            "sections": [],
        }

        # Render each section from template
        for section in template.get("sections", []):
            section_name = section.get("name", "")
            section_template = section.get("template", "")

            try:
                jinja_template = Template(section_template)
                rendered_content = jinja_template.render(**data)
            except Exception:
                rendered_content = section_template

            content["sections"].append(
                {
                    "name": section_name,
                    "content": rendered_content,
                }
            )

        content["generated_at"] = datetime.utcnow().isoformat()
        return content
