"""
Unit tests for reporting endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from sqlalchemy.orm import Session

from models.report import ReportType, ReportFormat, ReportGenerateRequest
from services.report_service import ReportService
from db.models.report import Report


@pytest.fixture
def mock_db():
    """Create a mock database session."""
    db = Mock(spec=Session)
    return db


@pytest.fixture
def sample_report():
    """Create a sample report for testing."""
    return Report(
        id="test-report-1",
        user_id="user-1",
        title="Test Penetration Report",
        type=ReportType.PENETRATION_TEST,
        format=ReportFormat.PDF,
        content={
            "title": "Test Report",
            "sections": [
                {"name": "Executive Summary", "content": "Test content"}
            ],
            "generated_at": datetime.utcnow().isoformat(),
        },
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


class TestReportService:
    """Test ReportService methods."""

    def test_create_report(self, mock_db, sample_report):
        """Test creating a new report."""
        with patch.object(ReportService, "create_report") as mock_create:
            mock_create.return_value = sample_report

            result = ReportService.create_report(
                db=mock_db,
                user_id="user-1",
                title="Test Report",
                report_type=ReportType.PENETRATION_TEST,
                format=ReportFormat.PDF,
            )

            assert result.id == "test-report-1"
            assert result.title == "Test Penetration Report"
            assert result.type == ReportType.PENETRATION_TEST

    def test_get_report(self, mock_db, sample_report):
        """Test retrieving a report."""
        mock_db.query().filter().first.return_value = sample_report

        result = ReportService.get_report(mock_db, "test-report-1", "user-1")

        assert result is not None
        assert result.id == "test-report-1"

    def test_get_report_not_found(self, mock_db):
        """Test retrieving a non-existent report."""
        mock_db.query().filter().first.return_value = None

        result = ReportService.get_report(mock_db, "non-existent", "user-1")

        assert result is None

    def test_get_user_reports(self, mock_db, sample_report):
        """Test retrieving user reports with pagination."""
        mock_query = MagicMock()
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.count.return_value = 1
        mock_query.order_by.return_value = mock_query
        mock_query.offset.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.all.return_value = [sample_report]

        reports, total = ReportService.get_user_reports(
            mock_db, "user-1", skip=0, limit=20
        )

        assert total == 1
        assert len(reports) == 1
        assert reports[0].id == "test-report-1"

    def test_delete_report(self, mock_db):
        """Test deleting a report."""
        mock_report = Mock()
        mock_db.query().filter().first.return_value = mock_report

        result = ReportService.delete_report(mock_db, "test-report-1", "user-1")

        assert result is True
        mock_db.delete.assert_called_once_with(mock_report)
        mock_db.commit.assert_called_once()

    def test_delete_report_not_found(self, mock_db):
        """Test deleting a non-existent report."""
        mock_db.query().filter().first.return_value = None

        result = ReportService.delete_report(mock_db, "non-existent", "user-1")

        assert result is False

    def test_render_content_with_jinja_template(self):
        """Test rendering content with Jinja2 template."""
        template = {
            "sections": [
                {
                    "name": "Test Section",
                    "template": "Client: {{ client }}, Date: {{ test_date }}",
                }
            ]
        }
        data = {"client": "ACME Corp", "test_date": "2024-01-01"}

        result = ReportService._render_content(
            ReportType.PENETRATION_TEST,
            ReportFormat.HTML,
            template,
            data,
        )

        assert "ACME Corp" in str(result)
        assert "2024-01-01" in str(result)


class TestReportGenerators:
    """Test report generation in different formats."""

    def test_generate_html(self):
        """Test HTML report generation."""
        from utils.report_generators import generate_html

        content = {
            "title": "Test Report",
            "sections": [
                {"name": "Section 1", "content": "Content 1"},
                {"name": "Section 2", "content": "Content 2"},
            ],
        }

        result = generate_html("Test Report", content)

        assert "<!DOCTYPE html>" in result
        assert "Test Report" in result
        assert "Section 1" in result
        assert "Content 1" in result

    def test_generate_json_report(self):
        """Test JSON report generation."""
        from utils.report_generators import generate_json_report
        import json

        content = {
            "title": "Test Report",
            "sections": [{"name": "Section 1", "content": "Content 1"}],
        }

        result = generate_json_report("Test Report", content)
        parsed = json.loads(result.decode("utf-8"))

        assert parsed["title"] == "Test Report"
        assert "generated_at" in parsed
        assert parsed["content"]["title"] == "Test Report"

    def test_generate_pdf_fallback(self):
        """Test PDF report generation fallback."""
        from utils.report_generators import _generate_pdf_fallback

        content = {"sections": []}
        result = _generate_pdf_fallback("Test PDF", content)

        assert b"%PDF" in result
        assert b"Test PDF" in result

    def test_generate_docx_fallback(self):
        """Test DOCX report generation fallback."""
        from utils.report_generators import _generate_docx_fallback

        content = {"sections": []}
        result = _generate_docx_fallback("Test DOCX", content)

        assert isinstance(result, bytes)
        assert b"Test DOCX" in result


class TestReportTemplates:
    """Test report templates."""

    def test_templates_exist(self):
        """Test that all required templates exist."""
        from templates.report_templates import REPORT_TEMPLATES

        required_templates = [
            "penetration_test",
            "executive_summary",
            "technical_findings",
            "remediation_roadmap",
        ]

        for template_key in required_templates:
            assert template_key in REPORT_TEMPLATES
            assert "title" in REPORT_TEMPLATES[template_key]
            assert "sections" in REPORT_TEMPLATES[template_key]

    def test_template_structure(self):
        """Test template structure is valid."""
        from templates.report_templates import REPORT_TEMPLATES

        for template_key, template_data in REPORT_TEMPLATES.items():
            assert isinstance(template_data["title"], str)
            assert isinstance(template_data["sections"], list)
            assert isinstance(template_data.get("defaults", {}), dict)

            for section in template_data["sections"]:
                assert "name" in section
                assert "template" in section


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
