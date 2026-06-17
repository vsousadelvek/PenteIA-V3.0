from sqlalchemy import Column, String, DateTime, JSON, Enum, ForeignKey, Index
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from db.base import Base
from models.report import ReportType, ReportFormat


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    type = Column(Enum(ReportType), nullable=False)
    format = Column(Enum(ReportFormat), nullable=False)
    content = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_reports_user_id_created_at", "user_id", "created_at"),
        Index("ix_reports_type", "type"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "type": self.type.value,
            "format": self.format.value,
            "content": self.content,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
