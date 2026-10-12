from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class PipelineRunORM(Base):
    __tablename__ = "pipeline_runs"
    __table_args__ = (
        CheckConstraint(
            "btrim(pipeline_key) <> ''",
            name="ck_pipeline_runs_key_nonempty",
        ),
        CheckConstraint(
            "kind IN ('provider_sync', 'enrichment')",
            name="ck_pipeline_runs_kind",
        ),
        CheckConstraint(
            "status IN ('running', 'completed', 'failed')",
            name="ck_pipeline_runs_status",
        ),
        CheckConstraint(
            "(status = 'running' AND finished_at IS NULL AND error_code IS NULL) OR "
            "(status = 'completed' AND finished_at IS NOT NULL AND error_code IS NULL) OR "
            "(status = 'failed' AND finished_at IS NOT NULL AND error_code IS NOT NULL)",
            name="ck_pipeline_runs_lifecycle",
        ),
        CheckConstraint(
            "error_code IS NULL OR error_code IN "
            "('execution_failed', 'interrupted_previous_run')",
            name="ck_pipeline_runs_error_code",
        ),
        CheckConstraint(
            "invocation_fingerprint IS NULL OR "
            "invocation_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_runs_invocation_fingerprint",
        ),
        Index(
            "ix_pipeline_runs_key_started_at",
            "pipeline_key",
            text("started_at DESC"),
        ),
        Index(
            "uq_pipeline_runs_running_key",
            "pipeline_key",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
        Index(
            "uq_pipeline_runs_invocation_fingerprint",
            "invocation_fingerprint",
            unique=True,
            postgresql_where=text("invocation_fingerprint IS NOT NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    pipeline_key: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    invocation_fingerprint: Mapped[str | None] = mapped_column(String(64))
