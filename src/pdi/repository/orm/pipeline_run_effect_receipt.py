from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class PipelineRunEffectReceiptORM(Base):
    """Append-only receipt for one committed enrichment publish transaction."""

    __tablename__ = "pipeline_run_effect_receipts"
    __table_args__ = (
        CheckConstraint("version = 1", name="ck_pipeline_run_effect_receipts_version"),
        CheckConstraint(
            "btrim(pipeline_key) <> ''",
            name="ck_pipeline_run_effect_receipts_pipeline_key_nonempty",
        ),
        CheckConstraint(
            "btrim(generator_type) <> '' AND btrim(generator_name) <> '' "
            "AND btrim(generator_version) <> ''",
            name="ck_pipeline_run_effect_receipts_generator_nonempty",
        ),
        CheckConstraint(
            "input_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_input_fingerprint",
        ),
        CheckConstraint(
            "enrichment_state_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_enrichment_fingerprint",
        ),
        CheckConstraint(
            "fragment_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_fragment_fingerprint",
        ),
        CheckConstraint(
            "statement_effect_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_statement_effect_fingerprint",
        ),
        CheckConstraint(
            "source_binding_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_source_binding_fingerprint",
        ),
        CheckConstraint(
            "cardinality(source_ids) > 0",
            name="ck_pipeline_run_effect_receipts_sources_nonempty",
        ),
        CheckConstraint(
            "statement_write_count = cardinality(created_statement_ids) "
            "AND deactivated_statement_count = cardinality(deactivated_statement_ids) "
            "AND current_statement_count = cardinality(current_statement_ids)",
            name="ck_pipeline_run_effect_receipts_counts",
        ),
        CheckConstraint(
            "statement_write_count >= 0 AND deactivated_statement_count >= 0 "
            "AND current_statement_count >= 0",
            name="ck_pipeline_run_effect_receipts_nonnegative_counts",
        ),
        UniqueConstraint(
            "pipeline_run_id",
            "subject_asset_id",
            "generator_type",
            "generator_name",
            "generator_version",
            name="uq_pipeline_run_effect_receipts_publish",
        ),
        Index(
            "ix_pipeline_run_effect_receipts_run",
            "pipeline_run_id",
            "id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    version: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=1, server_default=text("1")
    )
    pipeline_run_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "pipeline_runs.id",
            ondelete="RESTRICT",
            name="fk_pipeline_run_effect_receipts_run",
        ),
        nullable=False,
    )
    pipeline_key: Mapped[str] = mapped_column(String(128), nullable=False)
    subject_asset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "assets.id",
            ondelete="RESTRICT",
            name="fk_pipeline_run_effect_receipts_subject_asset",
        ),
        nullable=False,
    )
    generator_type: Mapped[str] = mapped_column(Text, nullable=False)
    generator_name: Mapped[str] = mapped_column(Text, nullable=False)
    generator_version: Mapped[str] = mapped_column(Text, nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_statement_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PG_UUID(as_uuid=True)), nullable=False
    )
    deactivated_statement_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PG_UUID(as_uuid=True)), nullable=False
    )
    current_statement_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PG_UUID(as_uuid=True)), nullable=False
    )
    source_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PG_UUID(as_uuid=True)), nullable=False
    )
    statement_write_count: Mapped[int] = mapped_column(Integer, nullable=False)
    deactivated_statement_count: Mapped[int] = mapped_column(Integer, nullable=False)
    current_statement_count: Mapped[int] = mapped_column(Integer, nullable=False)
    enrichment_state_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    statement_effect_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    source_binding_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    fragment_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
