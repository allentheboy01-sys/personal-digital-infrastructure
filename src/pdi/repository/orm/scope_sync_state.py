from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class ObservationScopeSyncStateORM(Base):
    __tablename__ = "observation_scope_sync_state"
    __table_args__ = (
        CheckConstraint(
            "btrim(mechanism) <> ''",
            name="ck_observation_scope_sync_state_mechanism_nonempty",
        ),
        CheckConstraint(
            "version >= 0",
            name="ck_observation_scope_sync_state_version_nonnegative",
        ),
    )

    observation_scope_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "observation_scopes.id",
            ondelete="RESTRICT",
            name="fk_observation_scope_sync_state_scope",
        ),
        primary_key=True,
    )
    mechanism: Mapped[str] = mapped_column(Text, primary_key=True)
    checkpoint: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    reconciliation_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
