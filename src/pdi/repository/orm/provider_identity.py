from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Text, UniqueConstraint, true
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


_KEY_PATTERN = "^[a-z0-9][a-z0-9._-]{0,127}$"


class ProviderInstanceORM(Base):
    __tablename__ = "provider_instances"
    __table_args__ = (
        CheckConstraint(f"provider_type ~ '{_KEY_PATTERN}'", name="ck_provider_instances_provider_type_canonical"),
        CheckConstraint(f"instance_key ~ '{_KEY_PATTERN}'", name="ck_provider_instances_instance_key_canonical"),
        CheckConstraint("display_label IS NULL OR btrim(display_label) <> ''", name="ck_provider_instances_display_label_nonempty"),
        UniqueConstraint("instance_key", name="uq_provider_instances_instance_key"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    provider_type: Mapped[str] = mapped_column(Text, nullable=False)
    instance_key: Mapped[str] = mapped_column(Text, nullable=False)
    display_label: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ProviderAccountORM(Base):
    __tablename__ = "provider_accounts"
    __table_args__ = (
        CheckConstraint(f"account_key ~ '{_KEY_PATTERN}'", name="ck_provider_accounts_account_key_canonical"),
        CheckConstraint("provider_native_id IS NULL OR btrim(provider_native_id) <> ''", name="ck_provider_accounts_native_id_nonempty"),
        CheckConstraint("display_label IS NULL OR btrim(display_label) <> ''", name="ck_provider_accounts_display_label_nonempty"),
        UniqueConstraint("provider_instance_id", "account_key", name="uq_provider_accounts_instance_account_key"),
        UniqueConstraint("id", "provider_instance_id", name="uq_provider_accounts_id_instance"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    provider_instance_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("provider_instances.id", ondelete="RESTRICT", name="fk_provider_accounts_instance"), nullable=False)
    account_key: Mapped[str] = mapped_column(Text, nullable=False)
    provider_native_id: Mapped[str | None] = mapped_column(Text)
    display_label: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ObservationScopeORM(Base):
    __tablename__ = "observation_scopes"
    __table_args__ = (
        CheckConstraint(f"scope_key ~ '{_KEY_PATTERN}'", name="ck_observation_scopes_scope_key_canonical"),
        CheckConstraint("display_label IS NULL OR btrim(display_label) <> ''", name="ck_observation_scopes_display_label_nonempty"),
        UniqueConstraint("provider_instance_id", "scope_key", name="uq_observation_scopes_instance_scope_key"),
        ForeignKeyConstraint(
            ("provider_account_id", "provider_instance_id"),
            ("provider_accounts.id", "provider_accounts.provider_instance_id"),
            name="fk_observation_scopes_account_instance",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    provider_instance_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("provider_instances.id", ondelete="RESTRICT", name="fk_observation_scopes_instance"), nullable=False)
    provider_account_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    scope_key: Mapped[str] = mapped_column(Text, nullable=False)
    display_label: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
