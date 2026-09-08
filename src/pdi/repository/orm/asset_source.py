from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Text,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pdi.repository.orm.base import Base


class AssetSourceORM(Base):
    __tablename__ = "asset_sources"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
    )

    blob_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "blobs.id",
            ondelete="RESTRICT",
            name="fk_asset_sources_blob",
        ),
        nullable=False,
    )

    provider: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    external_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    observation_scope_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "observation_scopes.id",
            ondelete="RESTRICT",
            name="fk_asset_sources_observation_scope",
        ),
        nullable=True,
    )

    path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    name: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    version_tag: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    provider_mime_type: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    provider_size: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
    )

    metadata_: Mapped[dict] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


Index(
    "ix_asset_sources_active_blob_id",
    AssetSourceORM.blob_id,
    postgresql_where=AssetSourceORM.is_active.is_(True),
)
Index(
    "uq_asset_sources_scope_external_id",
    AssetSourceORM.observation_scope_id,
    AssetSourceORM.external_id,
    unique=True,
    postgresql_where=AssetSourceORM.observation_scope_id.is_not(None),
)
Index(
    "uq_asset_sources_legacy_provider_external_id",
    AssetSourceORM.provider,
    AssetSourceORM.external_id,
    unique=True,
    postgresql_where=AssetSourceORM.observation_scope_id.is_(None),
)
