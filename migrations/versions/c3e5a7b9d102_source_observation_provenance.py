"""Add transitional Observation Scope provenance to Sources.

Revision ID: c3e5a7b9d102
Revises: b8d4f2a6c901
Create Date: 2026-09-08
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c3e5a7b9d102"
down_revision: str | Sequence[str] | None = "b8d4f2a6c901"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "asset_sources",
        sa.Column("observation_scope_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_asset_sources_observation_scope",
        "asset_sources",
        "observation_scopes",
        ("observation_scope_id",),
        ("id",),
        ondelete="RESTRICT",
    )
    op.drop_constraint(
        "uq_asset_sources_provider_external_id",
        "asset_sources",
        type_="unique",
    )
    op.create_index(
        "uq_asset_sources_scope_external_id",
        "asset_sources",
        ("observation_scope_id", "external_id"),
        unique=True,
        postgresql_where=sa.text("observation_scope_id IS NOT NULL"),
    )
    op.create_index(
        "uq_asset_sources_legacy_provider_external_id",
        "asset_sources",
        ("provider", "external_id"),
        unique=True,
        postgresql_where=sa.text("observation_scope_id IS NULL"),
    )


def downgrade() -> None:
    # The old namespace cannot represent duplicate provider/external_id pairs.
    # Abort before any DDL rather than deleting, merging, or rewriting Sources.
    op.execute(sa.text("""
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM asset_sources
            GROUP BY provider, external_id HAVING count(*) > 1
          ) THEN
            RAISE EXCEPTION 'MU5 downgrade blocked: scoped Source identities collide in legacy namespace';
          END IF;
        END $$
    """))
    op.drop_index("uq_asset_sources_legacy_provider_external_id", table_name="asset_sources")
    op.drop_index("uq_asset_sources_scope_external_id", table_name="asset_sources")
    op.create_unique_constraint(
        "uq_asset_sources_provider_external_id",
        "asset_sources",
        ("provider", "external_id"),
    )
    op.drop_constraint(
        "fk_asset_sources_observation_scope",
        "asset_sources",
        type_="foreignkey",
    )
    op.drop_column("asset_sources", "observation_scope_id")
