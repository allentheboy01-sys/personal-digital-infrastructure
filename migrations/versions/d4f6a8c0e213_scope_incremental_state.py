"""Add Observation Scope incremental state.

Revision ID: d4f6a8c0e213
Revises: c3e5a7b9d102
Create Date: 2026-09-08
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d4f6a8c0e213"
down_revision: str | Sequence[str] | None = "c3e5a7b9d102"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "observation_scope_sync_state",
        sa.Column("observation_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("mechanism", sa.Text(), nullable=False),
        sa.Column("checkpoint", sa.Text(), nullable=True),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("reconciliation_required", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "btrim(mechanism) <> ''",
            name="ck_observation_scope_sync_state_mechanism_nonempty",
        ),
        sa.CheckConstraint(
            "version >= 0",
            name="ck_observation_scope_sync_state_version_nonnegative",
        ),
        sa.ForeignKeyConstraint(
            ("observation_scope_id",),
            ("observation_scopes.id",),
            name="fk_observation_scope_sync_state_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "observation_scope_id",
            "mechanism",
            name="pk_observation_scope_sync_state",
        ),
    )


def downgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM observation_scope_sync_state) THEN
            RAISE EXCEPTION 'MU6 downgrade blocked: Scope incremental state is not empty';
          END IF;
        END $$
    """))
    op.drop_table("observation_scope_sync_state")
