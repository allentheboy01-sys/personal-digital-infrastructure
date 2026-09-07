"""Add Provider Instance, Account, and Observation Scope identity.

Revision ID: b8d4f2a6c901
Revises: 5e7a9c2d1f30
Create Date: 2026-09-07
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b8d4f2a6c901"
down_revision: str | Sequence[str] | None = "5e7a9c2d1f30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_KEY_PATTERN = "^[a-z0-9][a-z0-9._-]{0,127}$"


def upgrade() -> None:
    op.create_table(
        "provider_instances",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_type", sa.Text(), nullable=False),
        sa.Column("instance_key", sa.Text(), nullable=False),
        sa.Column("display_label", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"provider_type ~ '{_KEY_PATTERN}'", name="ck_provider_instances_provider_type_canonical"),
        sa.CheckConstraint(f"instance_key ~ '{_KEY_PATTERN}'", name="ck_provider_instances_instance_key_canonical"),
        sa.CheckConstraint("display_label IS NULL OR btrim(display_label) <> ''", name="ck_provider_instances_display_label_nonempty"),
        sa.PrimaryKeyConstraint("id", name="pk_provider_instances"),
        sa.UniqueConstraint("instance_key", name="uq_provider_instances_instance_key"),
    )
    op.create_table(
        "provider_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("account_key", sa.Text(), nullable=False),
        sa.Column("provider_native_id", sa.Text(), nullable=True),
        sa.Column("display_label", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"account_key ~ '{_KEY_PATTERN}'", name="ck_provider_accounts_account_key_canonical"),
        sa.CheckConstraint("provider_native_id IS NULL OR btrim(provider_native_id) <> ''", name="ck_provider_accounts_native_id_nonempty"),
        sa.CheckConstraint("display_label IS NULL OR btrim(display_label) <> ''", name="ck_provider_accounts_display_label_nonempty"),
        sa.ForeignKeyConstraint(("provider_instance_id",), ("provider_instances.id",), name="fk_provider_accounts_instance", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_provider_accounts"),
        sa.UniqueConstraint("provider_instance_id", "account_key", name="uq_provider_accounts_instance_account_key"),
        sa.UniqueConstraint("id", "provider_instance_id", name="uq_provider_accounts_id_instance"),
    )
    op.create_table(
        "observation_scopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_account_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scope_key", sa.Text(), nullable=False),
        sa.Column("display_label", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"scope_key ~ '{_KEY_PATTERN}'", name="ck_observation_scopes_scope_key_canonical"),
        sa.CheckConstraint("display_label IS NULL OR btrim(display_label) <> ''", name="ck_observation_scopes_display_label_nonempty"),
        sa.ForeignKeyConstraint(("provider_instance_id",), ("provider_instances.id",), name="fk_observation_scopes_instance", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("provider_account_id", "provider_instance_id"),
            ("provider_accounts.id", "provider_accounts.provider_instance_id"),
            name="fk_observation_scopes_account_instance",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_observation_scopes"),
        sa.UniqueConstraint("provider_instance_id", "scope_key", name="uq_observation_scopes_instance_scope_key"),
    )


def downgrade() -> None:
    op.drop_table("observation_scopes")
    op.drop_table("provider_accounts")
    op.drop_table("provider_instances")
