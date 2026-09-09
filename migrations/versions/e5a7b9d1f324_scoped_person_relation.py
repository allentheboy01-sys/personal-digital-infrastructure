"""Add Observation Scope Person and relation provenance.

Revision ID: e5a7b9d1f324
Revises: d4f6a8c0e213
Create Date: 2026-09-09
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e5a7b9d1f324"
down_revision: str | Sequence[str] | None = "d4f6a8c0e213"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "observation_scope_person_sources",
        sa.Column("observation_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.Text(), nullable=False),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("inactive_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "btrim(external_id) <> ''",
            name="ck_observation_scope_person_sources_external_id_nonempty",
        ),
        sa.CheckConstraint(
            "display_name IS NULL OR btrim(display_name) <> ''",
            name="ck_observation_scope_person_sources_display_name_nonempty",
        ),
        sa.ForeignKeyConstraint(
            ("observation_scope_id",),
            ("observation_scopes.id",),
            name="fk_observation_scope_person_sources_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("person_id",),
            ("persons.id",),
            name="fk_observation_scope_person_sources_person",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "observation_scope_id",
            "external_id",
            name="pk_observation_scope_person_sources",
        ),
    )
    op.create_index(
        "ix_scope_person_sources_active_display_name",
        "observation_scope_person_sources",
        [sa.text("lower(display_name)"), "person_id"],
        unique=False,
        postgresql_where=sa.text("inactive_at IS NULL AND display_name IS NOT NULL"),
    )
    op.create_table(
        "observation_scope_resource_person_relations",
        sa.Column("observation_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("inactive_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ("observation_scope_id",),
            ("observation_scopes.id",),
            name="fk_observation_scope_resource_person_relations_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("resource_id",),
            ("assets.id",),
            name="fk_observation_scope_resource_person_relations_resource",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("person_id",),
            ("persons.id",),
            name="fk_observation_scope_resource_person_relations_person",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "observation_scope_id",
            "resource_id",
            "person_id",
            name="pk_observation_scope_resource_person_relations",
        ),
    )
    op.create_index(
        "ix_scope_resource_person_relations_active",
        "observation_scope_resource_person_relations",
        ["person_id", "resource_id"],
        unique=False,
        postgresql_where=sa.text("inactive_at IS NULL"),
    )


def downgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM observation_scope_person_sources)
             OR EXISTS (SELECT 1 FROM observation_scope_resource_person_relations) THEN
            RAISE EXCEPTION 'MU11 downgrade blocked: scoped Person or relation data exists';
          END IF;
        END $$
    """))
    op.drop_table("observation_scope_resource_person_relations")
    op.drop_table("observation_scope_person_sources")
