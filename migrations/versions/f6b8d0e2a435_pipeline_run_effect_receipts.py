"""Bind systemd invocations to append-only enrichment effect receipts.

Revision ID: f6b8d0e2a435
Revises: e5a7b9d1f324
Create Date: 2026-10-12
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "f6b8d0e2a435"
down_revision: str | Sequence[str] | None = "e5a7b9d1f324"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "pipeline_runs",
        sa.Column("invocation_fingerprint", sa.String(length=64), nullable=True),
    )
    op.create_check_constraint(
        "ck_pipeline_runs_invocation_fingerprint",
        "pipeline_runs",
        "invocation_fingerprint IS NULL OR "
        "invocation_fingerprint ~ '^[0-9a-f]{64}$'",
    )
    op.create_index(
        "uq_pipeline_runs_invocation_fingerprint",
        "pipeline_runs",
        ["invocation_fingerprint"],
        unique=True,
        postgresql_where=sa.text("invocation_fingerprint IS NOT NULL"),
    )
    op.execute(sa.text("""
        CREATE FUNCTION public.pdi_reject_pipeline_run_invocation_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
          RAISE EXCEPTION 'pipeline run invocation binding is immutable'
            USING ERRCODE = '55000';
        END
        $$
    """))
    op.execute(sa.text("""
        CREATE TRIGGER trg_pipeline_runs_reject_invocation_mutation
        BEFORE UPDATE OF invocation_fingerprint ON pipeline_runs
        FOR EACH ROW
        WHEN (OLD.invocation_fingerprint IS DISTINCT FROM NEW.invocation_fingerprint)
        EXECUTE FUNCTION public.pdi_reject_pipeline_run_invocation_mutation()
    """))

    op.create_table(
        "pipeline_run_effect_receipts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.SmallInteger(), server_default=sa.text("1"), nullable=False),
        sa.Column("pipeline_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pipeline_key", sa.String(length=128), nullable=False),
        sa.Column("subject_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("generator_type", sa.Text(), nullable=False),
        sa.Column("generator_name", sa.Text(), nullable=False),
        sa.Column("generator_version", sa.Text(), nullable=False),
        sa.Column("input_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_statement_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
        ),
        sa.Column(
            "deactivated_statement_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
        ),
        sa.Column(
            "current_statement_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
        ),
        sa.Column(
            "source_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
        ),
        sa.Column("statement_write_count", sa.Integer(), nullable=False),
        sa.Column("deactivated_statement_count", sa.Integer(), nullable=False),
        sa.Column("current_statement_count", sa.Integer(), nullable=False),
        sa.Column("enrichment_state_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("statement_effect_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("source_binding_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("fragment_fingerprint", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "version = 1", name="ck_pipeline_run_effect_receipts_version"
        ),
        sa.CheckConstraint(
            "btrim(pipeline_key) <> ''",
            name="ck_pipeline_run_effect_receipts_pipeline_key_nonempty",
        ),
        sa.CheckConstraint(
            "btrim(generator_type) <> '' AND btrim(generator_name) <> '' "
            "AND btrim(generator_version) <> ''",
            name="ck_pipeline_run_effect_receipts_generator_nonempty",
        ),
        sa.CheckConstraint(
            "input_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_input_fingerprint",
        ),
        sa.CheckConstraint(
            "enrichment_state_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_enrichment_fingerprint",
        ),
        sa.CheckConstraint(
            "fragment_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_fragment_fingerprint",
        ),
        sa.CheckConstraint(
            "statement_effect_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_statement_effect_fingerprint",
        ),
        sa.CheckConstraint(
            "source_binding_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_pipeline_run_effect_receipts_source_binding_fingerprint",
        ),
        sa.CheckConstraint(
            "cardinality(source_ids) > 0",
            name="ck_pipeline_run_effect_receipts_sources_nonempty",
        ),
        sa.CheckConstraint(
            "statement_write_count = cardinality(created_statement_ids) "
            "AND deactivated_statement_count = cardinality(deactivated_statement_ids) "
            "AND current_statement_count = cardinality(current_statement_ids)",
            name="ck_pipeline_run_effect_receipts_counts",
        ),
        sa.CheckConstraint(
            "statement_write_count >= 0 AND deactivated_statement_count >= 0 "
            "AND current_statement_count >= 0",
            name="ck_pipeline_run_effect_receipts_nonnegative_counts",
        ),
        sa.ForeignKeyConstraint(
            ("pipeline_run_id",),
            ("pipeline_runs.id",),
            name="fk_pipeline_run_effect_receipts_run",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("subject_asset_id",),
            ("assets.id",),
            name="fk_pipeline_run_effect_receipts_subject_asset",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_pipeline_run_effect_receipts"),
        sa.UniqueConstraint(
            "pipeline_run_id",
            "subject_asset_id",
            "generator_type",
            "generator_name",
            "generator_version",
            name="uq_pipeline_run_effect_receipts_publish",
        ),
    )
    op.create_index(
        "ix_pipeline_run_effect_receipts_run",
        "pipeline_run_effect_receipts",
        ["pipeline_run_id", "id"],
        unique=False,
    )

    op.execute(sa.text("""
        CREATE FUNCTION public.pdi_validate_pipeline_run_effect_receipt_insert()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          bound_run public.pipeline_runs%ROWTYPE;
        BEGIN
          SELECT * INTO bound_run
          FROM public.pipeline_runs
          WHERE id = NEW.pipeline_run_id
          FOR UPDATE;

          IF NOT FOUND
             OR bound_run.kind <> 'enrichment'
             OR bound_run.status <> 'running'
             OR bound_run.invocation_fingerprint IS NULL
             OR bound_run.pipeline_key <> NEW.pipeline_key THEN
            RAISE EXCEPTION 'pipeline run effect receipt authority invalid'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
    """))
    op.execute(sa.text("""
        CREATE TRIGGER trg_pipeline_run_effect_receipts_validate_insert
        BEFORE INSERT ON pipeline_run_effect_receipts
        FOR EACH ROW EXECUTE FUNCTION public.pdi_validate_pipeline_run_effect_receipt_insert()
    """))
    op.execute(sa.text("""
        CREATE FUNCTION public.pdi_reject_pipeline_run_effect_receipt_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
          RAISE EXCEPTION 'pipeline run effect receipts are append-only'
            USING ERRCODE = '55000';
        END
        $$
    """))
    op.execute(sa.text("""
        CREATE TRIGGER trg_pipeline_run_effect_receipts_reject_mutation
        BEFORE UPDATE OR DELETE ON pipeline_run_effect_receipts
        FOR EACH ROW EXECUTE FUNCTION public.pdi_reject_pipeline_run_effect_receipt_mutation()
    """))
    # Existing Personal DB runtime roles already have explicit grants on
    # pipeline_runs. Copy only those existing table privileges to the new
    # receipt table without assuming or inventing a role name. New databases
    # still receive the provisioner's normal all-table grant after migration.
    op.execute(sa.text("""
        DO $$
        DECLARE
          grant_row record;
          grantee_name text;
        BEGIN
          FOR grant_row IN
            SELECT DISTINCT acl.grantee, acl.privilege_type
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl
            WHERE namespace.nspname = 'public'
              AND relation.relname = 'pipeline_runs'
              AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
          LOOP
            IF grant_row.grantee = 0 THEN
              grantee_name := 'PUBLIC';
              EXECUTE pg_catalog.format(
                'GRANT %s ON TABLE public.pipeline_run_effect_receipts TO PUBLIC',
                grant_row.privilege_type
              );
            ELSE
              grantee_name := pg_catalog.pg_get_userbyid(grant_row.grantee);
              EXECUTE pg_catalog.format(
                'GRANT %s ON TABLE public.pipeline_run_effect_receipts TO %I',
                grant_row.privilege_type,
                grantee_name
              );
            END IF;
          END LOOP;
        END
        $$
    """))


def downgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM pipeline_run_effect_receipts)
             OR EXISTS (
               SELECT 1 FROM pipeline_runs
               WHERE invocation_fingerprint IS NOT NULL
             ) THEN
            RAISE EXCEPTION
              'P3D runtime-effect downgrade blocked: invocation evidence exists';
          END IF;
        END
        $$
    """))
    op.execute(sa.text(
        "DROP TRIGGER trg_pipeline_run_effect_receipts_reject_mutation "
        "ON pipeline_run_effect_receipts"
    ))
    op.execute(sa.text(
        "DROP FUNCTION public.pdi_reject_pipeline_run_effect_receipt_mutation()"
    ))
    op.execute(sa.text(
        "DROP TRIGGER trg_pipeline_run_effect_receipts_validate_insert "
        "ON pipeline_run_effect_receipts"
    ))
    op.execute(sa.text(
        "DROP FUNCTION public.pdi_validate_pipeline_run_effect_receipt_insert()"
    ))
    op.drop_table("pipeline_run_effect_receipts")
    op.execute(sa.text(
        "DROP TRIGGER trg_pipeline_runs_reject_invocation_mutation "
        "ON pipeline_runs"
    ))
    op.execute(sa.text(
        "DROP FUNCTION public.pdi_reject_pipeline_run_invocation_mutation()"
    ))
    op.drop_index(
        "uq_pipeline_runs_invocation_fingerprint", table_name="pipeline_runs"
    )
    op.drop_constraint(
        "ck_pipeline_runs_invocation_fingerprint",
        "pipeline_runs",
        type_="check",
    )
    op.drop_column("pipeline_runs", "invocation_fingerprint")
