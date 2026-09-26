"""Fail-closed P3D evidence readers for protected journals and routed DBs."""

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import stat
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.engine import make_url

from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS
from pdi.scoped_enrichment_profiles import derive_enabled_scope_ids
from .enrichment_cutover import P3DControlRefused, context_fingerprint


@contextmanager
def postgresql_read_only_transaction(engine):
    """Yield one verified PostgreSQL READ ONLY connection, then roll it back."""
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            read_only = connection.scalar(text("SHOW transaction_read_only"))
            if str(read_only).lower() != "on":
                raise P3DControlRefused("READ_ONLY_TRANSACTION_REQUIRED")
            yield connection
        finally:
            if transaction.is_active:
                transaction.rollback()


def read_p3c_journal(path: Path, *, expected_sha: str, expected_context: str | None = None) -> dict:
    """Read exactly one current PASS record from a protected JSONL journal."""
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise P3DControlRefused("P3C_JOURNAL_UNTRUSTED")
        records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except (OSError, ValueError, json.JSONDecodeError):
        raise P3DControlRefused("P3C_JOURNAL_UNREADABLE") from None
    matching = [record for record in records if isinstance(record, dict)
                and record.get("phase") == "PASS"
                and record.get("release_sha") == expected_sha
                and record.get("context_fingerprint")
                and (expected_context is None or record.get("context_fingerprint") == expected_context)]
    if len(matching) != 1:
        raise P3DControlRefused("P3C_JOURNAL_EVIDENCE_INVALID")
    if any(record.get("phase") == "PASS" and record is not matching[0] for record in records):
        raise P3DControlRefused("P3C_JOURNAL_DUPLICATE")
    return matching[0]


@dataclass(frozen=True)
class PersonalDatabaseEvidence:
    principal_ref: str
    database_ref: str
    database_url: str
    enabled_scope_ids: frozenset[str]
    identity_fingerprint: str
    transaction_read_only: bool


class RoutedPersonalDatabaseEvidenceReader:
    """Read-only checks through the trusted PrincipalDatabaseRouter."""

    def __init__(self, router, engine, *, principal_ref: str,
                 identity_repository_factory=PostgreSQLProviderIdentityRepository,
                 scope_id_deriver=derive_enabled_scope_ids):
        self.router = router
        self.engine = engine
        self.principal_ref = principal_ref
        self.identity_repository_factory = identity_repository_factory
        self.scope_id_deriver = scope_id_deriver

    def collect(self) -> PersonalDatabaseEvidence:
        try:
            binding = self.router.resolve(self.principal_ref)
            if make_url(binding.database_url) != make_url(self.engine.url):
                raise P3DControlRefused("ROUTE_TARGET_MISMATCH")
            with postgresql_read_only_transaction(self.engine) as connection:
                revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
                if revision != "e5a7b9d1f324":
                    raise P3DControlRefused("ALEMBIC_MISMATCH")
                null_scope = connection.scalar(text(
                    "SELECT count(*) FROM asset_sources WHERE observation_scope_id IS NULL"))
                duplicate = connection.scalar(text(
                    "SELECT count(*) FROM (SELECT observation_scope_id, external_id "
                    "FROM asset_sources GROUP BY observation_scope_id, external_id HAVING count(*) > 1) d"))
                sync_rows = connection.execute(text(
                    "SELECT count(*), count(*) FILTER (WHERE checkpoint IS NOT NULL), "
                    "count(*) FILTER (WHERE NOT reconciliation_required) FROM observation_scope_sync_state"
                )).one()
                if null_scope != 0 or duplicate != 0 or tuple(sync_rows) != (2, 2, 2):
                    raise P3DControlRefused("PERSONAL_DB_INVARIANT_FAILED")
                provider_mismatch = connection.scalar(text(
                    "SELECT count(*) FROM asset_sources source "
                    "JOIN observation_scopes scope ON scope.id=source.observation_scope_id "
                    "JOIN provider_instances instance ON instance.id=scope.provider_instance_id "
                    "WHERE source.provider <> instance.provider_type"
                ))
                source_providers = connection.execute(text(
                    "SELECT provider, count(*) FROM asset_sources GROUP BY provider"
                )).all()
                if provider_mismatch != 0 or {row[0] for row in source_providers} != {
                        "nextcloud", "immich", "gmail", "integration-test"}:
                    raise P3DControlRefused("SOURCE_SCOPE_IDENTITY_MISMATCH")
                repository = self.identity_repository_factory(connection)
                instances = repository.list_instances()
                expected = {"nextcloud": True, "immich": True, "gmail": False,
                            "integration-test": False}
                actual = {}
                identity_state = []
                for instance in instances:
                    if instance.provider_type in expected:
                        if instance.provider_type in actual:
                            raise P3DControlRefused("IDENTITY_DUPLICATE")
                        actual[instance.provider_type] = instance.enabled
                        accounts = repository.list_accounts_for_instance(instance.id)
                        scopes = repository.list_scopes_for_instance(instance.id)
                        expected_account_count = (
                            1 if instance.provider_type in {"nextcloud", "immich"} else 0
                        )
                        if (len(accounts) != expected_account_count or len(scopes) != 1 or
                                any(account.enabled is not True for account in accounts) or
                                scopes[0].enabled is not expected[instance.provider_type]):
                            raise P3DControlRefused("IDENTITY_STATE_MISMATCH")
                        if expected_account_count and scopes[0].provider_account_id != accounts[0].id:
                            raise P3DControlRefused("IDENTITY_ACCOUNT_SCOPE_MISMATCH")
                        if not expected_account_count and scopes[0].provider_account_id is not None:
                            raise P3DControlRefused("IDENTITY_ACCOUNT_SCOPE_MISMATCH")
                        identity_state.append({
                            "provider_type": instance.provider_type,
                            "instance_id": str(instance.id),
                            "instance_enabled": instance.enabled,
                            "account_ids": sorted(str(account.id) for account in accounts),
                            "scope_id": str(scopes[0].id),
                            "scope_enabled": scopes[0].enabled,
                        })
                if actual != expected:
                    raise P3DControlRefused("IDENTITY_STATE_MISMATCH")
                scope_ids = self.scope_id_deriver(connection)
                fingerprint = context_fingerprint({
                    "principal": self.principal_ref,
                    "database_ref": binding.database_ref,
                    "scopes": sorted(map(str, scope_ids)),
                    "identity_state": sorted(
                        identity_state,
                        key=lambda item: item["provider_type"],
                    ),
                })
                return PersonalDatabaseEvidence(
                    self.principal_ref,
                    binding.database_ref,
                    binding.database_url,
                    frozenset(map(str, scope_ids)),
                    fingerprint,
                    True,
                )
        except P3DControlRefused:
            raise
        except Exception:
            raise P3DControlRefused("PERSONAL_DB_UNAVAILABLE") from None


def verify_qualification_ledger_batch(engine, *, started_after: datetime,
                                      pipeline_keys: tuple[str, ...],
                                      candidate_sha: str,
                                      context: dict[str, object]) -> tuple[dict[str, str], ...]:
    """Require exactly one completed, fresh run for every canonical key."""
    if set(pipeline_keys) != set(CANONICAL_SCOPED_ENRICHMENTS):
        raise P3DControlRefused("QUALIFICATION_LEDGER_COVERAGE")
    expected_context = context_fingerprint(context)
    results = []
    with engine.connect() as connection:
        for key in pipeline_keys:
            rows = connection.execute(text(
                "SELECT id, status, finished_at, error_code FROM pipeline_runs "
                "WHERE pipeline_key=:key AND started_at > :after ORDER BY started_at"
            ), {"key": key, "after": started_after}).all()
            if len(rows) != 1:
                raise P3DControlRefused("QUALIFICATION_LEDGER_COVERAGE")
            run_id, status, finished_at, error_code = rows[0]
            if status != "completed" or finished_at is None or error_code is not None:
                raise P3DControlRefused("QUALIFICATION_LEDGER_FAILED")
            results.append({"pipeline_key": key, "run_id": str(run_id),
                            "candidate_sha": candidate_sha,
                            "context_fingerprint": expected_context})
    return tuple(results)
