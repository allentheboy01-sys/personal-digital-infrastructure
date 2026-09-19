"""P3C frozen input contracts. No production identity or secret defaults."""

from dataclasses import dataclass
import json
import re
from urllib.parse import urlsplit
from uuid import UUID


class Refused(RuntimeError):
    """Only fixed, non-secret diagnostic codes may cross the CLI boundary."""


def require(condition, code):
    if not condition:
        raise Refused(code)


HEAD = "e5a7b9d1f324"
PROVIDERS = ("nextcloud", "immich", "gmail", "integration-test")
SOURCE_MAPPING = {
    "nextcloud": "nextcloud", "immich": "immich",
    "gmail": "gmail_preservation", "integration-test": "integration_test_quarantine",
}
MECHANISMS = {"nextcloud": "activity_v2_hint_v1", "immich": "metadata_updated_at_v1"}
LEGACY = tuple("pdi-" + name for name in (
    "sync-nextcloud-incremental", "sync-nextcloud", "sync-immich-incremental",
    "sync-immich", "enrichment-nextcloud-text", "enrichment-nextcloud-documents",
    "enrichment-immich", "enrichment-immich-geo", "enrichment-immich-ocr",
    "enrichment-file-metadata",
))
READ_SERVICES = ("pdi-resource-access.service", "pdi-dsh-poc-mcp.service",
                 "pdi-nextcloud-tunnel.service", "pdi-immich-tunnel.service")
BACKUP_TIMERS = ("pdi-nextcloud-backup-orchestrator.timer", "pdi-immich-backup-orchestrator.timer")
PIPELINES = {
    "nextcloud-full": "provider.nextcloud.sync",
    "nextcloud-incremental": "provider.nextcloud.incremental",
    "immich-full": "provider.immich.sync",
    "immich-incremental": "provider.immich.incremental",
    "immich-person": "person.immich.sync",
    "immich-relation": "relation.immich.sync",
    "immich-daily": "immich.daily",
}
QUALIFICATION = ("nextcloud-incremental", "immich-incremental", "immich-person", "immich-relation")
SCHEDULES = {"nextcloud-incremental": "*:0/5", "nextcloud-full": "02:15",
             "immich-incremental": "*:2/5", "immich-daily": "05:15"}
COUNT_TABLES = ("assets", "blobs", "asset_sources", "persons", "person_sources",
                "resource_person_relations", "resource_statements", "resource_enrichments",
                "provider_sync_state")
COUNT_KEYS = (*COUNT_TABLES, *("sources." + p for p in PROVIDERS))
ENV_KEYS = {"DATABASE__URL", "NEXTCLOUD__URL", "NEXTCLOUD__USER",
            "NEXTCLOUD__PASSWORD", "IMMICH__URL", "IMMICH__API_KEY"}


@dataclass(frozen=True, repr=False)
class Plan:
    principal: str
    instances: dict
    accounts: dict
    scopes: dict

    @classmethod
    def parse(cls, identity, transition):
        try:
            require(set(identity) == {"principal", "provider_instances", "provider_accounts",
                                     "observation_scopes", "policy"}, "IDENTITY_FORMAT")
            p = identity["principal"]
            require(p["enabled"] is False and p["represents"] == "existing-personal-world", "PRINCIPAL_PLAN")
            policy = identity["policy"]
            require(policy == {"gmail_scoped_ingestion": "disabled", "integration_test_rows_to_delete": 0,
                               "legacy_rows_preserved": True, "person_equals_principal": False}, "POLICY")
            instances, accounts, scopes = (identity[k] for k in
                ("provider_instances", "provider_accounts", "observation_scopes"))
            require(set(instances) == set(PROVIDERS) and set(accounts) == {"nextcloud", "immich"}, "IDENTITY_SET")
            require(set(scopes) == set(SOURCE_MAPPING.values()), "SCOPE_SET")
            require(all(s["enabled"] is False for s in scopes.values()), "SCOPE_PLAN_ENABLED")
            require(set(transition) == {"initial_enablement", "legacy_rows_mutated", "legacy_sync_state_copy", "source_mapping"}, "TRANSITION_FORMAT")
            require(isinstance(transition["initial_enablement"], str) and bool(transition["initial_enablement"]), "ENABLEMENT_FORMAT")
            require(transition["source_mapping"] == SOURCE_MAPPING, "SOURCE_MAPPING")
            # The other two fields are historical P3B evidence, not P3C actions.
            require(transition["legacy_rows_mutated"] is not None and transition["legacy_sync_state_copy"] is not None, "TRANSITION_EVIDENCE")
            result = cls(str(UUID(p["id"])), {k: str(UUID(v)) for k, v in instances.items()},
                         {k: str(UUID(v)) for k, v in accounts.items()},
                         {k: str(UUID(scopes[v]["id"])) for k, v in SOURCE_MAPPING.items()})
            ids = [result.principal, *result.instances.values(), *result.accounts.values(), *result.scopes.values()]
            require(len(ids) == len(set(ids)), "IDENTITY_COLLISION")
            return result
        except (KeyError, ValueError, TypeError, AttributeError):
            raise Refused("IDENTITY_FORMAT") from None


def parse_env(raw):
    """Literal env-file subset. No shell, interpolation, exports or execution."""
    result = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        require(sep and re.fullmatch(r"[A-Z][A-Z0-9_]*", key) and key not in result, "ENV_FORMAT")
        if value.startswith(('"', "'")):
            quote = value[0]
            require(len(value) >= 2 and value[-1] == quote, "ENV_QUOTES")
            value = value[1:-1]
            # Deliberately reject ambiguous escaping instead of changing a secret.
            require("\\" not in value and quote not in value, "ENV_ESCAPING_UNSUPPORTED")
        require(not any(ord(c) < 32 for c in value), "ENV_CONTROL_CHARACTER")
        result[key] = value
    return result


def validate_rollback(metadata, snapshot, source_sha):
    require(re.fullmatch(r"[0-9a-f]{64}", snapshot) is not None, "SNAPSHOT_ARGUMENT")
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None, "SOURCE_SHA_ARGUMENT")
    expected = {"FINAL_QUIESCED_SNAPSHOT_ID": snapshot, "SOURCE_SHA": source_sha,
                "SOURCE_ALEMBIC": "5e7a9c2d1f30", "POSTGRES_MAJOR": "16",
                "WRITERS_QUIESCED": "YES", "RESTORE_TESTED": "YES", "RESTORED_COUNTS_MATCH": "YES"}
    require(all(metadata.get(k) == v for k, v in expected.items()), "ROLLBACK_NOT_QUALIFIED")
    require(all(metadata.get(k) for k in ("SOURCE_HOST", "BACKUP_HOST", "BACKUP_FS_UUID",
        "BACKUP_FS_LABEL", "RESTIC_REPOSITORY_RELATIVE_PATH", "PREVIOUS_QUALIFIED_SNAPSHOT_ID", "FINAL_SNAPSHOT_TAGS")), "ROLLBACK_METADATA_MISSING")


def registry_text(plan, env):
    require(set(env) == ENV_KEYS and all(env.values()), "ENV_KEYS")
    for key in ("NEXTCLOUD__URL", "IMMICH__URL"):
        url = urlsplit(env[key])
        require(url.scheme in {"http", "https"} and url.hostname and not
                (url.username or url.password or url.query or url.fragment), "ENDPOINT_UNSAFE")
    q = json.dumps
    lines = ["[[principals]]", f"id = {q(plan.principal)}", 'database_ref = "harry-personal-db"',
             "enabled = true", "", "[[databases]]", 'ref = "harry-personal-db"', 'url_env = "DATABASE__URL"']
    for provider in ("nextcloud", "immich"):
        prefix = provider.upper()
        secret = "NEXTCLOUD__PASSWORD" if provider == "nextcloud" else "IMMICH__API_KEY"
        lines += ["", "[[provider_bindings]]", f"principal_id = {q(plan.principal)}",
                  f"scope_id = {q(plan.scopes[provider])}", f"provider_type = {q(provider)}",
                  f"endpoint = {q(env[prefix + '__URL'])}", f"secret_env = {q(secret)}"]
        if provider == "nextcloud":
            lines += [f"username = {q(env['NEXTCLOUD__USER'])}"]
    return "\n".join(lines) + "\n"


def unit_environment(plan, env, instance):
    provider = "nextcloud" if instance.startswith("nextcloud-") else "immich"
    secret = "NEXTCLOUD__PASSWORD" if provider == "nextcloud" else "IMMICH__API_KEY"
    values = {"DATABASE__URL": env["DATABASE__URL"], secret: env[secret],
              "PDI_PRINCIPAL_REF": plan.principal, "PDI_SCOPED_PIPELINE_KEY": PIPELINES[instance]}
    # systemd EnvironmentFile double-quote syntax, NOT shell substitution.
    def quote(value):
        require(not any(ord(c) < 32 for c in value), "ENV_CONTROL_CHARACTER")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return "\n".join(k + "=" + quote(v) for k, v in values.items()) + "\n"
