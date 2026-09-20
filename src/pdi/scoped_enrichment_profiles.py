"""Topology-neutral EnvironmentFile profiles for scoped enrichment units."""

from collections.abc import Mapping
import os
from pathlib import Path
import re
import stat
import tempfile
from uuid import UUID

from .scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS


REQUIRED_SECRET_KEYS: Mapping[str, tuple[str, ...]] = {
    "enrichment.nextcloud_text": ("NEXTCLOUD__PASSWORD",),
    "enrichment.nextcloud_documents": ("NEXTCLOUD__PASSWORD",),
    "enrichment.file_metadata": (),
    "enrichment.immich_geo": (),
    "enrichment.immich_metadata": (),
    "enrichment.immich_ocr": ("IMMICH__API_KEY",),
}


def build_enrichment_profile(
    pipeline_key: str,
    *,
    principal_ref: str,
    database_url: str,
    secrets: Mapping[str, str],
) -> dict[str, str]:
    """Build a validated unit environment without putting secrets in argv."""
    if pipeline_key not in CANONICAL_SCOPED_ENRICHMENTS:
        raise ValueError("UNKNOWN_ENRICHMENT_PIPELINE")
    values = {
        "PDI_PRINCIPAL_REF": principal_ref,
        "PDI_SCOPED_PIPELINE_KEY": pipeline_key,
        "DATABASE__URL": database_url,
    }
    for key in REQUIRED_SECRET_KEYS[pipeline_key]:
        value = secrets.get(key)
        if not value:
            raise ValueError("REQUIRED_SCOPE_SECRET_MISSING")
        values[key] = value
    return values


def profile_keys(pipeline_key: str) -> frozenset[str]:
    """Return key names only, useful for safe profile contract assertions."""
    if pipeline_key not in CANONICAL_SCOPED_ENRICHMENTS:
        raise ValueError("UNKNOWN_ENRICHMENT_PIPELINE")
    return frozenset({"PDI_PRINCIPAL_REF", "PDI_SCOPED_PIPELINE_KEY", "DATABASE__URL"}
                     | set(REQUIRED_SECRET_KEYS[pipeline_key]))


def build_profile_from_binding_refs(
    pipeline_key: str,
    *,
    principal_ref: str,
    database_url: str,
    binding_secret_refs: Mapping[str, str],
    environment: Mapping[str, str],
) -> dict[str, str]:
    """Resolve exact per-Scope refs; never infer one global Provider secret."""
    if pipeline_key not in CANONICAL_SCOPED_ENRICHMENTS:
        raise ValueError("UNKNOWN_ENRICHMENT_PIPELINE")
    provider = "nextcloud" if pipeline_key.startswith("enrichment.nextcloud_") else (
        "immich" if pipeline_key == "enrichment.immich_ocr" else None
    )
    if provider is None and binding_secret_refs:
        raise ValueError("UNRELATED_PROVIDER_SECRET")
    if provider is not None:
        if not binding_secret_refs:
            raise ValueError("REQUIRED_SCOPE_SECRET_REF_MISSING")
        if any(not re.fullmatch(r"[A-Z][A-Z0-9_]*", ref) for ref in binding_secret_refs.values()):
            raise ValueError("SECRET_REF_INVALID")
        if any(not environment.get(ref) for ref in binding_secret_refs.values()):
            raise ValueError("REQUIRED_SCOPE_SECRET_MISSING")
    values = {
        "PDI_PRINCIPAL_REF": principal_ref,
        "PDI_SCOPED_PIPELINE_KEY": pipeline_key,
        "DATABASE__URL": database_url,
    }
    for ref in dict.fromkeys(binding_secret_refs.values()):
        values[ref] = environment[ref]
    return values


def render_environment_file(values: Mapping[str, str]) -> str:
    """Render a systemd EnvironmentFile without shell evaluation."""
    if not values:
        raise ValueError("EMPTY_ENVIRONMENT")
    lines = []
    for key in sorted(values):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError("ENV_KEY_INVALID")
        value = values[key]
        if any(ord(char) < 32 for char in value):
            raise ValueError("ENV_CONTROL_CHARACTER")
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{key}="{escaped}"')
    return "\n".join(lines) + "\n"


def build_trusted_enrichment_profile(
    configuration,
    principal_ref: str,
    pipeline_key: str,
    *,
    enabled_scope_ids: set[UUID],
) -> dict[str, str]:
    """Derive DB and per-Scope secret refs from trusted configuration."""
    if pipeline_key not in CANONICAL_SCOPED_ENRICHMENTS:
        raise ValueError("UNKNOWN_ENRICHMENT_PIPELINE")
    db_env = configuration.router.database_environment_key(principal_ref)
    environment = configuration.environment
    values = {
        "PDI_PRINCIPAL_REF": principal_ref,
        "PDI_SCOPED_PIPELINE_KEY": pipeline_key,
        db_env: environment.get(db_env, ""),
    }
    provider = "nextcloud" if pipeline_key.startswith("enrichment.nextcloud_") else (
        "immich" if pipeline_key == "enrichment.immich_ocr" else None
    )
    if provider is None:
        if not values[db_env]:
            raise ValueError("DATABASE_BINDING_MISSING")
        return values
    selected = [binding for (principal, scope_id), binding in configuration.bindings.items()
                if str(principal) == principal_ref and scope_id in enabled_scope_ids
                and binding.provider_type == provider]
    if not selected:
        raise ValueError("REQUIRED_SCOPE_BINDING_MISSING")
    for binding in selected:
        if not binding.secret_env or not environment.get(binding.secret_env):
            raise ValueError("REQUIRED_SCOPE_SECRET_MISSING")
        if binding.secret_env in values and values[binding.secret_env] != environment[binding.secret_env]:
            raise ValueError("CONFLICTING_SECRET_REF")
        values[binding.secret_env] = environment[binding.secret_env]
    return values


def derive_enabled_scope_ids(engine, *, provider_types: tuple[str, ...] = ("nextcloud", "immich")) -> set[UUID]:
    """Derive enabled Scope authority from the routed Personal DB only."""
    from pdi.provider_identity import PostgreSQLProviderIdentityRepository

    repository = PostgreSQLProviderIdentityRepository(engine)
    enabled: set[UUID] = set()
    for instance in repository.list_instances():
        if instance.provider_type not in provider_types or not instance.enabled:
            continue
        accounts = repository.list_accounts_for_instance(instance.id)
        for scope in repository.list_scopes_for_instance(instance.id):
            if not scope.enabled:
                continue
            if scope.provider_account_id is None:
                raise ValueError("ENABLED_SCOPE_ACCOUNT_MISSING")
            account = next((item for item in accounts if item.id == scope.provider_account_id), None)
            if account is None or not account.enabled:
                raise ValueError("ENABLED_SCOPE_ACCOUNT_DISABLED")
            enabled.add(scope.id)
    return enabled


def install_environment_file(path: Path, values: Mapping[str, str], *, allow_test_root: bool = False) -> str:
    """Atomically install a root-controlled 0600 EnvironmentFile and verify it."""
    if path.is_symlink() or not path.parent.is_dir():
        raise ValueError("ENVFILE_PATH_UNTRUSTED")
    parents = (path.parent,) if allow_test_root else (path.parent, *path.parent.parents)
    for parent in parents:
        info = parent.stat()
        if (not allow_test_root and info.st_uid != 0) or info.st_mode & 0o022:
            raise ValueError("ENVFILE_PARENT_UNTRUSTED")
    content = render_environment_file(values)
    fd, temp_name = tempfile.mkstemp(prefix=".pdi-env-", dir=path.parent)
    try:
        if not allow_test_root:
            os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        installed = path.lstat()
        if (stat.S_ISLNK(installed.st_mode) or
                ((not allow_test_root) and (installed.st_uid != 0 or installed.st_gid != 0)) or
                stat.S_IMODE(installed.st_mode) != 0o600 or
                path.read_text() != content):
            raise ValueError("ENVFILE_VERIFY_FAILED")
    finally:
        Path(temp_name).unlink(missing_ok=True)
    return content
