"""Topology-neutral EnvironmentFile profiles for scoped enrichment units."""

from collections.abc import Mapping
import re

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
