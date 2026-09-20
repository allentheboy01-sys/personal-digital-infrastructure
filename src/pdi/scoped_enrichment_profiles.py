"""Topology-neutral EnvironmentFile profiles for scoped enrichment units."""

from collections.abc import Mapping

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
