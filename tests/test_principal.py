from pathlib import Path

import pytest

from pdi.principal import (
    DatabaseBindingRecord,
    DatabaseBindingRegistry,
    DisabledPrincipalError,
    InvalidPrincipalConfigurationError,
    MissingPrincipalError,
    PersonalDatabaseBinding,
    PersonalDatabaseUnavailableError,
    PersonalQueryContextFactory,
    PrincipalDatabaseRouter,
    PrincipalId,
    PrincipalRecord,
    PrincipalRegistry,
    UnknownDatabaseBindingError,
    UnknownPrincipalError,
    load_registries,
)


def _router(*, enabled: bool = True) -> PrincipalDatabaseRouter:
    return PrincipalDatabaseRouter(
        PrincipalRegistry(
            (PrincipalRecord(PrincipalId("mu3-harry"), "harry-db", enabled),)
        ),
        DatabaseBindingRegistry(
            (DatabaseBindingRecord("harry-db", "HARRY_DATABASE_URL"),),
            {
                "HARRY_DATABASE_URL": (
                    "postgresql+psycopg://harry:secret@localhost/harry_test"
                )
            },
        ),
    )


@pytest.mark.parametrize("value", ["", "Harry", "has space", "../harry", True])
def test_principal_id_rejects_noncanonical_values(value: object) -> None:
    with pytest.raises(ValueError, match="opaque identifier"):
        PrincipalId(value)  # type: ignore[arg-type]


def test_display_label_is_not_principal_identity() -> None:
    first = PrincipalRecord(PrincipalId("harry"), "harry-db", display_label="H")
    second = PrincipalRecord(PrincipalId("harry"), "harry-db", display_label="Harry")
    assert first == second


def test_router_resolves_only_preconfigured_principal_binding() -> None:
    binding = _router().resolve("mu3-harry")
    assert binding.database_ref == "harry-db"
    assert "secret" not in repr(binding)
    assert "***" in binding.sanitized_url


def test_router_denies_missing_unknown_and_disabled_principal() -> None:
    with pytest.raises(MissingPrincipalError):
        _router().resolve(None)
    with pytest.raises(UnknownPrincipalError):
        _router().resolve("mu3-mother")
    with pytest.raises(DisabledPrincipalError):
        _router(enabled=False).resolve("mu3-harry")


def test_router_denies_unknown_database_binding() -> None:
    router = PrincipalDatabaseRouter(
        PrincipalRegistry(
            (PrincipalRecord(PrincipalId("mu3-harry"), "missing-db"),)
        ),
        DatabaseBindingRegistry((), {}),
    )
    with pytest.raises(UnknownDatabaseBindingError):
        router.resolve("mu3-harry")


def test_missing_or_malformed_binding_secret_fails_safely() -> None:
    record = DatabaseBindingRecord("harry-db", "HARRY_DATABASE_URL")
    for environment in ({}, {"HARRY_DATABASE_URL": "secret-not-a-url"}):
        registry = DatabaseBindingRegistry((record,), environment)
        with pytest.raises(InvalidPrincipalConfigurationError) as caught:
            registry.resolve("harry-db")
        assert "secret-not-a-url" not in str(caught.value)


def test_registry_file_contains_only_environment_references(tmp_path: Path) -> None:
    config = tmp_path / "principals.toml"
    config.write_text(
        """
[[principals]]
id = "mu3-harry"
database_ref = "harry-db"
enabled = true

[[databases]]
ref = "harry-db"
url_env = "HARRY_DATABASE_URL"
""".strip(),
        encoding="utf-8",
    )
    principals, databases = load_registries(
        config,
        environment={
            "HARRY_DATABASE_URL": (
                "postgresql+psycopg://harry:private@localhost/harry_test"
            )
        },
    )
    assert principals.list_enabled()[0].principal_id == PrincipalId("mu3-harry")
    assert databases.resolve("harry-db") is not None
    assert "private" not in config.read_text(encoding="utf-8")


def test_registry_rejects_one_database_bound_to_two_principals() -> None:
    with pytest.raises(InvalidPrincipalConfigurationError):
        PrincipalRegistry(
            (
                PrincipalRecord(PrincipalId("mu3-harry"), "same-db"),
                PrincipalRecord(PrincipalId("mu3-mother"), "same-db"),
            )
        )


def test_single_user_compatibility_is_explicit_and_exact() -> None:
    url = "postgresql+psycopg://legacy:secret@localhost/legacy_test"
    router = PrincipalDatabaseRouter.explicit_single_user(
        principal_id="legacy-principal",
        database_url=url,
    )
    assert router.resolve("legacy-principal") == PersonalDatabaseBinding(
        "single-user-database", url
    )
    with pytest.raises(MissingPrincipalError):
        router.resolve(None)
    with pytest.raises(UnknownPrincipalError):
        router.resolve("harry")


def test_query_context_reports_unavailable_database_without_secret() -> None:
    router = PrincipalDatabaseRouter(
        PrincipalRegistry(
            (PrincipalRecord(PrincipalId("mu3-harry"), "harry-db"),)
        ),
        DatabaseBindingRegistry(
            (DatabaseBindingRecord("harry-db", "HARRY_DATABASE_URL"),),
            {
                "HARRY_DATABASE_URL": (
                    "postgresql+psycopg://user:topsecret@127.0.0.1:1/db_test"
                )
            },
        ),
    )
    with pytest.raises(PersonalDatabaseUnavailableError) as caught:
        PersonalQueryContextFactory(router).create("mu3-harry")
    assert "topsecret" not in str(caught.value)
