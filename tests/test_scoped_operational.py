from pathlib import Path
from uuid import UUID

import pytest

from pdi.principal import PrincipalId
from pdi.scoped_operational import build_parser
from pdi.scoped_operator_config import (
    ScopedOperatorConfigurationError,
    load_scoped_operator_configuration,
)


ROOT = Path(__file__).resolve().parents[1]


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "operator.toml"
    path.write_text(
        """
[[principals]]
id = "synthetic-a"
database_ref = "a-db"

[[databases]]
ref = "a-db"
url_env = "A_DATABASE_URL"

[[provider_bindings]]
principal_id = "synthetic-a"
scope_id = "11111111-1111-4111-8111-111111111111"
provider_type = "nextcloud"
endpoint = "https://provider.invalid"
username = "synthetic-user"
secret_env = "A_NEXTCLOUD_PASSWORD"
""".strip(),
        encoding="utf-8",
    )
    return path


def test_trusted_config_resolves_exact_principal_scope_without_secret_repr(tmp_path):
    config = load_scoped_operator_configuration(
        _config(tmp_path),
        environment={
            "A_DATABASE_URL": "postgresql+psycopg://u:p@localhost/a_test",
            "A_NEXTCLOUD_PASSWORD": "synthetic-secret",
        },
    )
    binding, secret = config.resolve(
        PrincipalId("synthetic-a"),
        UUID("11111111-1111-4111-8111-111111111111"),
        "nextcloud",
    )
    assert binding.provider_type == "nextcloud"
    assert secret == "synthetic-secret"
    assert "synthetic-secret" not in repr(config)
    with pytest.raises(ScopedOperatorConfigurationError):
        config.resolve(
            PrincipalId("synthetic-a"),
            UUID("22222222-2222-4222-8222-222222222222"),
            "nextcloud",
        )


def test_scoped_operator_cli_has_no_raw_authorization_secret_arguments():
    actions = {option for action in build_parser()._actions for option in action.option_strings}
    assert {"--config", "--principal-ref", "--pipeline-key", "--lock-timeout"} <= actions
    assert not actions & {
        "--database-url", "--database-password", "--scope-id", "--api-key",
        "--password", "--credential",
    }


def test_scoped_systemd_template_fixes_principal_and_keeps_secrets_out_of_argv():
    unit = (ROOT / "deployment/systemd/pdi-scoped-pipeline@.service").read_text()
    exec_start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    assert "--principal-ref ${PDI_PRINCIPAL_REF}" in exec_start
    assert "--config /etc/pdi/scoped/registry.toml" in exec_start
    assert "/run/lock" in unit
    assert all(word not in exec_start.lower() for word in ("password", "api-key", "database-url"))
