"""Provider-neutral control-plane models for Personal PDI databases."""

from dataclasses import dataclass, field
import re

from sqlalchemy.engine import make_url


_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def _validated_identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(
            f"{field_name} must be a lowercase opaque identifier"
        )
    return value


@dataclass(frozen=True, slots=True)
class PrincipalId:
    """Opaque stable identity of one authenticated PDI Principal."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _validated_identifier(self.value, "principal_id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PrincipalRecord:
    principal_id: PrincipalId
    database_ref: str
    enabled: bool = True
    display_label: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "database_ref",
            _validated_identifier(self.database_ref, "database_ref"),
        )
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be boolean")
        if self.display_label is not None and (
            not isinstance(self.display_label, str)
            or not self.display_label.strip()
        ):
            raise ValueError("display_label must be non-empty when present")


@dataclass(frozen=True, slots=True)
class DatabaseBindingRecord:
    """Non-secret reference to protected connection configuration."""

    database_ref: str
    url_env: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "database_ref",
            _validated_identifier(self.database_ref, "database_ref"),
        )
        if (
            not isinstance(self.url_env, str)
            or not self.url_env
            or not self.url_env.replace("_", "").isalnum()
            or self.url_env.upper() != self.url_env
        ):
            raise ValueError("url_env must be an uppercase environment name")


@dataclass(frozen=True, slots=True)
class PersonalDatabaseBinding:
    """Resolved internal database route; URL is deliberately hidden."""

    database_ref: str
    database_url: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "database_ref",
            _validated_identifier(self.database_ref, "database_ref"),
        )
        try:
            parsed = make_url(self.database_url)
        except Exception as error:
            raise ValueError("database binding URL is malformed") from error
        if parsed.get_backend_name() != "postgresql" or not parsed.database:
            raise ValueError("database binding must identify PostgreSQL")

    @property
    def sanitized_url(self) -> str:
        return str(make_url(self.database_url).render_as_string(hide_password=True))
