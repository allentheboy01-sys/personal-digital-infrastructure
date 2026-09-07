"""Control-plane Principal database fleet foundation."""

from .application import PersonalQueryContext, PersonalQueryContextFactory
from .errors import (
    DisabledPrincipalError,
    InvalidPrincipalConfigurationError,
    MissingPrincipalError,
    PersonalDatabaseUnavailableError,
    PrincipalRoutingError,
    UnknownDatabaseBindingError,
    UnknownPrincipalError,
)
from .models import (
    DatabaseBindingRecord,
    PersonalDatabaseBinding,
    PrincipalId,
    PrincipalRecord,
)
from .fleet import (
    FleetDatabaseHealth,
    PersonalDatabaseFleetInspector,
    PersonalDatabaseStatus,
    repository_schema_head,
)
from .provisioning import (
    PersonalDatabaseProvisioner,
    PersonalDatabaseProvisioningResult,
    PersonalDatabaseProvisioningSpec,
)
from .registry import DatabaseBindingRegistry, PrincipalRegistry, load_registries
from .router import PrincipalDatabaseRouter

__all__ = [
    "DatabaseBindingRecord",
    "DatabaseBindingRegistry",
    "DisabledPrincipalError",
    "FleetDatabaseHealth",
    "InvalidPrincipalConfigurationError",
    "MissingPrincipalError",
    "PersonalDatabaseBinding",
    "PersonalDatabaseFleetInspector",
    "PersonalDatabaseProvisioner",
    "PersonalDatabaseProvisioningResult",
    "PersonalDatabaseProvisioningSpec",
    "PersonalDatabaseStatus",
    "PersonalDatabaseUnavailableError",
    "PersonalQueryContext",
    "PersonalQueryContextFactory",
    "PrincipalDatabaseRouter",
    "PrincipalId",
    "PrincipalRecord",
    "PrincipalRegistry",
    "PrincipalRoutingError",
    "UnknownDatabaseBindingError",
    "UnknownPrincipalError",
    "load_registries",
    "repository_schema_head",
]
