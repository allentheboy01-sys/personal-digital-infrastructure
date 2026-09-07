"""Sanitized failures at the Principal database routing boundary."""


class PrincipalRoutingError(RuntimeError):
    code = "principal_routing_failed"


class MissingPrincipalError(PrincipalRoutingError):
    code = "principal_required"


class UnknownPrincipalError(PrincipalRoutingError):
    code = "principal_unknown"


class DisabledPrincipalError(PrincipalRoutingError):
    code = "principal_disabled"


class UnknownDatabaseBindingError(PrincipalRoutingError):
    code = "database_binding_unknown"


class InvalidPrincipalConfigurationError(PrincipalRoutingError):
    code = "principal_configuration_invalid"


class PersonalDatabaseUnavailableError(PrincipalRoutingError):
    code = "personal_database_unavailable"
