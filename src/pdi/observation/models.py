from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import math
import re
from types import MappingProxyType
from typing import TypeAlias

from pdi.query.resources import format_resource_ref, parse_resource_ref

from .errors import ObservationValidationError


class StatementValueType(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    RESOURCE_REF = "resource_ref"


class PredicateCardinality(StrEnum):
    SINGLE = "single"
    MULTI = "multi"


class EvidenceSourceKind(StrEnum):
    PROVIDER_METADATA = "provider_metadata"
    RESOURCE_CONTENT = "resource_content"


class EnrichmentStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def _non_empty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ObservationValidationError(f"{name} must be non-empty")
    return value


@dataclass(frozen=True, slots=True)
class GeneratorIdentity:
    generator_type: str
    generator_name: str
    generator_version: str

    def __post_init__(self) -> None:
        _non_empty(self.generator_type, "generator_type")
        _non_empty(self.generator_name, "generator_name")
        _non_empty(self.generator_version, "generator_version")


@dataclass(frozen=True, slots=True)
class Evidence:
    source_kind: EvidenceSourceKind
    source_locator: str

    def __post_init__(self) -> None:
        try:
            kind = EvidenceSourceKind(self.source_kind)
        except (ValueError, TypeError) as error:
            raise ObservationValidationError(
                "Unsupported evidence source_kind"
            ) from error
        object.__setattr__(self, "source_kind", kind)
        _non_empty(self.source_locator, "source_locator")


StatementScalar: TypeAlias = str | int | float | bool | datetime


@dataclass(frozen=True, slots=True)
class TypedStatementValue:
    value_type: StatementValueType
    value: StatementScalar

    def __post_init__(self) -> None:
        try:
            value_type = StatementValueType(self.value_type)
        except (ValueError, TypeError) as error:
            raise ObservationValidationError(
                "Unsupported statement value_type"
            ) from error
        object.__setattr__(self, "value_type", value_type)

        value = self.value
        if value_type is StatementValueType.STRING:
            valid = isinstance(value, str)
        elif value_type is StatementValueType.INTEGER:
            valid = type(value) is int
        elif value_type is StatementValueType.FLOAT:
            valid = type(value) is float and math.isfinite(value)
        elif value_type is StatementValueType.BOOLEAN:
            valid = type(value) is bool
        elif value_type is StatementValueType.DATETIME:
            valid = (
                isinstance(value, datetime)
                and value.tzinfo is not None
                and value.utcoffset() is not None
            )
            if valid:
                object.__setattr__(self, "value", value.astimezone(UTC))
        else:
            valid = isinstance(value, str)
            if valid:
                asset_id = parse_resource_ref(value)
                canonical = format_resource_ref(asset_id)
                valid = canonical == value

        if not valid:
            raise ObservationValidationError(
                f"Invalid Python value for {value_type.value}"
            )


@dataclass(frozen=True, slots=True)
class PredicateDefinition:
    name: str
    value_type: StatementValueType
    cardinality: PredicateCardinality

    def __post_init__(self) -> None:
        _non_empty(self.name, "predicate")
        object.__setattr__(
            self,
            "value_type",
            StatementValueType(self.value_type),
        )
        object.__setattr__(
            self,
            "cardinality",
            PredicateCardinality(self.cardinality),
        )


@dataclass(frozen=True, slots=True)
class StatementDraft:
    predicate: str
    value: TypedStatementValue
    evidence: Evidence
    confidence: float | None = None

    def __post_init__(self) -> None:
        _non_empty(self.predicate, "predicate")
        if self.confidence is not None:
            if (
                type(self.confidence) is not float
                or not math.isfinite(self.confidence)
                or not 0.0 <= self.confidence <= 1.0
            ):
                raise ObservationValidationError(
                    "confidence must be NULL or a finite float in [0, 1]"
                )


@dataclass(frozen=True, slots=True)
class ObservationBatch:
    subject_resource_ref: str
    generator: GeneratorIdentity
    covered_predicates: tuple[str, ...]
    input_fingerprint: str
    statements: tuple[StatementDraft, ...]

    def __post_init__(self) -> None:
        from .predicates import get_predicate

        asset_id = parse_resource_ref(self.subject_resource_ref)
        if format_resource_ref(asset_id) != self.subject_resource_ref:
            raise ObservationValidationError(
                "subject_resource_ref must be canonical"
            )
        covered = tuple(self.covered_predicates)
        statements = tuple(self.statements)
        object.__setattr__(self, "covered_predicates", covered)
        object.__setattr__(self, "statements", statements)
        if not covered or len(set(covered)) != len(covered):
            raise ObservationValidationError(
                "covered_predicates must be non-empty and unique"
            )
        definitions = {name: get_predicate(name) for name in covered}
        if not re.fullmatch(r"[0-9a-f]{64}", self.input_fingerprint):
            raise ObservationValidationError(
                "input_fingerprint must be a SHA-256 hex digest"
            )
        _validate_statement_set(definitions, statements)


def _validate_statement_set(
    definitions: Mapping[str, PredicateDefinition],
    statements: tuple[StatementDraft, ...],
) -> None:
        counts: dict[str, int] = {}
        normalized_values: set[tuple[str, StatementValueType, object]] = set()
        for statement in statements:
            if statement.predicate not in definitions:
                raise ObservationValidationError(
                    "Statement predicate is not covered by the batch"
                )
            definition = definitions[statement.predicate]
            if statement.value.value_type is not definition.value_type:
                raise ObservationValidationError(
                    "Statement value type does not match predicate"
                )
            counts[statement.predicate] = counts.get(statement.predicate, 0) + 1
            key = (
                statement.predicate,
                statement.value.value_type,
                statement.value.value,
            )
            if key in normalized_values:
                raise ObservationValidationError(
                    "Duplicate statement value in batch"
                )
            normalized_values.add(key)
        for predicate, count in counts.items():
            if (
                definitions[predicate].cardinality
                is PredicateCardinality.SINGLE
                and count > 1
            ):
                raise ObservationValidationError(
                    "Single-cardinality predicate has multiple values"
                )


FrozenMetadata: TypeAlias = Mapping[str, object]


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class EnrichmentSource:
    source_id: str
    provider: str
    metadata: FrozenMetadata
    provider_locator: str | None = field(default=None, repr=False)
    blob_sha256: str | None = field(default=None, repr=False)
    size: int | None = field(default=None, repr=False)
    mime_type: str | None = field(default=None, repr=False)
    path: str | None = field(default=None, repr=False)
    name: str | None = field(default=None, repr=False)
    version_tag: str | None = field(default=None, repr=False)
    is_active: bool = field(default=True, repr=False)
    observation_scope_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _non_empty(self.source_id, "source_id")
        _non_empty(self.provider, "provider")
        if self.provider_locator is not None:
            _non_empty(self.provider_locator, "provider_locator")
        if type(self.is_active) is not bool:
            raise ObservationValidationError("is_active must be boolean")
        if self.observation_scope_id is not None:
            _non_empty(self.observation_scope_id, "observation_scope_id")
        object.__setattr__(self, "metadata", _freeze(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class EnrichmentResource:
    resource_ref: str
    sources: tuple[EnrichmentSource, ...]

    def __post_init__(self) -> None:
        parse_resource_ref(self.resource_ref)
        object.__setattr__(self, "sources", tuple(self.sources))


@dataclass(frozen=True, slots=True)
class EnrichmentState:
    subject_resource_ref: str
    generator: GeneratorIdentity
    input_fingerprint: str
    status: EnrichmentStatus
    started_at: datetime
    completed_at: datetime | None
    updated_at: datetime
    error_code: str | None
    error_message: str | None


@dataclass(frozen=True, slots=True)
class PublishResult:
    statement_writes: int
    deactivated_statements: int


@dataclass(frozen=True, slots=True)
class StatementView:
    subject_resource_ref: str
    predicate: str
    value_type: StatementValueType
    value: StatementScalar
    generator: GeneratorIdentity
    evidence: Evidence
    confidence: float | None
    created_at: datetime
    is_current: bool


@dataclass(frozen=True, slots=True)
class WorkerResult:
    discovered: int
    processed: int
    skipped: int
    failed: int
    statement_writes: int
    deactivated_statements: int
