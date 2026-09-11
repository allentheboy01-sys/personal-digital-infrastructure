"""Administrative transition of legacy Person and relation observations.

Planning is read-only. Applying a plan locks the legacy inventories, validates
the complete Provider-to-Scope mapping, and commits all target rows atomically.
Legacy rows are deliberately retained.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Engine, exists, select
from sqlalchemy.orm import Session

from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.blob import BlobORM
from pdi.repository.orm.person import (
    ObservationScopePersonSourceORM,
    PersonSourceORM,
)
from pdi.repository.orm.provider_identity import (
    ObservationScopeORM,
    ProviderInstanceORM,
)
from pdi.repository.orm.resource_person_relation import (
    ObservationScopeResourcePersonRelationORM,
    ResourcePersonRelationORM,
)


class DerivedTransitionError(RuntimeError):
    """The requested transition is incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class DerivedTransitionPlan:
    examined: int
    would_create: int
    already_equivalent: int
    conflicts: int = 0
    providers_without_mapping: tuple[str, ...] = ()
    invalid_scope_mappings: int = 0
    missing_resource_scope_evidence: int = 0
    missing_person_scope_evidence: int = 0

    @property
    def ready(self) -> bool:
        return not any((
            self.conflicts,
            self.providers_without_mapping,
            self.invalid_scope_mappings,
            self.missing_resource_scope_evidence,
            self.missing_person_scope_evidence,
        ))


def _scopes(
    session: Session,
    providers: set[str],
    mapping: Mapping[str, UUID],
) -> tuple[dict[str, UUID], tuple[str, ...], int]:
    missing = tuple(sorted(providers - set(mapping)))
    resolved: dict[str, UUID] = {}
    invalid = 0
    for provider in sorted(providers & set(mapping)):
        scope = session.get(ObservationScopeORM, mapping[provider])
        instance = (
            None
            if scope is None
            else session.get(ProviderInstanceORM, scope.provider_instance_id)
        )
        if instance is None or instance.provider_type != provider:
            invalid += 1
        else:
            resolved[provider] = scope.id
    return resolved, missing, invalid


def _person_plan(
    session: Session,
    mapping: Mapping[str, UUID],
    *,
    lock: bool,
) -> tuple[DerivedTransitionPlan, list[ObservationScopePersonSourceORM]]:
    statement = select(PersonSourceORM)
    if lock:
        statement = statement.with_for_update()
    rows = list(session.execute(statement).scalars())
    scopes, missing, invalid = _scopes(
        session, {row.provider for row in rows}, mapping
    )
    creates: list[ObservationScopePersonSourceORM] = []
    equivalent = conflicts = 0
    for row in rows:
        scope_id = scopes.get(row.provider)
        if scope_id is None:
            continue
        existing = session.get(
            ObservationScopePersonSourceORM, (scope_id, row.external_id)
        )
        if existing is None:
            creates.append(ObservationScopePersonSourceORM(
                observation_scope_id=scope_id,
                external_id=row.external_id,
                person_id=row.person_id,
                display_name=row.display_name,
                inactive_at=row.inactive_at,
            ))
        elif (
            existing.person_id == row.person_id
            and existing.display_name == row.display_name
            and existing.inactive_at == row.inactive_at
        ):
            equivalent += 1
        else:
            conflicts += 1
    return DerivedTransitionPlan(
        examined=len(rows), would_create=len(creates),
        already_equivalent=equivalent, conflicts=conflicts,
        providers_without_mapping=missing, invalid_scope_mappings=invalid,
    ), creates


def plan_legacy_person_transition(
    engine: Engine, provider_scope_ids: Mapping[str, UUID]
) -> DerivedTransitionPlan:
    with Session(engine) as session, session.begin():
        plan, _ = _person_plan(session, provider_scope_ids, lock=False)
        return plan


def transition_legacy_person_sources(
    engine: Engine, provider_scope_ids: Mapping[str, UUID]
) -> DerivedTransitionPlan:
    with Session(engine) as session, session.begin():
        plan, creates = _person_plan(session, provider_scope_ids, lock=True)
        if not plan.ready:
            raise DerivedTransitionError("Person transition plan is unsafe")
        session.add_all(creates)
        session.flush()
        return plan


def _relation_plan(
    session: Session,
    mapping: Mapping[str, UUID],
    *,
    lock: bool,
) -> tuple[DerivedTransitionPlan, list[ObservationScopeResourcePersonRelationORM]]:
    statement = select(ResourcePersonRelationORM)
    if lock:
        statement = statement.with_for_update()
    rows = list(session.execute(statement).scalars())
    scopes, missing, invalid = _scopes(
        session, {row.provider for row in rows}, mapping
    )
    creates: list[ObservationScopeResourcePersonRelationORM] = []
    equivalent = conflicts = missing_resource = missing_person = 0
    for row in rows:
        scope_id = scopes.get(row.provider)
        if scope_id is None:
            continue
        resource_evidence = session.scalar(select(exists().where(
            AssetSourceORM.observation_scope_id == scope_id,
            AssetSourceORM.blob_id == BlobORM.id,
            BlobORM.asset_id == row.resource_id,
        )))
        person_evidence = session.scalar(select(exists().where(
            ObservationScopePersonSourceORM.observation_scope_id == scope_id,
            ObservationScopePersonSourceORM.person_id == row.person_id,
        )))
        if not resource_evidence:
            missing_resource += 1
        if not person_evidence:
            missing_person += 1
        if not resource_evidence or not person_evidence:
            continue
        identity = (scope_id, row.resource_id, row.person_id)
        existing = session.get(ObservationScopeResourcePersonRelationORM, identity)
        if existing is None:
            creates.append(ObservationScopeResourcePersonRelationORM(
                observation_scope_id=scope_id,
                resource_id=row.resource_id,
                person_id=row.person_id,
                inactive_at=row.inactive_at,
            ))
        elif existing.inactive_at == row.inactive_at:
            equivalent += 1
        else:
            conflicts += 1
    return DerivedTransitionPlan(
        examined=len(rows), would_create=len(creates),
        already_equivalent=equivalent, conflicts=conflicts,
        providers_without_mapping=missing, invalid_scope_mappings=invalid,
        missing_resource_scope_evidence=missing_resource,
        missing_person_scope_evidence=missing_person,
    ), creates


def plan_legacy_relation_transition(
    engine: Engine, provider_scope_ids: Mapping[str, UUID]
) -> DerivedTransitionPlan:
    with Session(engine) as session, session.begin():
        plan, _ = _relation_plan(session, provider_scope_ids, lock=False)
        return plan


def transition_legacy_resource_person_relations(
    engine: Engine, provider_scope_ids: Mapping[str, UUID]
) -> DerivedTransitionPlan:
    with Session(engine) as session, session.begin():
        plan, creates = _relation_plan(session, provider_scope_ids, lock=True)
        if not plan.ready:
            raise DerivedTransitionError("Relation transition plan is unsafe")
        session.add_all(creates)
        session.flush()
        return plan
