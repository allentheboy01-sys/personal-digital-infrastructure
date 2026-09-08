from abc import ABC, abstractmethod
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Engine, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from pdi.repository.orm.provider_identity import ObservationScopeORM
from pdi.repository.orm.scope_sync_state import (
    ObservationScopeSyncStateORM,
)

from .models import ScopeSyncState, validate_mechanism


class ScopeSyncStateScopeNotFoundError(RuntimeError):
    """The Observation Scope does not exist in this Personal DB."""


class ScopeSyncStateRepository(ABC):
    @abstractmethod
    def read(
        self, observation_scope_id: UUID, mechanism: str
    ) -> ScopeSyncState | None:
        raise NotImplementedError

    @abstractmethod
    def get_or_create(
        self, observation_scope_id: UUID, mechanism: str
    ) -> ScopeSyncState:
        raise NotImplementedError

    @abstractmethod
    def compare_and_swap_checkpoint(
        self,
        observation_scope_id: UUID,
        mechanism: str,
        *,
        expected_version: int,
        checkpoint: str,
    ) -> ScopeSyncState | None:
        raise NotImplementedError

    @abstractmethod
    def mark_reconciliation_required(
        self,
        observation_scope_id: UUID,
        mechanism: str,
        *,
        expected_version: int,
    ) -> ScopeSyncState | None:
        raise NotImplementedError

    @abstractmethod
    def recover_after_reconciliation(
        self,
        observation_scope_id: UUID,
        mechanism: str,
        *,
        expected_version: int,
        trusted_checkpoint: str,
    ) -> ScopeSyncState | None:
        raise NotImplementedError


class PostgreSQLScopeSyncStateRepository(ScopeSyncStateRepository):
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(
            bind=engine, class_=Session, expire_on_commit=False
        )

    @staticmethod
    def _to_domain(row: ObservationScopeSyncStateORM) -> ScopeSyncState:
        return ScopeSyncState(
            observation_scope_id=row.observation_scope_id,
            mechanism=row.mechanism,
            checkpoint=row.checkpoint,
            version=row.version,
            reconciliation_required=row.reconciliation_required,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def read(
        self, observation_scope_id: UUID, mechanism: str
    ) -> ScopeSyncState | None:
        mechanism = validate_mechanism(mechanism)
        with self._session_factory() as session:
            row = session.get(
                ObservationScopeSyncStateORM,
                (observation_scope_id, mechanism),
            )
            return None if row is None else self._to_domain(row)

    def get_or_create(
        self, observation_scope_id: UUID, mechanism: str
    ) -> ScopeSyncState:
        mechanism = validate_mechanism(mechanism)
        existing = self.read(observation_scope_id, mechanism)
        if existing is not None:
            return existing
        now = datetime.now(UTC)
        row = ObservationScopeSyncStateORM(
            observation_scope_id=observation_scope_id,
            mechanism=mechanism,
            checkpoint=None,
            version=0,
            reconciliation_required=False,
            created_at=now,
            updated_at=now,
        )
        with self._session_factory() as session:
            if session.get(ObservationScopeORM, observation_scope_id) is None:
                raise ScopeSyncStateScopeNotFoundError(
                    "Observation Scope does not exist"
                )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                concurrent = session.get(
                    ObservationScopeSyncStateORM,
                    (observation_scope_id, mechanism),
                )
                if concurrent is None:
                    raise
                return self._to_domain(concurrent)
            return self._to_domain(row)

    def _cas(
        self,
        observation_scope_id: UUID,
        mechanism: str,
        *,
        expected_version: int,
        values: dict[str, object],
        expected_reconciliation_required: bool | None = None,
    ) -> ScopeSyncState | None:
        mechanism = validate_mechanism(mechanism)
        with self._session_factory() as session:
            statement = update(ObservationScopeSyncStateORM).where(
                ObservationScopeSyncStateORM.observation_scope_id
                == observation_scope_id,
                ObservationScopeSyncStateORM.mechanism == mechanism,
                ObservationScopeSyncStateORM.version == expected_version,
            )
            if expected_reconciliation_required is not None:
                statement = statement.where(
                    ObservationScopeSyncStateORM.reconciliation_required
                    == expected_reconciliation_required
                )
            row = session.execute(
                statement.values(
                    **values,
                    version=expected_version + 1,
                    updated_at=datetime.now(UTC),
                ).returning(ObservationScopeSyncStateORM)
            ).scalar_one_or_none()
            if row is None:
                session.rollback()
                return None
            session.commit()
            return self._to_domain(row)

    def compare_and_swap_checkpoint(
        self,
        observation_scope_id: UUID,
        mechanism: str,
        *,
        expected_version: int,
        checkpoint: str,
    ) -> ScopeSyncState | None:
        self._validate_checkpoint(checkpoint)
        return self._cas(
            observation_scope_id,
            mechanism,
            expected_version=expected_version,
            values={"checkpoint": checkpoint},
            expected_reconciliation_required=False,
        )

    def mark_reconciliation_required(
        self,
        observation_scope_id: UUID,
        mechanism: str,
        *,
        expected_version: int,
    ) -> ScopeSyncState | None:
        return self._cas(
            observation_scope_id,
            mechanism,
            expected_version=expected_version,
            values={"reconciliation_required": True},
        )

    def recover_after_reconciliation(
        self,
        observation_scope_id: UUID,
        mechanism: str,
        *,
        expected_version: int,
        trusted_checkpoint: str,
    ) -> ScopeSyncState | None:
        self._validate_checkpoint(trusted_checkpoint)
        return self._cas(
            observation_scope_id,
            mechanism,
            expected_version=expected_version,
            values={
                "checkpoint": trusted_checkpoint,
                "reconciliation_required": False,
            },
            expected_reconciliation_required=True,
        )

    @staticmethod
    def _validate_checkpoint(checkpoint: str) -> None:
        if not isinstance(checkpoint, str) or not checkpoint:
            raise ValueError(
                "A trusted checkpoint must be a non-empty string"
            )
