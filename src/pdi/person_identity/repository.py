from collections.abc import Iterable
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Engine, text, update
from sqlalchemy.orm import Session, sessionmaker

from pdi.repository.orm.person import (
    ObservationScopePersonSourceORM,
    PersonORM,
    PersonSourceORM,
)

from .models import (
    Person,
    PersonSource,
    ScopedPersonSource,
    PersonSyncResult,
    ProviderPersonIdentity,
    utc_instant,
)


class PersonRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(
            bind=engine,
            class_=Session,
            expire_on_commit=False,
        )

    @staticmethod
    def _validate_identity(provider: str, external_id: str) -> None:
        if not provider.strip():
            raise ValueError("provider must be non-empty")
        if not external_id.strip():
            raise ValueError("external_id must be non-empty")

    @staticmethod
    def _lock_identity(
        session: Session, provider: str, external_id: str
    ) -> None:
        session.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtextextended(:identity, 0))"
            ),
            {"identity": f"{len(provider)}:{provider}{external_id}"},
        )

    @staticmethod
    def _to_source(row: PersonSourceORM) -> PersonSource:
        return PersonSource(
            provider=row.provider,
            external_id=row.external_id,
            person_id=row.person_id,
            display_name=row.display_name,
            inactive_at=row.inactive_at,
        )

    @staticmethod
    def _resolve_in_session(
        session: Session,
        provider: str,
        external_id: str,
        now: datetime,
    ) -> tuple[PersonSourceORM, str]:
        PersonRepository._validate_identity(provider, external_id)
        PersonRepository._lock_identity(session, provider, external_id)
        source = session.get(PersonSourceORM, (provider, external_id))
        if source is not None:
            if source.inactive_at is not None:
                source.inactive_at = None
                return source, "reactivated"
            return source, "existing"

        person = PersonORM(id=uuid4(), created_at=now)
        source = PersonSourceORM(
            provider=provider,
            external_id=external_id,
            person_id=person.id,
            display_name=None,
            inactive_at=None,
        )
        session.add_all((person, source))
        return source, "created"

    def get_or_create_source(
        self,
        provider: str,
        external_id: str,
        *,
        now: datetime | None = None,
    ) -> PersonSource:
        instant = utc_instant(now or datetime.now(UTC))
        with self._session_factory.begin() as session:
            source, _ = self._resolve_in_session(
                session, provider, external_id, instant
            )
        return self._to_source(source)

    def reconcile_inventory(
        self,
        provider: str,
        identities: Iterable[ProviderPersonIdentity],
        *,
        now: datetime | None = None,
    ) -> PersonSyncResult:
        if not provider.strip():
            raise ValueError("provider must be non-empty")
        identities = tuple(identities)
        external_ids = tuple(
            identity.external_id for identity in identities
        )
        if len(set(external_ids)) != len(external_ids):
            raise ValueError("enumerable inventory contains duplicate IDs")
        instant = utc_instant(now or datetime.now(UTC))
        counts = {"created": 0, "existing": 0, "reactivated": 0}

        with self._session_factory.begin() as session:
            session.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtextextended(:provider, 0))"
                ),
                {"provider": f"person-inventory:{provider}"},
            )
            labels_updated = 0
            for identity in identities:
                source, outcome = self._resolve_in_session(
                    session, provider, identity.external_id, instant
                )
                counts[outcome] += 1
                if source.display_name != identity.display_name:
                    source.display_name = identity.display_name
                    labels_updated += 1

            statement = update(PersonSourceORM).where(
                PersonSourceORM.provider == provider,
                PersonSourceORM.inactive_at.is_(None),
            )
            if external_ids:
                statement = statement.where(
                    PersonSourceORM.external_id.not_in(external_ids)
                )
            inactivated = session.execute(
                statement.values(inactive_at=instant)
            ).rowcount

        return PersonSyncResult(
            discovered=len(identities),
            created=counts["created"],
            existing=counts["existing"],
            reactivated=counts["reactivated"],
            inactivated=inactivated,
            labels_updated=labels_updated,
        )

    def find_source(
        self, provider: str, external_id: str
    ) -> PersonSource | None:
        with self._session_factory() as session:
            row = session.get(PersonSourceORM, (provider, external_id))
            return self._to_source(row) if row is not None else None

    def get_person(self, person_id) -> Person | None:
        with self._session_factory() as session:
            row = session.get(PersonORM, person_id)
            if row is None:
                return None
            return Person(id=row.id, created_at=row.created_at)


class ScopedPersonRepository:
    """Person observations permanently bound to one Observation Scope."""

    def __init__(self, engine: Engine, observation_scope_id) -> None:
        self.observation_scope_id = observation_scope_id
        self._session_factory = sessionmaker(
            bind=engine, class_=Session, expire_on_commit=False
        )

    @staticmethod
    def _to_source(row: ObservationScopePersonSourceORM) -> ScopedPersonSource:
        return ScopedPersonSource(
            observation_scope_id=row.observation_scope_id,
            external_id=row.external_id,
            person_id=row.person_id,
            display_name=row.display_name,
            inactive_at=row.inactive_at,
        )

    def _resolve(
        self, session: Session, external_id: str, now: datetime
    ) -> tuple[ObservationScopePersonSourceORM, str]:
        if not isinstance(external_id, str) or not external_id.strip():
            raise ValueError("external_id must be non-empty")
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:identity, 0))"),
            {
                "identity": (
                    f"scoped-person:{self.observation_scope_id}:{external_id}"
                )
            },
        )
        row = session.get(
            ObservationScopePersonSourceORM,
            (self.observation_scope_id, external_id),
        )
        if row is not None:
            if row.inactive_at is not None:
                row.inactive_at = None
                return row, "reactivated"
            return row, "existing"
        person = PersonORM(id=uuid4(), created_at=now)
        session.add(person)
        session.flush()
        row = ObservationScopePersonSourceORM(
            observation_scope_id=self.observation_scope_id,
            external_id=external_id,
            person_id=person.id,
            display_name=None,
            inactive_at=None,
        )
        session.add(row)
        return row, "created"

    def get_or_create_source(
        self, external_id: str, *, now: datetime | None = None
    ) -> ScopedPersonSource:
        instant = utc_instant(now or datetime.now(UTC))
        with self._session_factory.begin() as session:
            row, _ = self._resolve(session, external_id, instant)
        return self._to_source(row)

    def find_source(self, external_id: str) -> ScopedPersonSource | None:
        with self._session_factory() as session:
            row = session.get(
                ObservationScopePersonSourceORM,
                (self.observation_scope_id, external_id),
            )
            return self._to_source(row) if row is not None else None

    def reconcile_inventory(
        self,
        identities: Iterable[ProviderPersonIdentity],
        *,
        now: datetime | None = None,
    ) -> PersonSyncResult:
        identities = tuple(identities)
        external_ids = tuple(item.external_id for item in identities)
        if len(set(external_ids)) != len(external_ids):
            raise ValueError("enumerable inventory contains duplicate IDs")
        instant = utc_instant(now or datetime.now(UTC))
        counts = {"created": 0, "existing": 0, "reactivated": 0}
        with self._session_factory.begin() as session:
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"scoped-person-inventory:{self.observation_scope_id}"},
            )
            labels_updated = 0
            for identity in identities:
                row, outcome = self._resolve(session, identity.external_id, instant)
                counts[outcome] += 1
                if row.display_name != identity.display_name:
                    row.display_name = identity.display_name
                    labels_updated += 1
            statement = update(ObservationScopePersonSourceORM).where(
                ObservationScopePersonSourceORM.observation_scope_id
                == self.observation_scope_id,
                ObservationScopePersonSourceORM.inactive_at.is_(None),
            )
            if external_ids:
                statement = statement.where(
                    ObservationScopePersonSourceORM.external_id.not_in(external_ids)
                )
            inactivated = session.execute(
                statement.values(inactive_at=instant)
            ).rowcount
        return PersonSyncResult(
            discovered=len(identities),
            created=counts["created"],
            existing=counts["existing"],
            reactivated=counts["reactivated"],
            inactivated=inactivated,
            labels_updated=labels_updated,
        )
