"""PostgreSQL implementation of Provider identity persistence."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from pdi.repository.orm.provider_identity import (
    ObservationScopeORM,
    ProviderAccountORM,
    ProviderInstanceORM,
)

from .errors import (
    ProviderIdentityConflictError,
    ProviderIdentityNotFoundError,
    ProviderIdentityRelationshipError,
)
from .models import (
    ObservationScope,
    ProviderAccount,
    ProviderInstance,
    canonical_key,
    optional_label,
    utc_instant,
)


class PostgreSQLProviderIdentityRepository:
    def __init__(self, engine: Engine | Connection) -> None:
        self._session_factory = sessionmaker(
            bind=engine,
            class_=Session,
            expire_on_commit=False,
        )

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        return utc_instant(value or datetime.now(UTC), "now")

    @staticmethod
    def _instance(row: ProviderInstanceORM) -> ProviderInstance:
        return ProviderInstance(
            id=row.id,
            provider_type=row.provider_type,
            instance_key=row.instance_key,
            display_label=row.display_label,
            enabled=row.enabled,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _account(row: ProviderAccountORM) -> ProviderAccount:
        return ProviderAccount(
            id=row.id,
            provider_instance_id=row.provider_instance_id,
            account_key=row.account_key,
            provider_native_id=row.provider_native_id,
            display_label=row.display_label,
            enabled=row.enabled,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _scope(row: ObservationScopeORM) -> ObservationScope:
        return ObservationScope(
            id=row.id,
            provider_instance_id=row.provider_instance_id,
            provider_account_id=row.provider_account_id,
            scope_key=row.scope_key,
            display_label=row.display_label,
            enabled=row.enabled,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _commit_created(session: Session, row: object, identity: str) -> None:
        session.add(row)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise ProviderIdentityConflictError(
                f"Provider identity already exists: {identity}"
            ) from None

    def create_instance(
        self,
        *,
        provider_type: str,
        instance_key: str,
        display_label: str | None = None,
        enabled: bool = True,
        now: datetime | None = None,
    ) -> ProviderInstance:
        provider_type = canonical_key(provider_type, "provider_type")
        instance_key = canonical_key(instance_key, "instance_key")
        display_label = optional_label(display_label, "display_label")
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        instant = self._now(now)
        row = ProviderInstanceORM(
            id=uuid4(),
            provider_type=provider_type,
            instance_key=instance_key,
            display_label=display_label,
            enabled=enabled,
            created_at=instant,
            updated_at=instant,
        )
        with self._session_factory() as session:
            self._commit_created(session, row, instance_key)
        return self._instance(row)

    def get_instance(self, instance_id: UUID) -> ProviderInstance | None:
        with self._session_factory() as session:
            row = session.get(ProviderInstanceORM, instance_id)
            return None if row is None else self._instance(row)

    def get_instance_by_key(self, instance_key: str) -> ProviderInstance | None:
        instance_key = canonical_key(instance_key, "instance_key")
        with self._session_factory() as session:
            row = session.execute(
                select(ProviderInstanceORM).where(
                    ProviderInstanceORM.instance_key == instance_key
                )
            ).scalar_one_or_none()
            return None if row is None else self._instance(row)

    def list_instances(self) -> tuple[ProviderInstance, ...]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ProviderInstanceORM).order_by(
                    ProviderInstanceORM.instance_key
                )
            ).scalars()
            return tuple(self._instance(row) for row in rows)

    def set_instance_enabled(
        self,
        instance_id: UUID,
        enabled: bool,
        *,
        now: datetime | None = None,
    ) -> ProviderInstance:
        return self._set_enabled(
            ProviderInstanceORM,
            instance_id,
            enabled,
            now,
            self._instance,
        )

    def create_account(
        self,
        *,
        provider_instance_id: UUID,
        account_key: str,
        provider_native_id: str | None = None,
        display_label: str | None = None,
        enabled: bool = True,
        now: datetime | None = None,
    ) -> ProviderAccount:
        account_key = canonical_key(account_key, "account_key")
        provider_native_id = optional_label(
            provider_native_id, "provider_native_id"
        )
        display_label = optional_label(display_label, "display_label")
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        instant = self._now(now)
        with self._session_factory() as session:
            if session.get(ProviderInstanceORM, provider_instance_id) is None:
                raise ProviderIdentityNotFoundError(
                    "Provider Instance does not exist"
                )
            row = ProviderAccountORM(
                id=uuid4(),
                provider_instance_id=provider_instance_id,
                account_key=account_key,
                provider_native_id=provider_native_id,
                display_label=display_label,
                enabled=enabled,
                created_at=instant,
                updated_at=instant,
            )
            self._commit_created(session, row, account_key)
        return self._account(row)

    def get_account(self, account_id: UUID) -> ProviderAccount | None:
        with self._session_factory() as session:
            row = session.get(ProviderAccountORM, account_id)
            return None if row is None else self._account(row)

    def get_account_by_key(
        self, provider_instance_id: UUID, account_key: str
    ) -> ProviderAccount | None:
        account_key = canonical_key(account_key, "account_key")
        with self._session_factory() as session:
            row = session.execute(
                select(ProviderAccountORM).where(
                    ProviderAccountORM.provider_instance_id
                    == provider_instance_id,
                    ProviderAccountORM.account_key == account_key,
                )
            ).scalar_one_or_none()
            return None if row is None else self._account(row)

    def list_accounts_for_instance(
        self, provider_instance_id: UUID
    ) -> tuple[ProviderAccount, ...]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ProviderAccountORM)
                .where(
                    ProviderAccountORM.provider_instance_id
                    == provider_instance_id
                )
                .order_by(ProviderAccountORM.account_key)
            ).scalars()
            return tuple(self._account(row) for row in rows)

    def set_account_enabled(
        self,
        account_id: UUID,
        enabled: bool,
        *,
        now: datetime | None = None,
    ) -> ProviderAccount:
        return self._set_enabled(
            ProviderAccountORM,
            account_id,
            enabled,
            now,
            self._account,
        )

    def create_scope(
        self,
        *,
        provider_instance_id: UUID,
        scope_key: str,
        provider_account_id: UUID | None = None,
        display_label: str | None = None,
        enabled: bool = True,
        now: datetime | None = None,
    ) -> ObservationScope:
        scope_key = canonical_key(scope_key, "scope_key")
        display_label = optional_label(display_label, "display_label")
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        instant = self._now(now)
        with self._session_factory() as session:
            if session.get(ProviderInstanceORM, provider_instance_id) is None:
                raise ProviderIdentityNotFoundError(
                    "Provider Instance does not exist"
                )
            if provider_account_id is not None:
                account = session.get(ProviderAccountORM, provider_account_id)
                if account is None:
                    raise ProviderIdentityNotFoundError(
                        "Provider Account does not exist"
                    )
                if account.provider_instance_id != provider_instance_id:
                    raise ProviderIdentityRelationshipError(
                        "Provider Account belongs to a different Instance"
                    )
            row = ObservationScopeORM(
                id=uuid4(),
                provider_instance_id=provider_instance_id,
                provider_account_id=provider_account_id,
                scope_key=scope_key,
                display_label=display_label,
                enabled=enabled,
                created_at=instant,
                updated_at=instant,
            )
            self._commit_created(session, row, scope_key)
        return self._scope(row)

    def get_scope(self, scope_id: UUID) -> ObservationScope | None:
        with self._session_factory() as session:
            row = session.get(ObservationScopeORM, scope_id)
            return None if row is None else self._scope(row)

    def get_scope_by_key(
        self, provider_instance_id: UUID, scope_key: str
    ) -> ObservationScope | None:
        scope_key = canonical_key(scope_key, "scope_key")
        with self._session_factory() as session:
            row = session.execute(
                select(ObservationScopeORM).where(
                    ObservationScopeORM.provider_instance_id
                    == provider_instance_id,
                    ObservationScopeORM.scope_key == scope_key,
                )
            ).scalar_one_or_none()
            return None if row is None else self._scope(row)

    def list_scopes_for_instance(
        self, provider_instance_id: UUID
    ) -> tuple[ObservationScope, ...]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ObservationScopeORM)
                .where(
                    ObservationScopeORM.provider_instance_id
                    == provider_instance_id
                )
                .order_by(ObservationScopeORM.scope_key)
            ).scalars()
            return tuple(self._scope(row) for row in rows)

    def list_scopes_for_account(
        self, provider_account_id: UUID
    ) -> tuple[ObservationScope, ...]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ObservationScopeORM)
                .where(
                    ObservationScopeORM.provider_account_id
                    == provider_account_id
                )
                .order_by(ObservationScopeORM.scope_key)
            ).scalars()
            return tuple(self._scope(row) for row in rows)

    def set_scope_enabled(
        self,
        scope_id: UUID,
        enabled: bool,
        *,
        now: datetime | None = None,
    ) -> ObservationScope:
        return self._set_enabled(
            ObservationScopeORM,
            scope_id,
            enabled,
            now,
            self._scope,
        )

    def _set_enabled(
        self,
        orm_type,
        identity: UUID,
        enabled: bool,
        now: datetime | None,
        converter,
    ):
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        with self._session_factory.begin() as session:
            row = session.get(orm_type, identity)
            if row is None:
                raise ProviderIdentityNotFoundError(
                    "Provider identity does not exist"
                )
            row.enabled = enabled
            row.updated_at = self._now(now)
        return converter(row)
