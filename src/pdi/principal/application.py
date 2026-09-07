"""Application composition bound to exactly one Personal PDI database."""

from dataclasses import dataclass

from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from pdi.database import create_postgres_engine
from pdi.query import QueryService
from pdi.repository import PostgreSQLRepository

from .models import PersonalDatabaseBinding, PrincipalId
from .errors import PersonalDatabaseUnavailableError
from .router import PrincipalDatabaseRouter


@dataclass(slots=True)
class PersonalQueryContext:
    principal_id: PrincipalId
    binding: PersonalDatabaseBinding
    engine: Engine
    query_service: QueryService

    def close(self) -> None:
        self.engine.dispose()

    def __enter__(self) -> "PersonalQueryContext":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class PersonalQueryContextFactory:
    def __init__(self, router: PrincipalDatabaseRouter) -> None:
        self._router = router

    def create(
        self,
        principal_id: PrincipalId | str | None,
    ) -> PersonalQueryContext:
        binding = self._router.resolve(principal_id)
        parsed_id = (
            principal_id
            if isinstance(principal_id, PrincipalId)
            else PrincipalId(principal_id or "")
        )
        engine = create_postgres_engine(binding.database_url)
        try:
            with engine.connect():
                pass
        except SQLAlchemyError:
            engine.dispose()
            raise PersonalDatabaseUnavailableError(
                f"Personal database is unavailable: {binding.database_ref}"
            ) from None
        repository = PostgreSQLRepository(engine)
        return PersonalQueryContext(
            principal_id=parsed_id,
            binding=binding,
            engine=engine,
            query_service=QueryService(repository),
        )
