from collections.abc import Sequence
from datetime import UTC, datetime
import re
from uuid import UUID, uuid4

from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, aliased, sessionmaker

from pdi.repository.orm.pipeline_run import PipelineRunORM

from .models import (
    PipelineErrorCode,
    PipelineKind,
    PipelineRun,
    PipelineStatus,
)


class PipelineRunLifecycleError(RuntimeError):
    pass


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _utc_instant(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("pipeline run timestamp must be timezone-aware")
    return value.astimezone(UTC)


class PipelineRunRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(
            bind=engine,
            class_=Session,
            expire_on_commit=False,
        )

    @staticmethod
    def _to_domain(row: PipelineRunORM) -> PipelineRun:
        return PipelineRun(
            id=row.id,
            pipeline_key=row.pipeline_key,
            kind=PipelineKind(row.kind),
            status=PipelineStatus(row.status),
            started_at=row.started_at,
            finished_at=row.finished_at,
            error_code=(
                PipelineErrorCode(row.error_code)
                if row.error_code is not None
                else None
            ),
        )

    def begin_run(
        self,
        pipeline_key: str,
        kind: PipelineKind,
        *,
        started_at: datetime | None = None,
        invocation_fingerprint: str | None = None,
    ) -> PipelineRun:
        if (
            invocation_fingerprint is not None
            and (
                not isinstance(invocation_fingerprint, str)
                or _SHA256.fullmatch(invocation_fingerprint) is None
            )
        ):
            raise PipelineRunLifecycleError(
                "invocation fingerprint must be a SHA-256 digest"
            )
        row = PipelineRunORM(
            id=uuid4(),
            pipeline_key=pipeline_key,
            kind=kind.value,
            status=PipelineStatus.RUNNING.value,
            started_at=_utc_instant(started_at or datetime.now(UTC)),
            finished_at=None,
            error_code=None,
            invocation_fingerprint=invocation_fingerprint,
        )
        with self._session_factory() as session:
            session.add(row)
            session.commit()
        return self._to_domain(row)

    def _finish(
        self,
        run_id: UUID,
        *,
        status: PipelineStatus,
        error_code: PipelineErrorCode | None,
        finished_at: datetime | None,
    ) -> PipelineRun:
        terminal_at = _utc_instant(finished_at or datetime.now(UTC))
        with self._session_factory() as session:
            result = session.execute(
                update(PipelineRunORM)
                .where(
                    PipelineRunORM.id == run_id,
                    PipelineRunORM.status == PipelineStatus.RUNNING.value,
                )
                .values(
                    status=status.value,
                    finished_at=terminal_at,
                    error_code=(error_code.value if error_code else None),
                )
                .returning(PipelineRunORM)
            ).scalar_one_or_none()
            if result is None:
                session.rollback()
                raise PipelineRunLifecycleError(
                    "pipeline run is not in running state"
                )
            session.commit()
            return self._to_domain(result)

    def complete_run(
        self,
        run_id: UUID,
        *,
        finished_at: datetime | None = None,
    ) -> PipelineRun:
        return self._finish(
            run_id,
            status=PipelineStatus.COMPLETED,
            error_code=None,
            finished_at=finished_at,
        )

    def fail_run(
        self,
        run_id: UUID,
        error_code: PipelineErrorCode,
        *,
        finished_at: datetime | None = None,
    ) -> PipelineRun:
        return self._finish(
            run_id,
            status=PipelineStatus.FAILED,
            error_code=error_code,
            finished_at=finished_at,
        )

    def fail_interrupted_run(
        self,
        pipeline_key: str,
        *,
        finished_at: datetime | None = None,
    ) -> PipelineRun | None:
        terminal_at = _utc_instant(finished_at or datetime.now(UTC))
        with self._session_factory() as session:
            row = session.execute(
                select(PipelineRunORM)
                .where(
                    PipelineRunORM.pipeline_key == pipeline_key,
                    PipelineRunORM.status == PipelineStatus.RUNNING.value,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if row is None:
                session.rollback()
                return None
            row.status = PipelineStatus.FAILED.value
            row.finished_at = terminal_at
            row.error_code = PipelineErrorCode.INTERRUPTED_PREVIOUS_RUN.value
            session.commit()
            return self._to_domain(row)

    def get_latest_runs(
        self,
        pipeline_keys: Sequence[str],
    ) -> dict[str, PipelineRun]:
        if not pipeline_keys:
            return {}
        ranked = (
            select(
                PipelineRunORM,
                func.row_number()
                .over(
                    partition_by=PipelineRunORM.pipeline_key,
                    order_by=(
                        PipelineRunORM.started_at.desc(),
                        PipelineRunORM.id.asc(),
                    ),
                )
                .label("rank"),
            )
            .where(PipelineRunORM.pipeline_key.in_(tuple(pipeline_keys)))
            .subquery()
        )
        latest = aliased(PipelineRunORM, ranked)
        with self._session_factory() as session:
            rows = session.execute(
                select(latest).where(ranked.c.rank == 1)
            ).scalars()
            return {
                row.pipeline_key: self._to_domain(row)
                for row in rows
            }

    def get_last_successes(
        self,
        pipeline_keys: Sequence[str],
    ) -> dict[str, datetime]:
        if not pipeline_keys:
            return {}
        with self._session_factory() as session:
            rows = session.execute(
                select(
                    PipelineRunORM.pipeline_key,
                    func.max(PipelineRunORM.finished_at),
                )
                .where(
                    PipelineRunORM.pipeline_key.in_(tuple(pipeline_keys)),
                    PipelineRunORM.status == PipelineStatus.COMPLETED.value,
                )
                .group_by(PipelineRunORM.pipeline_key)
            ).all()
            return {key: finished_at for key, finished_at in rows}
