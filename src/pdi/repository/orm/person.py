from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Text, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class PersonORM(Base):
    __tablename__ = "persons"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class PersonSourceORM(Base):
    __tablename__ = "person_sources"
    __table_args__ = (
        CheckConstraint(
            "btrim(provider) <> ''",
            name="ck_person_sources_provider_nonempty",
        ),
        CheckConstraint(
            "btrim(external_id) <> ''",
            name="ck_person_sources_external_id_nonempty",
        ),
        CheckConstraint(
            "display_name IS NULL OR btrim(display_name) <> ''",
            name="ck_person_sources_display_name_nonempty",
        ),
    )

    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    external_id: Mapped[str] = mapped_column(Text, primary_key=True)
    person_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "persons.id",
            ondelete="RESTRICT",
            name="fk_person_sources_person",
        ),
        nullable=False,
    )
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    inactive_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


Index(
    "ix_person_sources_active_display_name",
    func.lower(PersonSourceORM.display_name),
    PersonSourceORM.person_id,
    postgresql_where=(
        PersonSourceORM.inactive_at.is_(None)
        & PersonSourceORM.display_name.is_not(None)
    ),
)


class ObservationScopePersonSourceORM(Base):
    __tablename__ = "observation_scope_person_sources"
    __table_args__ = (
        CheckConstraint(
            "btrim(external_id) <> ''",
            name="ck_observation_scope_person_sources_external_id_nonempty",
        ),
        CheckConstraint(
            "display_name IS NULL OR btrim(display_name) <> ''",
            name="ck_observation_scope_person_sources_display_name_nonempty",
        ),
    )

    observation_scope_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "observation_scopes.id",
            ondelete="RESTRICT",
            name="fk_observation_scope_person_sources_scope",
        ),
        primary_key=True,
    )
    external_id: Mapped[str] = mapped_column(Text, primary_key=True)
    person_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "persons.id",
            ondelete="RESTRICT",
            name="fk_observation_scope_person_sources_person",
        ),
        nullable=False,
    )
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    inactive_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


Index(
    "ix_scope_person_sources_active_display_name",
    func.lower(ObservationScopePersonSourceORM.display_name),
    ObservationScopePersonSourceORM.person_id,
    postgresql_where=(
        ObservationScopePersonSourceORM.inactive_at.is_(None)
        & ObservationScopePersonSourceORM.display_name.is_not(None)
    ),
)
