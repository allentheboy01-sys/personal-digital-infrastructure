from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, event

from pdi.database import create_postgres_engine
from pdi.repository import PostgreSQLRepository
from pdi.repository.orm.asset import AssetORM
from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.blob import BlobORM
from pdi.resource_access import ResourceAccessSource, TextResourceAccessSource
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[3]


def _alembic_config(connection: Connection) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    return config


def test_postgres_resource_access_mapping_is_read_only_and_detached() -> None:
    engine = create_postgres_engine(require_safe_test_database_url())
    with engine.connect() as connection:
        command.upgrade(_alembic_config(connection), "head")

    now = datetime.now(UTC)
    asset_ids = {name: uuid4() for name in (
        "eligible",
        "no_source",
        "ambiguous",
    )}
    blob_ids = {name: uuid4() for name in (
        "eligible",
        "video",
        "inactive",
        "nextcloud",
        "nextcloud_text",
        "ambiguous_a",
        "ambiguous_b",
    )}
    source_ids = {name: uuid4() for name in blob_ids}
    locators = {name: str(uuid4()) for name in blob_ids}

    with engine.begin() as connection:
        connection.execute(
            AssetORM.__table__.insert(),
            [
                {
                    "id": asset_id,
                    "resource_type": "file",
                    "title": f"resource-access-{name}",
                    "metadata": {},
                    "created_at": now,
                    "updated_at": now,
                }
                for name, asset_id in asset_ids.items()
            ],
        )
        connection.execute(
            BlobORM.__table__.insert(),
            [
                {
                    "id": blob_ids[name],
                    "asset_id": (
                        asset_ids["ambiguous"]
                        if name.startswith("ambiguous")
                        else asset_ids["eligible"]
                    ),
                    "hash": (
                        "a" * 64
                        if name == "nextcloud_text"
                        else "b" * 64
                        if name == "nextcloud"
                        else f"resource-access-{uuid4()}"
                    ),
                    "size": 100,
                    "mime_type": (
                        "application/octet-stream"
                        if name == "nextcloud_text"
                        else "image/jpeg"
                    ),
                }
                for name in blob_ids
            ],
        )
        connection.execute(
            AssetSourceORM.__table__.insert(),
            [
                {
                    "id": source_ids[name],
                    "blob_id": blob_ids[name],
                    "provider": (
                        "nextcloud"
                        if name in {"nextcloud", "nextcloud_text"}
                        else "immich"
                    ),
                    "external_id": locators[name],
                    "path": f"/resource-access/{name}",
                    "name": f"{name}.jpg",
                    "version_tag": "1",
                    "provider_mime_type": (
                        "video/mp4"
                        if name == "video"
                        else "text/markdown"
                        if name == "nextcloud_text"
                        else "application/octet-stream"
                        if name == "nextcloud"
                        else None
                    ),
                    "metadata": {},
                    "is_active": name != "inactive",
                    "deleted_at": now if name == "inactive" else None,
                }
                for name in source_ids
            ],
        )

    statements: list[str] = []

    def capture(
        conn,
        cursor,
        statement,
        parameters,
        context,
        executemany,
    ) -> None:
        del conn, cursor, parameters, context, executemany
        statements.append(statement.strip().upper())

    event.listen(engine, "before_cursor_execute", capture)
    try:
        repository = PostgreSQLRepository(engine)
        eligible = repository.resolve_access_sources(
            str(asset_ids["eligible"])
        )
        no_source = repository.resolve_access_sources(
            str(asset_ids["no_source"])
        )
        ambiguous = repository.resolve_access_sources(
            str(asset_ids["ambiguous"])
        )
        text_sources = repository.resolve_text_access_sources(
            str(asset_ids["eligible"])
        )
        missing = repository.resolve_access_sources(str(uuid4()))
        missing_text = repository.resolve_text_access_sources(str(uuid4()))

        assert eligible is not None and set(eligible) == {
            ResourceAccessSource(
                source_id=str(source_ids["eligible"]),
                provider="immich",
                provider_locator=locators["eligible"],
                resource_type="file",
                mime_type="image/jpeg",
            ),
            ResourceAccessSource(
                source_id=str(source_ids["video"]),
                provider="immich",
                provider_locator=locators["video"],
                resource_type="file",
                mime_type="video/mp4",
            ),
        }
        assert no_source == ()
        assert ambiguous is not None and len(ambiguous) == 2
        assert {item.provider_locator for item in ambiguous} == {
            locators["ambiguous_a"],
            locators["ambiguous_b"],
        }
        assert missing is None
        assert text_sources is not None and set(text_sources) == {
            TextResourceAccessSource(
                source_id=str(source_ids["nextcloud"]),
                provider="nextcloud",
                provider_locator="/resource-access/nextcloud",
                resource_type="file",
                mime_type="application/octet-stream",
                size_bytes=100,
                blob_sha256="b" * 64,
                version_tag="1",
                observation_scope_id=None,
            ),
            TextResourceAccessSource(
                source_id=str(source_ids["nextcloud_text"]),
                provider="nextcloud",
                provider_locator="/resource-access/nextcloud_text",
                resource_type="file",
                mime_type="text/markdown",
                size_bytes=100,
                blob_sha256="a" * 64,
                version_tag="1",
                observation_scope_id=None,
            ),
        }
        assert missing_text is None
        assert all(isinstance(item, ResourceAccessSource) for item in ambiguous)
        assert all(
            statement.startswith("SELECT")
            for statement in statements
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
        with engine.begin() as connection:
            connection.execute(
                AssetSourceORM.__table__.delete().where(
                    AssetSourceORM.id.in_(source_ids.values())
                )
            )
            connection.execute(
                BlobORM.__table__.delete().where(
                    BlobORM.id.in_(blob_ids.values())
                )
            )
            connection.execute(
                AssetORM.__table__.delete().where(
                    AssetORM.id.in_(asset_ids.values())
                )
            )
        engine.dispose()
