import asyncio
from datetime import UTC, datetime
from pathlib import Path
import secrets
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from pdi.principal import (
    DatabaseBindingRecord,
    DatabaseBindingRegistry,
    PersonalDatabaseProvisioner,
    PersonalDatabaseProvisioningSpec,
    PrincipalDatabaseRouter,
    PrincipalId,
    PrincipalRecord,
    PrincipalRegistry,
)
from pdi.query import format_resource_ref
from pdi.repository.orm.asset import AssetORM
from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.blob import BlobORM
from pdi.repository.orm.provider_identity import (
    ObservationScopeORM,
    ProviderInstanceORM,
)
from pdi.resource_access import ProviderRepresentation, ResourceNotFoundError
from pdi.resource_access.scoped import (
    ProviderAccessBinding,
    ProviderAccessBindingRegistry,
    ProviderAccessMaterial,
    ScopedResourceAccessRuntimeFactory,
)
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[3]


class Secrets:
    def __init__(self, values):
        self.values = values

    def resolve(self, binding_ref):
        return ProviderAccessMaterial(self.values[binding_ref])


class Adapter:
    provider = "immich"

    def __init__(self, marker):
        self.marker = marker

    async def open_representation(self, locator, kind):
        return self._response()

    async def open_video(self, locator, byte_range):
        return self._response(media_type="video/mp4")

    def _response(self, media_type="image/webp"):
        async def body():
            yield self.marker.encode()

        async def close():
            return None

        return ProviderRepresentation(
            status_code=200,
            media_type=media_type,
            content_length=str(len(self.marker)),
            etag=None,
            last_modified=None,
            body=body(),
            close=close,
        )

    async def aclose(self):
        return None


def insert_world(engine, *, instance_id, scope_id, asset_id, marker):
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            ProviderInstanceORM.__table__.insert(),
            {
                "id": instance_id,
                "provider_type": "immich",
                "instance_key": "shared-synthetic-instance",
                "enabled": True,
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            ObservationScopeORM.__table__.insert(),
            {
                "id": scope_id,
                "provider_instance_id": instance_id,
                "scope_key": "shared-synthetic-scope",
                "enabled": True,
                "created_at": now,
                "updated_at": now,
            },
        )
    insert_resource(engine, scope_id=scope_id, asset_id=asset_id, marker=marker)


def insert_resource(engine, *, scope_id, asset_id, marker):
    now = datetime.now(UTC)
    blob_id, source_id = uuid4(), uuid4()
    with engine.begin() as connection:
        connection.execute(
            AssetORM.__table__.insert(),
            {
                "id": asset_id,
                "resource_type": "file",
                "title": marker,
                "metadata": {},
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            BlobORM.__table__.insert(),
            {
                "id": blob_id,
                "asset_id": asset_id,
                "hash": f"{marker}-{uuid4()}",
                "size": len(marker),
                "mime_type": "image/jpeg",
            },
        )
        connection.execute(
            AssetSourceORM.__table__.insert(),
            {
                "id": source_id,
                "blob_id": blob_id,
                "provider": "immich",
                "external_id": str(uuid4()),
                "observation_scope_id": scope_id,
                "name": f"{marker}.jpg",
                "provider_mime_type": "image/jpeg",
                "metadata": {},
                "is_active": True,
            },
        )


async def collect(opened):
    return b"".join([chunk async for chunk in opened])


def test_same_scope_and_resource_uuid_are_isolated_by_personal_database():
    admin_url = require_safe_test_database_url()
    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=ROOT)
    specs = (
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu8h_{token}_test",
            runtime_role=f"pdi_mu3_mu8h_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu8-harry-db",
        ),
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu8m_{token}_test",
            runtime_role=f"pdi_mu3_mu8m_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu8-mother-db",
        ),
    )
    results = []
    engines = []
    try:
        results = [provisioner.provision(spec) for spec in specs]
        engines = [
            create_engine(result.binding.database_url, poolclass=NullPool)
            for result in results
        ]
        instance_id, scope_id, asset_id = uuid4(), uuid4(), uuid4()
        insert_world(
            engines[0],
            instance_id=instance_id,
            scope_id=scope_id,
            asset_id=asset_id,
            marker="harry-private",
        )
        insert_world(
            engines[1],
            instance_id=instance_id,
            scope_id=scope_id,
            asset_id=asset_id,
            marker="mother-private",
        )
        mother_only_asset_id = uuid4()
        insert_resource(
            engines[1],
            scope_id=scope_id,
            asset_id=mother_only_asset_id,
            marker="mother-only",
        )
        router = PrincipalDatabaseRouter(
            PrincipalRegistry(
                (
                    PrincipalRecord(PrincipalId("mu8-harry"), "mu8-harry-db"),
                    PrincipalRecord(PrincipalId("mu8-mother"), "mu8-mother-db"),
                )
            ),
            DatabaseBindingRegistry(
                (
                    DatabaseBindingRecord("mu8-harry-db", "MU8_HARRY_URL"),
                    DatabaseBindingRecord("mu8-mother-db", "MU8_MOTHER_URL"),
                ),
                {
                    "MU8_HARRY_URL": results[0].binding.database_url,
                    "MU8_MOTHER_URL": results[1].binding.database_url,
                },
            ),
        )
        bindings = ProviderAccessBindingRegistry(
            (
                ProviderAccessBinding(
                    PrincipalId("mu8-harry"), scope_id, "immich", "harry-secret"
                ),
                ProviderAccessBinding(
                    PrincipalId("mu8-mother"), scope_id, "immich", "mother-secret"
                ),
            )
        )

        def adapter_factory(binding, material):
            return Adapter(material.value)

        factory = ScopedResourceAccessRuntimeFactory(
            router,
            bindings,
            Secrets(
                {
                    "harry-secret": "harry-private",
                    "mother-secret": "mother-private",
                }
            ),
            representation_factories={"immich": adapter_factory},
            text_factories={},
        )

        async def verify():
            async with factory.build("mu8-harry") as harry:
                opened = await harry.representation_service.open_representation(
                    format_resource_ref(asset_id), "thumbnail"
                )
                assert await collect(opened) == b"harry-private"
                with pytest.raises(ResourceNotFoundError):
                    await harry.representation_service.open_representation(
                        format_resource_ref(mother_only_asset_id), "thumbnail"
                    )
            async with factory.build("mu8-mother") as mother:
                opened = await mother.representation_service.open_representation(
                    format_resource_ref(asset_id), "thumbnail"
                )
                assert await collect(opened) == b"mother-private"

        asyncio.run(verify())
    finally:
        for engine in engines:
            engine.dispose()
        for spec in reversed(specs[: len(results)]):
            provisioner.drop(spec, missing_ok=True)
