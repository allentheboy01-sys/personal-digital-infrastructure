"""Opt-in MU10 qualification against a disposable real Immich v3.1 server."""

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import secrets
from uuid import uuid4

import pytest
import requests
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from pdi.adapters.immich import ImmichAccountMismatchError
from pdi.adapters.immich.adapter import ImmichAdapter
from pdi.adapters.immich.incremental import ImmichIncrementalSync
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
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.query import format_resource_ref
from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.blob import BlobORM
from pdi.repository.orm.provider_sync_state import ProviderSyncStateORM
from pdi.repository.orm.scope_sync_state import ObservationScopeSyncStateORM
from pdi.resource_access import (
    ImmichRepresentationAdapter,
    ResourceAccessUnavailableError,
    ResourceRepresentationKind,
)
from pdi.resource_access.scoped import (
    ProviderAccessBinding,
    ProviderAccessBindingRegistry,
    ProviderAccessMaterial,
    ScopedResourceAccessRuntimeFactory,
)
from pdi.scoped_ingestion import ScopedIngestionRuntimeFactory
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[2]
PDI_KEY_PERMISSIONS = (
    "user.read",
    "asset.read",
    "asset.view",
    "asset.download",
    "album.read",
)


@dataclass(frozen=True)
class QualificationConfig:
    base_url: str
    admin_email: str
    admin_password: str = field(repr=False)
    user_a_email: str
    user_a_password: str = field(repr=False)
    user_b_email: str
    user_b_password: str = field(repr=False)
    image_a: Path
    video_a: Path
    image_b: Path
    video_b: Path


def _secret_file(name: str) -> str:
    raw = os.environ.get(name)
    if not raw:
        pytest.skip(f"{name} is required for real Immich qualification")
    path = Path(raw)
    if not path.is_file():
        pytest.fail(f"{name} does not identify a qualification secret file")
    return path.read_text().strip()


def _media_file(name: str) -> Path:
    raw = os.environ.get(name)
    if not raw:
        pytest.skip(f"{name} is required for real Immich qualification")
    path = Path(raw)
    if not path.is_file():
        pytest.fail(f"{name} does not identify synthetic qualification media")
    return path


def _config() -> QualificationConfig:
    base_url = os.environ.get("PDI_MU10_IMMICH_URL")
    if not base_url:
        pytest.skip("explicit disposable MU10 Immich configuration is required")
    return QualificationConfig(
        base_url=base_url.rstrip("/"),
        admin_email="mu10-admin@example.invalid",
        admin_password=_secret_file("PDI_MU10_ADMIN_PASSWORD_FILE"),
        user_a_email="immich-user-a@example.invalid",
        user_a_password=_secret_file("PDI_MU10_PASSWORD_A_FILE"),
        user_b_email="immich-user-b@example.invalid",
        user_b_password=_secret_file("PDI_MU10_PASSWORD_B_FILE"),
        image_a=_media_file("PDI_MU10_IMAGE_A"),
        video_a=_media_file("PDI_MU10_VIDEO_A"),
        image_b=_media_file("PDI_MU10_IMAGE_B"),
        video_b=_media_file("PDI_MU10_VIDEO_B"),
    )


def _request(config, method, path, *, token=None, api_key=None, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if api_key:
        headers["x-api-key"] = api_key
    return requests.request(
        method, f"{config.base_url}{path}", headers=headers, timeout=60, **kwargs
    )


def _login(config, email, password):
    response = _request(
        config,
        "POST",
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    response.raise_for_status()
    return response.json()["accessToken"]


def _create_user(config, admin_token, email, password, name):
    response = _request(
        config,
        "POST",
        "/api/admin/users",
        token=admin_token,
        json={
            "email": email,
            "password": password,
            "name": name,
            "isAdmin": False,
            "shouldChangePassword": False,
            "notify": False,
        },
    )
    response.raise_for_status()
    return response.json()


def _create_key(config, token, name):
    response = _request(
        config,
        "POST",
        "/api/api-keys",
        token=token,
        json={"name": name, "permissions": list(PDI_KEY_PERMISSIONS)},
    )
    response.raise_for_status()
    payload = response.json()
    return payload["secret"], payload["apiKey"]["id"]


def _upload(config, token, path):
    now = datetime.now(UTC).isoformat()
    with path.open("rb") as handle:
        response = _request(
            config,
            "POST",
            "/api/assets",
            token=token,
            data={
                "fileCreatedAt": now,
                "fileModifiedAt": now,
                "filename": path.name,
            },
            files={"assetData": (path.name, handle)},
        )
    response.raise_for_status()
    return response.json()["id"]


def _facts(adapter):
    return tuple(adapter.scan())


def _world(engine):
    with Session(engine) as session:
        return tuple(
            session.execute(
                select(
                    AssetSourceORM.id,
                    AssetSourceORM.external_id,
                    AssetSourceORM.is_active,
                    AssetSourceORM.version_tag,
                    AssetSourceORM.observation_scope_id,
                ).order_by(AssetSourceORM.id)
            ).all()
        )


def _source(engine, external_id):
    with Session(engine) as session:
        row = session.execute(
            select(AssetSourceORM, BlobORM)
            .join(BlobORM, BlobORM.id == AssetSourceORM.blob_id)
            .where(AssetSourceORM.external_id == external_id)
        ).one_or_none()
        if row is None:
            return None
        source, blob = row
        return str(source.id), str(blob.asset_id), source.observation_scope_id


def _state(engine):
    with Session(engine) as session:
        return tuple(
            session.execute(
                select(
                    ObservationScopeSyncStateORM.observation_scope_id,
                    ObservationScopeSyncStateORM.mechanism,
                    ObservationScopeSyncStateORM.version,
                    ObservationScopeSyncStateORM.reconciliation_required,
                )
            ).all()
        )


class SecretResolver:
    def __init__(self, values):
        self.values = values

    def resolve(self, binding_ref):
        return ProviderAccessMaterial(self.values[binding_ref])


def _access_factory(router, scopes, config, values):
    registry = ProviderAccessBindingRegistry(
        (
            ProviderAccessBinding(PrincipalId("mu10-a"), scopes[0].id, "immich", "a"),
            ProviderAccessBinding(PrincipalId("mu10-b"), scopes[1].id, "immich", "b"),
        )
    )

    def factory(_binding, material):
        key, expected_user_id = material.value
        return ImmichRepresentationAdapter(
            config.base_url, key, expected_user_id=expected_user_id
        )

    return ScopedResourceAccessRuntimeFactory(
        router,
        registry,
        SecretResolver(values),
        representation_factories={"immich": factory},
        text_factories={},
    )


async def _read_representation(factory, principal, resource_ref, kind):
    async with factory.build(principal) as runtime:
        opened = await runtime.representation_service.open_representation(
            resource_ref, kind
        )
        async with opened:
            return b"".join([chunk async for chunk in opened])


async def _read_video(factory, principal, resource_ref, byte_range=None):
    async with factory.build(principal) as runtime:
        opened = await runtime.representation_service.open_video(
            resource_ref, byte_range
        )
        async with opened:
            return opened.descriptor.status_code, b"".join(
                [chunk async for chunk in opened]
            )


def test_real_immich_multi_principal_qualification():
    config = _config()
    admin_url = require_safe_test_database_url()
    signup = _request(
        config,
        "POST",
        "/api/auth/admin-sign-up",
        json={
            "email": config.admin_email,
            "password": config.admin_password,
            "name": "MU10 Admin",
        },
    )
    assert signup.status_code in {200, 201}
    admin_token = _login(config, config.admin_email, config.admin_password)
    user_a = _create_user(
        config, admin_token, config.user_a_email, config.user_a_password, "MU10 User A"
    )
    user_b = _create_user(
        config, admin_token, config.user_b_email, config.user_b_password, "MU10 User B"
    )
    assert not user_a["isAdmin"] and not user_b["isAdmin"]
    assert user_a["id"] != user_b["id"]
    token_a = _login(config, config.user_a_email, config.user_a_password)
    token_b = _login(config, config.user_b_email, config.user_b_password)
    key_a, _key_a_id = _create_key(config, token_a, "PDI MU10 A")
    key_b, key_b_id = _create_key(config, token_b, "PDI MU10 B1")
    image_a = _upload(config, token_a, config.image_a)
    video_a = _upload(config, token_a, config.video_a)
    image_b = _upload(config, token_b, config.image_b)
    video_b = _upload(config, token_b, config.video_b)

    adapter_a = ImmichAdapter(
        config.base_url, key_a, expected_user_id=user_a["id"]
    )
    adapter_b = ImmichAdapter(
        config.base_url, key_b, expected_user_id=user_b["id"]
    )
    adapter_a.connect()
    adapter_b.connect()
    with pytest.raises(ImmichAccountMismatchError):
        ImmichAdapter(
            config.base_url, key_b, expected_user_id=user_a["id"]
        ).connect()
    ids_a = {fact.external_id for fact in _facts(adapter_a)}
    ids_b = {fact.external_id for fact in _facts(adapter_b)}
    assert {image_a, video_a} <= ids_a
    assert {image_b, video_b} <= ids_b
    assert {image_b, video_b}.isdisjoint(ids_a)
    assert {image_a, video_a}.isdisjoint(ids_b)
    for key, foreign_id in ((key_a, image_b), (key_b, image_a)):
        denied = _request(config, "GET", f"/api/assets/{foreign_id}/original", api_key=key)
        assert denied.status_code in {401, 403, 404}

    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=ROOT)
    specs = (
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu10a_{token}_test",
            runtime_role=f"pdi_mu3_mu10a_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu10-a-db",
        ),
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu10b_{token}_test",
            runtime_role=f"pdi_mu3_mu10b_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu10-b-db",
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
        router = PrincipalDatabaseRouter(
            PrincipalRegistry(
                (
                    PrincipalRecord(PrincipalId("mu10-a"), "mu10-a-db"),
                    PrincipalRecord(PrincipalId("mu10-b"), "mu10-b-db"),
                )
            ),
            DatabaseBindingRegistry(
                (
                    DatabaseBindingRecord("mu10-a-db", "MU10_A_DATABASE_URL"),
                    DatabaseBindingRecord("mu10-b-db", "MU10_B_DATABASE_URL"),
                ),
                {
                    "MU10_A_DATABASE_URL": results[0].binding.database_url,
                    "MU10_B_DATABASE_URL": results[1].binding.database_url,
                },
            ),
        )
        scopes = []
        for index, (engine, remote) in enumerate(
            ((engines[0], user_a), (engines[1], user_b))
        ):
            identities = PostgreSQLProviderIdentityRepository(engine)
            instance = identities.create_instance(
                provider_type="immich", instance_key="mu10-immich"
            )
            account = identities.create_account(
                provider_instance_id=instance.id,
                account_key=f"mu10-user-{index}",
                provider_native_id=remote["id"],
            )
            scopes.append(
                identities.create_scope(
                    provider_instance_id=instance.id,
                    provider_account_id=account.id,
                    scope_key="owned-library",
                )
            )

        ingestion = ScopedIngestionRuntimeFactory(router)
        with ingestion.build("mu10-a", scopes[0].id, adapter_a) as runtime:
            runtime.sync_engine.sync_once()
        with ingestion.build("mu10-b", scopes[1].id, adapter_b) as runtime:
            runtime.sync_engine.sync_once()
        for external_id in (image_a, video_a):
            assert _source(engines[0], external_id)[2] == scopes[0].id
            assert _source(engines[1], external_id) is None
        for external_id in (image_b, video_b):
            assert _source(engines[1], external_id)[2] == scopes[1].id
            assert _source(engines[0], external_id) is None

        world_a = _world(engines[0])
        state_a = _state(engines[0])
        wrong = ImmichAdapter(
            config.base_url, key_b, expected_user_id=user_a["id"]
        )
        with pytest.raises(ImmichAccountMismatchError):
            with ingestion.build("mu10-a", scopes[0].id, wrong) as runtime:
                runtime.sync_engine.sync_once()
        assert _world(engines[0]) == world_a and _state(engines[0]) == state_a

        access = _access_factory(
            router,
            scopes,
            config,
            {"a": (key_a, user_a["id"]), "b": (key_b, user_b["id"])},
        )
        a_image_ref = format_resource_ref(_source(engines[0], image_a)[1])
        b_image_ref = format_resource_ref(_source(engines[1], image_b)[1])
        a_video_ref = format_resource_ref(_source(engines[0], video_a)[1])
        b_video_ref = format_resource_ref(_source(engines[1], video_b)[1])
        for principal, resource_ref in (
            ("mu10-a", a_image_ref),
            ("mu10-b", b_image_ref),
        ):
            assert asyncio.run(
                _read_representation(
                    access, principal, resource_ref, ResourceRepresentationKind.THUMBNAIL
                )
            )
            assert asyncio.run(
                _read_representation(
                    access, principal, resource_ref, ResourceRepresentationKind.PREVIEW
                )
            )
        for principal, resource_ref in (
            ("mu10-a", a_video_ref),
            ("mu10-b", b_video_ref),
        ):
            assert asyncio.run(_read_video(access, principal, resource_ref))[1]
            status, ranged = asyncio.run(
                _read_video(access, principal, resource_ref, "bytes=0-31")
            )
            assert status == 206 and ranged

        wrong_access = _access_factory(
            router,
            scopes,
            config,
            {"a": (key_b, user_a["id"]), "b": (key_b, user_b["id"])},
        )
        with pytest.raises(ResourceAccessUnavailableError):
            asyncio.run(
                _read_representation(
                    wrong_access,
                    "mu10-a",
                    a_image_ref,
                    ResourceRepresentationKind.THUMBNAIL,
                )
            )

        anchor = datetime.now(UTC) + timedelta(seconds=2)
        with ingestion.build("mu10-a", scopes[0].id, adapter_a) as runtime:
            ImmichIncrementalSync(
                adapter_a, runtime.sync_engine, runtime.state_repository, clock=lambda: anchor
            ).bootstrap()
        with ingestion.build("mu10-b", scopes[1].id, adapter_b) as runtime:
            ImmichIncrementalSync(
                adapter_b,
                runtime.sync_engine,
                runtime.state_repository,
                clock=lambda: anchor + timedelta(seconds=1),
            ).bootstrap()
        state_a_before = _state(engines[0])
        state_b_before = _state(engines[1])
        world_b_before = _world(engines[1])
        update = _request(
            config,
            "PUT",
            f"/api/assets/{image_a}",
            token=token_a,
            json={"description": "MU10 A metadata update"},
        )
        update.raise_for_status()
        with ingestion.build("mu10-a", scopes[0].id, adapter_a) as runtime:
            ImmichIncrementalSync(
                adapter_a,
                runtime.sync_engine,
                runtime.state_repository,
                clock=lambda: anchor + timedelta(minutes=1),
            ).run_incremental()
        assert _state(engines[0]) != state_a_before
        assert _state(engines[1]) == state_b_before
        assert _world(engines[1]) == world_b_before
        first_replay = _world(engines[0])
        with ingestion.build("mu10-a", scopes[0].id, adapter_a) as runtime:
            ImmichIncrementalSync(
                adapter_a,
                runtime.sync_engine,
                runtime.state_repository,
                clock=lambda: anchor + timedelta(minutes=1),
            ).run_incremental()
        assert len(_world(engines[0])) == len(first_replay)

        world_a_before_b = _world(engines[0])
        update_b = _request(
            config,
            "PUT",
            f"/api/assets/{image_b}",
            token=token_b,
            json={"description": "MU10 B metadata update"},
        )
        update_b.raise_for_status()
        with ingestion.build("mu10-b", scopes[1].id, adapter_b) as runtime:
            ImmichIncrementalSync(
                adapter_b,
                runtime.sync_engine,
                runtime.state_repository,
                clock=lambda: anchor + timedelta(minutes=2),
            ).run_incremental()
        assert _state(engines[1]) != state_b_before
        assert _world(engines[0]) == world_a_before_b

        world_b_before_delete = _world(engines[1])
        deleted = _request(
            config,
            "DELETE",
            "/api/assets",
            token=token_a,
            json={"ids": [video_a], "force": True},
        )
        deleted.raise_for_status()
        with ingestion.build("mu10-a", scopes[0].id, adapter_a) as runtime:
            runtime.sync_engine.sync_once()
        with Session(engines[0]) as session:
            assert session.scalar(
                select(AssetSourceORM.is_active).where(
                    AssetSourceORM.external_id == video_a
                )
            ) is False
        assert _world(engines[1]) == world_b_before_delete

        identity_b_before_rotation = (
            scopes[1].id,
            _source(engines[1], image_b),
            _source(engines[1], video_b),
            _state(engines[1]),
            b_image_ref,
            b_video_ref,
        )
        key_b2, _key_b2_id = _create_key(config, token_b, "PDI MU10 B2")
        revoked = _request(
            config, "DELETE", f"/api/api-keys/{key_b_id}", token=token_b
        )
        revoked.raise_for_status()
        with pytest.raises(requests.HTTPError):
            adapter_b.connect()
        rotated_b = ImmichAdapter(
            config.base_url, key_b2, expected_user_id=user_b["id"]
        )
        rotated_b.connect()
        with pytest.raises(ImmichAccountMismatchError):
            ImmichAdapter(
                config.base_url, key_a, expected_user_id=user_b["id"]
            ).connect()
        assert identity_b_before_rotation == (
            scopes[1].id,
            _source(engines[1], image_b),
            _source(engines[1], video_b),
            _state(engines[1]),
            format_resource_ref(_source(engines[1], image_b)[1]),
            format_resource_ref(_source(engines[1], video_b)[1]),
        )
        with Session(engines[0]) as session_a, Session(engines[1]) as session_b:
            count = select(func.count()).select_from(ProviderSyncStateORM)
            assert session_a.scalar(count) == 0
            assert session_b.scalar(count) == 0

        album = _request(
            config,
            "POST",
            "/api/albums",
            token=token_a,
            json={
                "albumName": "MU10 shared album",
                "assetIds": [image_a],
                "albumUsers": [{"userId": user_b["id"], "role": "viewer"}],
            },
        )
        album.raise_for_status()
        shared = _request(
            config, "GET", f"/api/assets/{image_a}/thumbnail", api_key=key_b2
        )
        assert shared.status_code == 200
        shared_scan_supported = image_a in {fact.external_id for fact in _facts(rotated_b)}
        assert isinstance(shared_scan_supported, bool)
        print(
            "MU10_SHARED_SCAN_SUPPORTED="
            f"{'YES' if shared_scan_supported else 'NO'}"
        )
    finally:
        for engine in engines:
            engine.dispose()
        for spec in reversed(specs[: len(results)]):
            provisioner.drop(spec, missing_ok=True)
