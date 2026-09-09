"""Opt-in MU9 qualification against a disposable real Nextcloud server."""

import asyncio
from dataclasses import dataclass, field
import os
from pathlib import Path
import secrets
from uuid import uuid4

import pytest
import requests
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from pdi.adapters.nextcloud import NextcloudActivityIncrementalSync
from pdi.adapters.nextcloud.adapter import NextcloudAdapter
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
from pdi.repository.orm.scope_sync_state import ObservationScopeSyncStateORM
from pdi.repository.orm.provider_sync_state import ProviderSyncStateORM
from pdi.resource_access import (
    NextcloudTextAdapter,
    ProviderInvalidResponseError,
    ResourceAccessError,
    TextUnavailableError,
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
OCS_HEADERS = {"OCS-APIRequest": "true", "Accept": "application/json"}


@dataclass(frozen=True)
class QualificationConfig:
    base_url: str
    user_a: str
    user_b: str
    password_a: str = field(repr=False)
    password_b: str = field(repr=False)
    rotated_password_b: str = field(repr=False)
    admin_user: str
    admin_password: str = field(repr=False)


def _required_file(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} is required for real Nextcloud qualification")
    path = Path(value)
    if not path.is_file():
        pytest.fail(f"{name} does not identify a qualification secret file")
    return path.read_text().strip()


def _config() -> QualificationConfig:
    base_url = os.environ.get("PDI_MU9_NEXTCLOUD_URL")
    user_a = os.environ.get("PDI_MU9_USER_A")
    user_b = os.environ.get("PDI_MU9_USER_B")
    admin_user = os.environ.get("PDI_MU9_ADMIN_USER")
    if not all((base_url, user_a, user_b, admin_user)):
        pytest.skip("explicit disposable MU9 Nextcloud configuration is required")
    return QualificationConfig(
        base_url=base_url.rstrip("/"),
        user_a=user_a,
        user_b=user_b,
        password_a=_required_file("PDI_MU9_PASSWORD_A_FILE"),
        password_b=_required_file("PDI_MU9_PASSWORD_B_FILE"),
        rotated_password_b=_required_file("PDI_MU9_ROTATED_PASSWORD_B_FILE"),
        admin_user=admin_user,
        admin_password=_required_file("PDI_MU9_ADMIN_PASSWORD_FILE"),
    )


def _dav_url(config: QualificationConfig, user: str, name: str = "") -> str:
    suffix = f"/{name}" if name else "/"
    return f"{config.base_url}/remote.php/dav/files/{user}{suffix}"


def _put(config, user, password, name, content):
    response = requests.put(
        _dav_url(config, user, name),
        data=content,
        auth=(user, password),
        timeout=30,
    )
    response.raise_for_status()


def _ocs(config, method, path, *, auth, data=None):
    response = requests.request(
        method,
        f"{config.base_url}/ocs/v2.php/{path}",
        headers=OCS_HEADERS,
        auth=auth,
        data=data,
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    status_code = int(payload["ocs"]["meta"]["statuscode"])
    if status_code not in {100, 200}:
        raise RuntimeError(f"Disposable Nextcloud OCS operation failed: {status_code}")
    return payload["ocs"]["data"]


def _file_facts(adapter):
    return tuple(fact for fact in adapter.scan() if fact.kind == "file")


def _content(adapter, fact):
    return b"".join(adapter.open(fact))


def _source_identity(engine, name, *, active=True):
    with Session(engine) as session:
        row = session.execute(
            select(AssetSourceORM, BlobORM)
            .join(BlobORM, AssetSourceORM.blob_id == BlobORM.id)
            .where(
                AssetSourceORM.name == name,
                AssetSourceORM.is_active.is_(active),
            )
        ).one_or_none()
        if row is None:
            return None
        source, blob = row
        return str(source.id), str(blob.asset_id), source.observation_scope_id


def _world_snapshot(engine):
    with Session(engine) as session:
        return tuple(
            session.execute(
                select(
                    AssetSourceORM.id,
                    AssetSourceORM.is_active,
                    AssetSourceORM.version_tag,
                    AssetSourceORM.observation_scope_id,
                ).order_by(AssetSourceORM.id)
            ).all()
        )


def _state_snapshot(engine):
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


async def _read_text(factory, principal, resource_ref):
    async with factory.build(principal) as runtime:
        return await runtime.text_service.read_text(resource_ref)


def _text_access_factory(router, scopes, config, credentials):
    bindings = ProviderAccessBindingRegistry(
        (
            ProviderAccessBinding(
                PrincipalId("mu9-a"), scopes[0].id, "nextcloud", "nextcloud-a"
            ),
            ProviderAccessBinding(
                PrincipalId("mu9-b"), scopes[1].id, "nextcloud", "nextcloud-b"
            ),
        )
    )

    def text_factory(binding, material):
        username, password = material.value
        return NextcloudTextAdapter(config.base_url, username, password)

    return ScopedResourceAccessRuntimeFactory(
        router,
        bindings,
        SecretResolver(credentials),
        representation_factories={},
        text_factories={"nextcloud": text_factory},
    )


def test_real_nextcloud_multi_principal_qualification():
    config = _config()
    admin_url = require_safe_test_database_url()
    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=ROOT)
    specs = (
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu9a_{token}_test",
            runtime_role=f"pdi_mu3_mu9a_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu9-a-db",
        ),
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu9b_{token}_test",
            runtime_role=f"pdi_mu3_mu9b_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu9-b-db",
        ),
    )
    results = []
    engines = []
    content_a = b"MU9-A-private-only"
    content_b = b"MU9-B-private-only"
    shared_content = b"MU9-A-shared-authorized"
    rotated_content_b = b"MU9-B-private-rotated"
    try:
        adapter_a = NextcloudAdapter(
            config.base_url, config.user_a, config.password_a
        )
        adapter_b = NextcloudAdapter(
            config.base_url, config.user_b, config.password_b
        )
        adapter_a.connect()
        adapter_b.connect()
        for user, password in (
            (config.user_a, config.password_b),
            (config.user_b, config.password_a),
            (config.user_a, secrets.token_urlsafe(32)),
            ("mu9-nonexistent", config.password_a),
        ):
            with pytest.raises(requests.HTTPError):
                NextcloudAdapter(config.base_url, user, password).connect()

        _put(config, config.user_a, config.password_a, "a-private.txt", content_a)
        _put(config, config.user_a, config.password_a, "a-shared.txt", shared_content)
        _put(config, config.user_b, config.password_b, "b-private.txt", content_b)

        facts_a = _file_facts(adapter_a)
        facts_b = _file_facts(adapter_b)
        names_a = {fact.name for fact in facts_a}
        names_b = {fact.name for fact in facts_b}
        assert {"a-private.txt", "a-shared.txt"} <= names_a
        assert "b-private.txt" not in names_a
        assert "b-private.txt" in names_b
        assert {"a-private.txt", "a-shared.txt"}.isdisjoint(names_b)
        private_a_fact = next(f for f in facts_a if f.name == "a-private.txt")
        private_b_fact = next(f for f in facts_b if f.name == "b-private.txt")
        assert _content(adapter_a, private_a_fact) == content_a
        assert _content(adapter_b, private_b_fact) == content_b

        for requester, password, owner, name in (
            (config.user_b, config.password_b, config.user_a, "a-private.txt"),
            (config.user_a, config.password_a, config.user_b, "b-private.txt"),
        ):
            response = requests.get(
                _dav_url(config, owner, name),
                auth=(requester, password),
                timeout=30,
            )
            assert response.status_code in {401, 403, 404}

        results = [provisioner.provision(spec) for spec in specs]
        engines = [
            create_engine(result.binding.database_url, poolclass=NullPool)
            for result in results
        ]
        router = PrincipalDatabaseRouter(
            PrincipalRegistry(
                (
                    PrincipalRecord(PrincipalId("mu9-a"), "mu9-a-db"),
                    PrincipalRecord(PrincipalId("mu9-b"), "mu9-b-db"),
                )
            ),
            DatabaseBindingRegistry(
                (
                    DatabaseBindingRecord("mu9-a-db", "MU9_A_DATABASE_URL"),
                    DatabaseBindingRecord("mu9-b-db", "MU9_B_DATABASE_URL"),
                ),
                {
                    "MU9_A_DATABASE_URL": results[0].binding.database_url,
                    "MU9_B_DATABASE_URL": results[1].binding.database_url,
                },
            ),
        )
        scopes = []
        for index, engine in enumerate(engines):
            identities = PostgreSQLProviderIdentityRepository(engine)
            instance = identities.create_instance(
                provider_type="nextcloud", instance_key="mu9-nextcloud"
            )
            account = identities.create_account(
                provider_instance_id=instance.id,
                account_key=f"mu9-user-{index}",
            )
            scopes.append(
                identities.create_scope(
                    provider_instance_id=instance.id,
                    provider_account_id=account.id,
                    scope_key="files-root",
                )
            )

        ingestion = ScopedIngestionRuntimeFactory(router)
        with ingestion.build("mu9-a", scopes[0].id, adapter_a) as runtime_a:
            runtime_a.sync_engine.sync_once()
        with ingestion.build("mu9-b", scopes[1].id, adapter_b) as runtime_b:
            runtime_b.sync_engine.sync_once()

        a_private = _source_identity(engines[0], "a-private.txt")
        b_private = _source_identity(engines[1], "b-private.txt")
        assert a_private is not None and a_private[2] == scopes[0].id
        assert b_private is not None and b_private[2] == scopes[1].id
        assert _source_identity(engines[0], "b-private.txt") is None
        assert _source_identity(engines[1], "a-private.txt") is None

        access = _text_access_factory(
            router,
            scopes,
            config,
            {
                "nextcloud-a": (config.user_a, config.password_a),
                "nextcloud-b": (config.user_b, config.password_b),
            },
        )
        text_a = asyncio.run(
            _read_text(access, "mu9-a", format_resource_ref(a_private[1]))
        )
        text_b = asyncio.run(
            _read_text(access, "mu9-b", format_resource_ref(b_private[1]))
        )
        assert text_a.text.encode() == content_a
        assert text_b.text.encode() == content_b

        wrong_access = _text_access_factory(
            router,
            scopes,
            config,
            {
                "nextcloud-a": (config.user_b, config.password_b),
                "nextcloud-b": (config.user_b, config.password_b),
            },
        )
        with pytest.raises((ProviderInvalidResponseError, ResourceAccessError)):
            asyncio.run(
                _read_text(
                    wrong_access, "mu9-a", format_resource_ref(a_private[1])
                )
            )

        share = _ocs(
            config,
            "POST",
            "apps/files_sharing/api/v1/shares",
            auth=(config.user_a, config.password_a),
            data={
                "path": "/a-shared.txt",
                "shareType": 0,
                "shareWith": config.user_b,
                "permissions": 1,
            },
        )
        share_id = str(share["id"])
        facts_b_shared = _file_facts(adapter_b)
        shared_b_fact = next(
            fact
            for fact in facts_b_shared
            if _content(adapter_b, fact) == shared_content
        )
        with ingestion.build("mu9-b", scopes[1].id, adapter_b) as runtime_b:
            runtime_b.sync_engine.sync_once()
        shared_a = _source_identity(engines[0], "a-shared.txt")
        shared_b = _source_identity(engines[1], shared_b_fact.name)
        assert shared_a is not None and shared_b is not None
        assert shared_a[0] != shared_b[0]
        assert shared_a[1] != shared_b[1]
        text_shared_b = asyncio.run(
            _read_text(access, "mu9-b", format_resource_ref(shared_b[1]))
        )
        assert text_shared_b.text.encode() == shared_content

        with ingestion.build("mu9-a", scopes[0].id, adapter_a) as runtime_a:
            incremental_a = NextcloudActivityIncrementalSync(
                adapter_a, runtime_a.sync_engine, runtime_a.state_repository
            )
            incremental_a.bootstrap()
        with ingestion.build("mu9-b", scopes[1].id, adapter_b) as runtime_b:
            incremental_b = NextcloudActivityIncrementalSync(
                adapter_b, runtime_b.sync_engine, runtime_b.state_repository
            )
            incremental_b.bootstrap()
        state_a_before = _state_snapshot(engines[0])
        state_b_before = _state_snapshot(engines[1])
        world_b_before = _world_snapshot(engines[1])
        _put(
            config,
            config.user_a,
            config.password_a,
            "a-private.txt",
            b"MU9-A-private-updated",
        )
        with ingestion.build("mu9-a", scopes[0].id, adapter_a) as runtime_a:
            NextcloudActivityIncrementalSync(
                adapter_a, runtime_a.sync_engine, runtime_a.state_repository
            ).run_incremental()
        assert _state_snapshot(engines[0]) != state_a_before
        assert _state_snapshot(engines[1]) == state_b_before
        assert _world_snapshot(engines[1]) == world_b_before

        state_a_after = _state_snapshot(engines[0])
        _put(
            config,
            config.user_b,
            config.password_b,
            "b-private.txt",
            b"MU9-B-private-updated",
        )
        with ingestion.build("mu9-b", scopes[1].id, adapter_b) as runtime_b:
            NextcloudActivityIncrementalSync(
                adapter_b, runtime_b.sync_engine, runtime_b.state_repository
            ).run_incremental()
        assert _state_snapshot(engines[0]) == state_a_after
        assert _state_snapshot(engines[1]) != state_b_before

        world_a_before_revoke = _world_snapshot(engines[0])
        _ocs(
            config,
            "DELETE",
            f"apps/files_sharing/api/v1/shares/{share_id}",
            auth=(config.user_a, config.password_a),
        )
        with ingestion.build("mu9-b", scopes[1].id, adapter_b) as runtime_b:
            runtime_b.sync_engine.sync_once()
        assert _source_identity(engines[1], shared_b_fact.name) is None
        assert (
            _source_identity(engines[1], shared_b_fact.name, active=False)
            is not None
        )
        assert _world_snapshot(engines[0]) == world_a_before_revoke
        with pytest.raises(TextUnavailableError):
            asyncio.run(
                _read_text(access, "mu9-b", format_resource_ref(shared_b[1]))
            )
        assert asyncio.run(
            _read_text(access, "mu9-a", format_resource_ref(shared_a[1]))
        ).text.encode() == shared_content

        _ocs(
            config,
            "PUT",
            f"cloud/users/{config.user_b}/disable",
            auth=(config.admin_user, config.admin_password),
        )
        with pytest.raises(requests.HTTPError):
            adapter_b.connect()
        adapter_a.connect()
        _ocs(
            config,
            "PUT",
            f"cloud/users/{config.user_b}/enable",
            auth=(config.admin_user, config.admin_password),
        )
        adapter_b.connect()

        identities_before = (
            scopes[1].id,
            b_private[0],
            b_private[1],
            _state_snapshot(engines[1]),
        )
        _ocs(
            config,
            "PUT",
            f"cloud/users/{config.user_b}",
            auth=(config.admin_user, config.admin_password),
            data={"key": "password", "value": config.rotated_password_b},
        )
        with pytest.raises(requests.HTTPError):
            adapter_b.connect()
        rotated_b = NextcloudAdapter(
            config.base_url, config.user_b, config.rotated_password_b
        )
        rotated_b.connect()
        rotated_access = _text_access_factory(
            router,
            scopes,
            config,
            {
                "nextcloud-a": (config.user_a, config.password_a),
                "nextcloud-b": (config.user_b, config.rotated_password_b),
            },
        )
        assert asyncio.run(
            _read_text(
                rotated_access, "mu9-b", format_resource_ref(b_private[1])
            )
        ).text.encode() == b"MU9-B-private-updated"
        _put(
            config,
            config.user_b,
            config.rotated_password_b,
            "b-private.txt",
            rotated_content_b,
        )
        with ingestion.build("mu9-b", scopes[1].id, rotated_b) as runtime_b:
            runtime_b.sync_engine.sync_once()
        assert identities_before == (
            scopes[1].id,
            _source_identity(engines[1], "b-private.txt")[0],
            _source_identity(engines[1], "b-private.txt")[1],
            _state_snapshot(engines[1]),
        )
        assert asyncio.run(
            _read_text(
                rotated_access, "mu9-b", format_resource_ref(b_private[1])
            )
        ).text.encode() == rotated_content_b

        with Session(engines[0]) as session_a, Session(engines[1]) as session_b:
            legacy_count = select(func.count()).select_from(
                ProviderSyncStateORM
            )
            assert session_a.scalar(legacy_count) == 0
            assert session_b.scalar(legacy_count) == 0
    finally:
        for engine in engines:
            engine.dispose()
        for spec in reversed(specs[: len(results)]):
            provisioner.drop(spec, missing_ok=True)
