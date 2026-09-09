import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

import pytest

from pdi.principal import PrincipalId
from pdi.provider_identity import ObservationScope, ProviderAccount, ProviderInstance
from pdi.query import format_resource_ref
from pdi.resource_access import (
    ProviderInvalidResponseError,
    ProviderRepresentation,
    ProviderTextContent,
    ResourceAccessService,
    ResourceAccessSource,
    ResourceAccessUnavailableError,
    ResourceRepresentationKind,
    ResourceTextService,
    TextResourceAccessSource,
)
from pdi.resource_access.scoped import (
    ProviderAccessBinding,
    ProviderAccessBindingRegistry,
    ProviderAccessMaterial,
    ScopeResourceAccessAdapterResolver,
)


class IdentityRepository:
    def __init__(self, instance, account, scopes):
        self.instance = instance
        self.account = account
        self.scopes = {scope.id: scope for scope in scopes}

    def get_scope(self, scope_id):
        return self.scopes.get(scope_id)

    def get_instance(self, instance_id):
        return self.instance if self.instance.id == instance_id else None

    def get_account(self, account_id):
        return self.account if self.account and self.account.id == account_id else None


class SecretResolver:
    def __init__(self, values):
        self.values = values
        self.calls = []

    def resolve(self, binding_ref):
        self.calls.append(binding_ref)
        if binding_ref not in self.values:
            raise KeyError(binding_ref)
        return ProviderAccessMaterial(self.values[binding_ref])


class AccessRepository:
    def __init__(self, representation=(), text=()):
        self.representation = representation
        self.text = text

    def resolve_access_sources(self, asset_id):
        return self.representation

    def resolve_text_access_sources(self, asset_id):
        return self.text


class RepresentationAdapter:
    provider = "immich"

    def __init__(self, marker, *, status=200):
        self.marker = marker
        self.status = status
        self.calls = []
        self.closed = 0

    async def open_representation(self, locator, kind):
        self.calls.append(("representation", locator, kind))
        return self._response("image/webp")

    async def open_video(self, locator, byte_range):
        self.calls.append(("video", locator, byte_range))
        return self._response(
            "video/mp4",
            status=206 if byte_range and self.status == 200 else self.status,
            content_range="bytes 0-8/9" if byte_range else None,
        )

    def _response(self, media_type, *, status=None, content_range=None):
        async def body():
            yield self.marker.encode()

        async def close():
            self.closed += 1

        return ProviderRepresentation(
            status_code=self.status if status is None else status,
            media_type=media_type,
            content_length=str(len(self.marker)),
            etag=None,
            last_modified=None,
            body=body(),
            close=close,
            content_range=content_range,
            accept_ranges="bytes" if content_range else None,
        )

    async def aclose(self):
        return None


class TextAdapter:
    provider = "nextcloud"

    def __init__(self, marker):
        self.marker = marker
        self.calls = []

    async def open_text(self, locator):
        self.calls.append(locator)

        async def body():
            yield self.marker.encode()

        async def close():
            return None

        return ProviderTextContent(
            status_code=200,
            media_type="text/plain",
            content_length=str(len(self.marker)),
            body=body(),
            close=close,
        )


def identities(provider="immich", *, scopes=2, account=True):
    now = datetime.now(UTC)
    instance = ProviderInstance(
        uuid4(), provider, "synthetic-instance", None, True, now, now
    )
    account_row = (
        ProviderAccount(
            uuid4(), instance.id, "synthetic-account", None, None, True, now, now
        )
        if account
        else None
    )
    scope_rows = tuple(
        ObservationScope(
            uuid4(),
            instance.id,
            None if account_row is None else account_row.id,
            f"synthetic-scope-{index}",
            None,
            True,
            now,
            now,
        )
        for index in range(scopes)
    )
    return instance, account_row, scope_rows


def resolver(provider="immich", *, principal="harry", account=True):
    instance, account_row, scopes = identities(provider, account=account)
    principal_id = PrincipalId(principal)
    bindings = ProviderAccessBindingRegistry(
        ProviderAccessBinding(
            principal_id,
            scope.id,
            provider,
            f"binding-{index}",
        )
        for index, scope in enumerate(scopes)
    )
    secrets = SecretResolver(
        {f"binding-{index}": f"private-{index}" for index in range(len(scopes))}
    )
    made = []

    def make_representation(binding, material):
        adapter = RepresentationAdapter(material.value)
        made.append(adapter)
        return adapter

    def make_text(binding, material):
        adapter = TextAdapter(material.value)
        made.append(adapter)
        return adapter

    selected = ScopeResourceAccessAdapterResolver(
        principal_id,
        IdentityRepository(instance, account_row, scopes),
        bindings,
        secrets,
        representation_factories={provider: make_representation},
        text_factories={provider: make_text},
    )
    return selected, instance, account_row, scopes, secrets, made


async def collect(stream):
    return b"".join([chunk async for chunk in stream])


def representation_source(
    scope, *, locator="asset-a", provider="immich", mime="image/jpeg"
):
    return ResourceAccessSource(
        provider=provider,
        provider_locator=locator,
        resource_type="file",
        mime_type=mime,
        source_id=str(uuid4()),
        observation_scope_id=None if scope is None else str(scope.id),
    )


def text_source(scope, content, *, locator="notes/a.txt"):
    return TextResourceAccessSource(
        source_id=str(uuid4()),
        provider="nextcloud",
        provider_locator=locator,
        resource_type="file",
        mime_type="text/plain",
        size_bytes=len(content),
        blob_sha256=sha256(content).hexdigest(),
        observation_scope_id=None if scope is None else str(scope.id),
    )


def test_binding_registry_is_principal_and_scope_namespaced_and_secret_safe():
    scope_id = uuid4()
    harry = ProviderAccessBinding(
        PrincipalId("harry"), scope_id, "immich", "harry-binding"
    )
    mother = ProviderAccessBinding(
        PrincipalId("mother"), scope_id, "immich", "mother-binding"
    )
    registry = ProviderAccessBindingRegistry((harry, mother))
    secret = ProviderAccessMaterial("do-not-render")

    assert registry.resolve(PrincipalId("harry"), scope_id, "immich") is harry
    assert registry.resolve(PrincipalId("mother"), scope_id, "immich") is mother
    assert "do-not-render" not in repr(secret)
    with pytest.raises(ResourceAccessUnavailableError):
        registry.resolve(PrincipalId("father"), scope_id, "immich")
    with pytest.raises(ResourceAccessUnavailableError):
        registry.resolve(PrincipalId("harry"), scope_id, "nextcloud")


def test_immich_thumbnail_preview_video_and_range_use_exact_scope_adapter():
    selected, _, _, scopes, _, made = resolver()
    source = representation_source(scopes[1], mime="video/mp4")
    service = ResourceAccessService(
        AccessRepository(representation=(source,)), adapter_resolver=selected
    )
    resource_ref = format_resource_ref(uuid4())

    async def run():
        for kind in (
            ResourceRepresentationKind.THUMBNAIL,
            ResourceRepresentationKind.PREVIEW,
        ):
            opened = await service.open_representation(resource_ref, kind)
            assert await collect(opened) == b"private-1"
        video = await service.open_video(resource_ref)
        assert await collect(video) == b"private-1"
        ranged = await service.open_video(resource_ref, "bytes=0-8")
        assert await collect(ranged) == b"private-1"

    asyncio.run(run())
    assert len(made) == 4
    assert all(adapter.marker == "private-1" for adapter in made)


def test_nextcloud_text_hash_window_and_scope_selection_are_preserved():
    selected, _, _, scopes, _, made = resolver("nextcloud")
    content = b"private-1"
    service = ResourceTextService(
        AccessRepository(text=(text_source(scopes[1], content),)),
        adapter_resolver=selected,
    )
    result = asyncio.run(
        service.read_text(format_resource_ref(uuid4()), max_bytes=5)
    )
    assert result.text == "priva"
    assert result.truncated is True
    assert [adapter.marker for adapter in made] == ["private-1"]


def test_same_provider_two_immich_scopes_never_cross_adapter_bytes():
    selected, _, _, scopes, _, made = resolver()

    async def run():
        for index, scope in enumerate(scopes):
            service = ResourceAccessService(
                AccessRepository(
                    representation=(representation_source(scope),)
                ),
                adapter_resolver=selected,
            )
            opened = await service.open_representation(
                format_resource_ref(uuid4()), "thumbnail"
            )
            assert await collect(opened) == f"private-{index}".encode()

    asyncio.run(run())
    assert [adapter.marker for adapter in made] == ["private-0", "private-1"]


def test_same_provider_two_nextcloud_scopes_never_cross_text_bytes():
    selected, _, _, scopes, _, made = resolver("nextcloud")
    for index, scope in enumerate(scopes):
        content = f"private-{index}".encode()
        service = ResourceTextService(
            AccessRepository(text=(text_source(scope, content),)),
            adapter_resolver=selected,
        )
        result = asyncio.run(service.read_text(format_resource_ref(uuid4())))
        assert result.text == content.decode()

    assert [adapter.marker for adapter in made] == ["private-0", "private-1"]


def test_null_scope_wrong_provider_and_missing_binding_fail_before_secret_use():
    selected, _, _, scopes, secrets, made = resolver()
    service = ResourceAccessService(
        AccessRepository(representation=(representation_source(None),)),
        adapter_resolver=selected,
    )
    with pytest.raises(ResourceAccessUnavailableError, match="Legacy Source"):
        asyncio.run(
            service.open_representation(format_resource_ref(uuid4()), "thumbnail")
        )
    assert secrets.calls == [] and made == []

    with pytest.raises(ResourceAccessUnavailableError, match="Source Provider"):
        asyncio.run(
            selected.resolve_representation_adapter(
                representation_source(scopes[0], provider="nextcloud")
            )
        )
    assert secrets.calls == [] and made == []

    other_secrets = SecretResolver({"binding-0": "wrong-private"})
    other_principal = ScopeResourceAccessAdapterResolver(
        PrincipalId("mother"),
        selected._identities,
        selected._bindings,
        other_secrets,
        representation_factories={
            "immich": lambda binding, material: RepresentationAdapter(
                material.value
            )
        },
        text_factories={},
    )
    with pytest.raises(ResourceAccessUnavailableError, match="binding"):
        asyncio.run(
            other_principal.resolve_representation_adapter(
                representation_source(scopes[0])
            )
        )
    assert other_secrets.calls == []


@pytest.mark.parametrize("disabled", ("scope", "instance", "account"))
def test_disabled_identity_denies_access_before_secret_resolution(disabled):
    selected, instance, account, scopes, secrets, made = resolver()
    if disabled == "scope":
        selected._identities.scopes[scopes[0].id] = replace(scopes[0], enabled=False)
    elif disabled == "instance":
        selected._identities.instance = replace(instance, enabled=False)
    else:
        selected._identities.account = replace(account, enabled=False)

    with pytest.raises(ResourceAccessUnavailableError, match="disabled"):
        asyncio.run(
            selected.resolve_representation_adapter(
                representation_source(scopes[0])
            )
        )
    assert secrets.calls == [] and made == []


def test_auth_failure_does_not_fallback_to_another_scope():
    selected, _, _, scopes, secrets, made = resolver()

    def failing_factory(binding, material):
        adapter = RepresentationAdapter(material.value, status=403)
        made.append(adapter)
        return adapter

    selected._representation_factories["immich"] = failing_factory
    service = ResourceAccessService(
        AccessRepository(representation=(representation_source(scopes[0]),)),
        adapter_resolver=selected,
    )
    with pytest.raises(ProviderInvalidResponseError):
        asyncio.run(
            service.open_representation(format_resource_ref(uuid4()), "thumbnail")
        )
    assert secrets.calls == ["binding-0"]
    assert [adapter.marker for adapter in made] == ["private-0"]


def test_credential_rotation_changes_material_not_pdi_identity():
    selected, _, _, scopes, secrets, made = resolver()
    source = representation_source(scopes[0])
    first = asyncio.run(selected.resolve_representation_adapter(source))
    secrets.values["binding-0"] = "rotated-private"
    second = asyncio.run(selected.resolve_representation_adapter(source))

    assert source.observation_scope_id == str(scopes[0].id)
    assert source.source_id is not None
    assert first.marker == "private-0"
    assert second.marker == "rotated-private"
    assert len(made) == 2


def test_accountless_scope_can_resolve_scope_binding():
    selected, _, account, scopes, _, _ = resolver(account=False)
    adapter = asyncio.run(
        selected.resolve_representation_adapter(
            representation_source(scopes[0])
        )
    )
    assert account is None
    assert adapter.marker == "private-0"
