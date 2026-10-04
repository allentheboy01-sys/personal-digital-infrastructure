from hashlib import sha256
from types import SimpleNamespace
from uuid import uuid4

import pytest

from pdi.observation import (
    EnrichmentResource,
    EnrichmentSource,
    NextcloudTextExtractor,
    ObservationExtractionError,
)
from pdi.observation.scoped_access import (
    ScopedEnrichmentAccessResolver,
    ScopedImmichOCRReader,
    ScopedNextcloudContentReader,
)
from pdi.observation.ocr import ImmichOCRExtractor, OCRRegion
from pdi.principal import PrincipalId
from pdi.query import format_resource_ref
from pdi.resource_access.scoped import (
    ProviderAccessBinding,
    ProviderAccessBindingRegistry,
    ProviderAccessMaterial,
)


class Identities:
    def __init__(self, scopes, instances, accounts):
        self.scopes = scopes
        self.instances = instances
        self.accounts = accounts

    def get_scope(self, identity):
        return self.scopes.get(identity)

    def get_instance(self, identity):
        return self.instances.get(identity)

    def get_account(self, identity):
        return self.accounts.get(identity)


class Secrets:
    def __init__(self, values):
        self.values = values

    def resolve(self, binding_ref):
        value = self.values[binding_ref]
        if isinstance(value, Exception):
            raise value
        return ProviderAccessMaterial(value)


def _resolver(provider, values, factory):
    principal = PrincipalId("mu11-a")
    instance_id, account_id = uuid4(), uuid4()
    scopes = [uuid4(), uuid4()]
    identities = Identities(
        {
            scope: SimpleNamespace(
                id=scope,
                provider_instance_id=instance_id,
                provider_account_id=account_id,
                enabled=True,
            )
            for scope in scopes
        },
        {
            instance_id: SimpleNamespace(
                id=instance_id, provider_type=provider, enabled=True
            )
        },
        {
            account_id: SimpleNamespace(
                id=account_id,
                provider_instance_id=instance_id,
                provider_native_id="remote-user-a",
                enabled=True,
            )
        },
    )
    bindings = ProviderAccessBindingRegistry(
        tuple(
            ProviderAccessBinding(principal, scope, provider, f"binding-{index}")
            for index, scope in enumerate(scopes)
        )
    )
    return (
        ScopedEnrichmentAccessResolver(
            principal,
            identities,
            bindings,
            Secrets(values),
            {provider: factory},
        ),
        scopes,
    )


def _source(provider, scope, *, content=b"private", locator="locator"):
    return EnrichmentSource(
        source_id="source-stable",
        provider=provider,
        metadata={},
        provider_locator=locator,
        blob_sha256=sha256(content).hexdigest(),
        size=len(content),
        mime_type="text/plain" if provider == "nextcloud" else "image/jpeg",
        name="private.txt",
        observation_scope_id=str(scope),
    )


def test_scoped_immich_ocr_uses_only_selected_scope_reader():
    calls = []

    class Reader:
        def __init__(self, value):
            self.value = value

        def get_asset_ocr(self, locator):
            calls.append(self.value)
            return (OCRRegion(self.value),)

    resolver, scopes = _resolver(
        "immich",
        {"binding-0": "A-private", "binding-1": "B-private"},
        lambda _binding, material, native_id: Reader(
            f"{material.value}:{native_id}"
        ),
    )
    extractor = ImmichOCRExtractor(ScopedImmichOCRReader(resolver))
    resource = EnrichmentResource(
        format_resource_ref(uuid4()), (_source("immich", scopes[0]),)
    )
    assert extractor.extract(resource).statements[0].value.value.startswith(
        "A-private"
    )
    assert calls == ["A-private:remote-user-a"]


def test_scoped_nextcloud_reader_has_no_auth_failure_fallback():
    calls = []

    class Adapter:
        def __init__(self, value):
            self.value = value

        def connect(self):
            calls.append(("connect", self.value))
            if isinstance(self.value, Exception):
                raise self.value

        def open(self, fact):
            calls.append(("open", self.value))
            yield self.value

    resolver, scopes = _resolver(
        "nextcloud",
        {"binding-0": RuntimeError("denied"), "binding-1": b"B-private"},
        lambda _binding, material, _native_id: Adapter(material.value),
    )
    reader = ScopedNextcloudContentReader(resolver)
    with pytest.raises(ObservationExtractionError):
        NextcloudTextExtractor(reader).extract(
            EnrichmentResource(
                format_resource_ref(uuid4()),
                (_source("nextcloud", scopes[0]),),
            )
        )
    assert calls == []


def test_scoped_nextcloud_content_reader_freezes_selected_scope():
    calls = []

    class Adapter:
        def __init__(self, value):
            self.value = value

        def connect(self):
            calls.append(("connect", self.value))

        def open(self, fact):
            calls.append(("open", self.value))
            yield self.value

    resolver, scopes = _resolver(
        "nextcloud",
        {"binding-0": b"A-private", "binding-1": b"B-private"},
        lambda _binding, material, _native_id: Adapter(material.value),
    )
    reader = ScopedNextcloudContentReader(resolver)
    assert b"".join(reader.open(_source("nextcloud", scopes[0]))) == b"A-private"
    assert calls == [("connect", b"A-private"), ("open", b"A-private")]


def test_remote_enrichment_fingerprint_includes_scope_provenance():
    content = b"same-content"

    class Adapter:
        def connect(self):
            pass

        def open(self, fact):
            yield content

    resolver, scopes = _resolver(
        "nextcloud",
        {"binding-0": "A", "binding-1": "B"},
        lambda *_args: Adapter(),
    )
    extractor = NextcloudTextExtractor(ScopedNextcloudContentReader(resolver))
    fingerprints = [
        extractor.input_fingerprint(
            EnrichmentResource(
                format_resource_ref(uuid4()),
                (_source("nextcloud", scope, content=content),),
            )
        )
        for scope in scopes
    ]
    assert fingerprints[0] != fingerprints[1]


def test_scoped_remote_reader_rejects_legacy_null_scope():
    resolver, _ = _resolver(
        "nextcloud", {"binding-0": b"A", "binding-1": b"B"}, lambda *_: object()
    )
    with pytest.raises(ObservationExtractionError, match="no remote enrichment Scope"):
        resolver.resolve(
            EnrichmentSource(
                source_id="legacy",
                provider="nextcloud",
                metadata={},
            )
        )


def test_scoped_remote_reader_requires_provider_account():
    principal = PrincipalId("mu11-a")
    instance_id, scope_id = uuid4(), uuid4()
    resolver = ScopedEnrichmentAccessResolver(
        principal,
        Identities(
            {scope_id: SimpleNamespace(
                id=scope_id, provider_instance_id=instance_id,
                provider_account_id=None, enabled=True,
            )},
            {instance_id: SimpleNamespace(
                id=instance_id, provider_type="nextcloud", enabled=True,
            )},
            {},
        ),
        ProviderAccessBindingRegistry(()),
        Secrets({}),
        {},
    )
    with pytest.raises(ObservationExtractionError, match="Provider Account"):
        resolver.resolve(_source("nextcloud", scope_id))


def test_scoped_immich_reader_requires_remote_identity():
    principal = PrincipalId("mu11-a")
    instance_id, account_id, scope_id = uuid4(), uuid4(), uuid4()
    resolver = ScopedEnrichmentAccessResolver(
        principal,
        Identities(
            {scope_id: SimpleNamespace(
                id=scope_id, provider_instance_id=instance_id,
                provider_account_id=account_id, enabled=True,
            )},
            {instance_id: SimpleNamespace(
                id=instance_id, provider_type="immich", enabled=True,
            )},
            {account_id: SimpleNamespace(
                id=account_id, provider_instance_id=instance_id,
                provider_native_id=None, enabled=True,
            )},
        ),
        ProviderAccessBindingRegistry((ProviderAccessBinding(
            principal, scope_id, "immich", "binding",
        ),)),
        Secrets({"binding": "secret"}),
        {"immich": lambda *_: object()},
    )
    with pytest.raises(ObservationExtractionError, match="identity"):
        resolver.resolve(_source("immich", scope_id))
