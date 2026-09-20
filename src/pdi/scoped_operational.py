"""Principal-bound formal orchestration for staged multi-user promotion.

This module is additive to :mod:`pdi.operational`.  Its dependencies are
trusted operator composition, never model-facing input.  It deliberately has
no environment/default database fallback and no legacy execution fallback.
"""

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

from sqlalchemy import Engine

from pdi.data_status import PipelineErrorCode, PipelineKind, PipelineRunRepository
from pdi.database import create_postgres_engine
from pdi.operational import LOCK_PATH, acquire_formal_lock
from pdi.principal import PrincipalDatabaseRouter, PrincipalId
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.scoped_ingestion import (
    ScopedIngestionRuntime,
    ScopedIngestionRuntimeFactory,
)
from pdi.adapters.base import Adapter
from pdi.adapters.immich import ImmichAdapter, ImmichIncrementalSync
from pdi.adapters.nextcloud import NextcloudAdapter, NextcloudActivityIncrementalSync
from pdi.scoped_operator_config import (
    ScopedOperatorConfiguration,
    load_scoped_operator_configuration,
)
from pdi.person_identity import (
    ImmichEnumerablePeopleAdapter,
    ScopedPersonRepository,
    ScopedPersonSyncService,
)
from pdi.resource_person_relation import (
    ImmichResourcePersonRelationAdapter,
    ScopedResourcePersonRelationRepository,
    ScopedResourcePersonRelationSyncService,
)
from pdi.config.settings import ImmichSettings
from pdi.observation import (
    EnrichmentWorker,
    FileMetadataExtractor,
    ImmichGeoExtractor,
    ImmichMetadataExtractor,
    ImmichOCRExtractor,
    ImmichOCRReader,
    NextcloudDOCXExtractor,
    NextcloudODTExtractor,
    NextcloudPDFExtractor,
    NextcloudTextExtractor,
    PostgreSQLObservationRepository,
)
from pdi.observation.scoped_access import (
    ScopedEnrichmentAccessResolver,
    ScopedImmichOCRReader,
    ScopedNextcloudContentReader,
)
from pdi.resource_access.scoped import (
    ProviderAccessBinding,
    ProviderAccessBindingRegistry,
    ProviderAccessMaterial,
)


class ScopedFormalPipelineError(RuntimeError):
    """A principal-bound formal operation could not safely complete."""


@dataclass(frozen=True, slots=True)
class FormalScopeTarget:
    principal_id: PrincipalId
    observation_scope_id: UUID | None
    provider_instance_id: UUID | None
    provider_account_id: UUID | None
    provider_type: str


class FormalOperationExecutor(Protocol):
    def __call__(self, engine: Engine, target: FormalScopeTarget | None) -> None: ...


@dataclass(frozen=True, slots=True)
class FormalPipelineSpec:
    pipeline_key: str
    kind: PipelineKind
    provider_type: str | None


ENRICHMENT_BATCH_SIZES: Mapping[str, int] = {
    "enrichment.nextcloud_text": 100,
    "enrichment.nextcloud_documents": 100,
    "enrichment.file_metadata": 20000,
    "enrichment.immich_geo": 20000,
    "enrichment.immich_metadata": 20000,
    "enrichment.immich_ocr": 20000,
}


SCOPED_FORMAL_PIPELINES: Mapping[str, FormalPipelineSpec] = {
    **{
        f"provider.{provider}.{suffix}": FormalPipelineSpec(
            f"provider.{provider}.{suffix}", PipelineKind.PROVIDER_SYNC, provider
        )
        for provider in ("nextcloud", "immich")
        for suffix in ("sync", "incremental", "bootstrap", "recovery")
    },
    "person.immich.sync": FormalPipelineSpec(
        "person.immich.sync", PipelineKind.PROVIDER_SYNC, "immich"
    ),
    "relation.immich.sync": FormalPipelineSpec(
        "relation.immich.sync", PipelineKind.PROVIDER_SYNC, "immich"
    ),
    "enrichment.immich_ocr": FormalPipelineSpec(
        "enrichment.immich_ocr", PipelineKind.ENRICHMENT, "immich"
    ),
    "enrichment.nextcloud_text": FormalPipelineSpec(
        "enrichment.nextcloud_text", PipelineKind.ENRICHMENT, "nextcloud"
    ),
    "enrichment.nextcloud_documents": FormalPipelineSpec(
        "enrichment.nextcloud_documents", PipelineKind.ENRICHMENT, "nextcloud"
    ),
    "enrichment.file_metadata": FormalPipelineSpec(
        "enrichment.file_metadata", PipelineKind.ENRICHMENT, None
    ),
    "enrichment.immich_geo": FormalPipelineSpec(
        "enrichment.immich_geo", PipelineKind.ENRICHMENT, None
    ),
    "enrichment.immich_metadata": FormalPipelineSpec(
        "enrichment.immich_metadata", PipelineKind.ENRICHMENT, None
    ),
}


class PrincipalFormalPipelineRunner:
    """Run one registered operation in exactly one routed Personal DB.

    Scope-backed operations visit every enabled Scope for the Provider in
    deterministic instance/scope-key order. All intended Scopes are attempted;
    failures are collected, the Personal-DB-local ledger is marked failed, and
    the runner never tries another
    Principal, credential, legacy executable, or database.
    """

    def __init__(
        self,
        router: PrincipalDatabaseRouter,
        executors: Mapping[str, FormalOperationExecutor],
        *,
        engine_factory: Callable[[str], Engine] = create_postgres_engine,
        lock_path: Path = LOCK_PATH,
    ) -> None:
        self._router = router
        self._executors = dict(executors)
        self._engine_factory = engine_factory
        self._lock_path = lock_path

    def run(
        self,
        principal_id: PrincipalId | str | None,
        pipeline_key: str,
        *,
        lock_timeout: float,
    ) -> int:
        spec = SCOPED_FORMAL_PIPELINES.get(pipeline_key)
        executor = self._executors.get(pipeline_key)
        if spec is None or executor is None:
            raise ScopedFormalPipelineError(
                "Scoped formal pipeline is not explicitly configured"
            )
        binding = self._router.resolve(principal_id)
        parsed = principal_id if isinstance(principal_id, PrincipalId) else PrincipalId(principal_id or "")
        with acquire_formal_lock(self._lock_path, lock_timeout):
            engine = self._engine_factory(binding.database_url)
            try:
                ledger = PipelineRunRepository(engine)
                ledger.fail_interrupted_run(pipeline_key)
                run = ledger.begin_run(pipeline_key, spec.kind)
                try:
                    targets = self._targets(engine, parsed, spec.provider_type)
                    if spec.provider_type is not None and not targets:
                        raise ScopedFormalPipelineError(
                            "No enabled Observation Scope exists for Provider"
                        )
                    failures: list[BaseException] = []
                    for target in targets:
                        try:
                            executor(engine, target)
                        except BaseException as error:
                            failures.append(error)
                    if failures:
                        raise ScopedFormalPipelineError(
                            f"{len(failures)} scoped operation(s) failed"
                        ) from failures[0]
                except BaseException:
                    ledger.fail_run(run.id, PipelineErrorCode.EXECUTION_FAILED)
                    raise
                ledger.complete_run(run.id)
                return 0
            finally:
                engine.dispose()

    @staticmethod
    def _targets(
        engine: Engine,
        principal_id: PrincipalId,
        provider_type: str | None,
    ) -> tuple[FormalScopeTarget, ...]:
        if provider_type is None:
            return (FormalScopeTarget(
                principal_id=principal_id,
                observation_scope_id=None,
                provider_instance_id=None,
                provider_account_id=None,
                provider_type="",
            ),)
        identities = PostgreSQLProviderIdentityRepository(engine)
        targets: list[FormalScopeTarget] = []
        for instance in identities.list_instances():
            if not instance.enabled or instance.provider_type != provider_type:
                continue
            for scope in identities.list_scopes_for_instance(instance.id):
                if not scope.enabled:
                    continue
                if scope.provider_account_id is not None:
                    account = identities.get_account(scope.provider_account_id)
                    if (
                        account is None
                        or not account.enabled
                        or account.provider_instance_id != instance.id
                    ):
                        raise ScopedFormalPipelineError(
                            "Enabled Scope has unavailable Provider Account"
                        )
                targets.append(FormalScopeTarget(
                    principal_id=principal_id,
                    observation_scope_id=scope.id,
                    provider_instance_id=instance.id,
                    provider_account_id=scope.provider_account_id,
                    provider_type=provider_type,
                ))
        return tuple(targets)


class ScopedIngestionFormalExecutor:
    """Small adapter from formal orchestration to trusted MU7 composition.

    The callback owns Provider-specific full/incremental/bootstrap/recover
    behavior and receives the fixed Principal+Scope target.  This keeps secrets
    out of argv and prevents this neutral layer from understanding credentials.
    """

    def __init__(self, operation: Callable[[FormalScopeTarget], None]) -> None:
        self._operation = operation

    def __call__(self, engine: Engine, target: FormalScopeTarget | None) -> None:
        if target is None or target.observation_scope_id is None:
            raise ScopedFormalPipelineError("Provider operation requires Scope")
        self._operation(target)


class MU7ScopedIngestionFormalExecutor:
    """Concrete trusted bridge from a formal target into the MU7 runtime."""

    def __init__(
        self,
        runtime_factory: ScopedIngestionRuntimeFactory,
        adapter_factory: Callable[[FormalScopeTarget], Adapter],
        operation: Callable[[ScopedIngestionRuntime], None],
    ) -> None:
        self._runtime_factory = runtime_factory
        self._adapter_factory = adapter_factory
        self._operation = operation

    def __call__(self, engine: Engine, target: FormalScopeTarget | None) -> None:
        if target is None or target.observation_scope_id is None:
            raise ScopedFormalPipelineError("Ingestion operation requires Scope")
        adapter = self._adapter_factory(target)
        with self._runtime_factory.build(
            target.principal_id,
            target.observation_scope_id,
            adapter,
        ) as runtime:
            self._operation(runtime)


class ExecutableScopedProviderOperation:
    """Executable Nextcloud/Immich operation using exact config binding."""

    def __init__(
        self,
        configuration: ScopedOperatorConfiguration,
        operation: str,
    ) -> None:
        self._configuration = configuration
        self._operation = operation

    def __call__(self, engine: Engine, target: FormalScopeTarget | None) -> None:
        if target is None or target.observation_scope_id is None:
            raise ScopedFormalPipelineError("Provider operation requires Scope")
        binding, secret = self._configuration.resolve(
            target.principal_id,
            target.observation_scope_id,
            target.provider_type,
        )
        identities = PostgreSQLProviderIdentityRepository(engine)
        account = (
            None
            if target.provider_account_id is None
            else identities.get_account(target.provider_account_id)
        )
        if target.provider_type == "nextcloud":
            adapter: Adapter = NextcloudAdapter(
                binding.endpoint, binding.username or "", secret
            )
        elif target.provider_type == "immich":
            if account is None or not account.provider_native_id:
                raise ScopedFormalPipelineError(
                    "Immich Scope requires expected remote Account identity"
                )
            adapter = ImmichAdapter(
                binding.endpoint,
                secret,
                expected_user_id=account.provider_native_id,
            )
        else:
            raise ScopedFormalPipelineError("Provider is not scoped-formal capable")
        factory = ScopedIngestionRuntimeFactory(self._configuration.router)
        with factory.build(
            target.principal_id, target.observation_scope_id, adapter
        ) as runtime:
            if self._operation == "full":
                runtime.sync_engine.sync_once()
                return
            incremental = (
                NextcloudActivityIncrementalSync(
                    adapter, runtime.sync_engine, runtime.state_repository
                )
                if isinstance(adapter, NextcloudAdapter)
                else ImmichIncrementalSync(
                    adapter, runtime.sync_engine, runtime.state_repository
                )
            )
            method_name = {
                "incremental": "run_incremental",
                "bootstrap": "bootstrap",
                "recover": "recover",
            }.get(self._operation)
            if method_name is None:
                raise ScopedFormalPipelineError("Unknown Provider operation")
            getattr(incremental, method_name)()


def _immich_access(
    configuration: ScopedOperatorConfiguration,
    engine: Engine,
    target: FormalScopeTarget,
) -> tuple[str, str, str]:
    binding, secret = configuration.resolve(
        target.principal_id, target.observation_scope_id, "immich"
    )
    account = (
        None
        if target.provider_account_id is None
        else PostgreSQLProviderIdentityRepository(engine).get_account(
            target.provider_account_id
        )
    )
    if account is None or not account.provider_native_id:
        raise ScopedFormalPipelineError(
            "Immich Scope requires expected remote Account identity"
        )
    return binding.endpoint, secret, account.provider_native_id


class ExecutableScopedPersonOperation:
    def __init__(self, configuration: ScopedOperatorConfiguration) -> None:
        self._configuration = configuration

    def __call__(self, engine: Engine, target: FormalScopeTarget | None) -> None:
        if target is None or target.observation_scope_id is None or target.provider_type != "immich":
            raise ScopedFormalPipelineError("Person operation requires Immich Scope")
        endpoint, secret, expected = _immich_access(
            self._configuration, engine, target
        )
        ScopedPersonSyncService(
            ImmichEnumerablePeopleAdapter(
                endpoint, secret, expected_user_id=expected
            ),
            ScopedPersonRepository(engine, target.observation_scope_id),
            "immich",
        ).sync_once()


class ExecutableScopedRelationOperation:
    def __init__(self, configuration: ScopedOperatorConfiguration) -> None:
        self._configuration = configuration

    def __call__(self, engine: Engine, target: FormalScopeTarget | None) -> None:
        if target is None or target.observation_scope_id is None or target.provider_type != "immich":
            raise ScopedFormalPipelineError("Relation operation requires Immich Scope")
        endpoint, secret, expected = _immich_access(
            self._configuration, engine, target
        )
        ScopedResourcePersonRelationSyncService(
            ImmichResourcePersonRelationAdapter(
                endpoint, secret, expected_user_id=expected
            ),
            ScopedResourcePersonRelationRepository(
                engine, target.observation_scope_id
            ),
            "immich",
        ).sync_once()


class _ConfiguredSecretResolver:
    def __init__(self, configuration: ScopedOperatorConfiguration) -> None:
        self._configuration = configuration

    def resolve(self, binding_ref: str) -> ProviderAccessMaterial:
        for binding in self._configuration.bindings.values():
            if binding.secret_env == binding_ref:
                value = self._configuration.environment.get(binding_ref)
                if value:
                    return ProviderAccessMaterial(value)
        raise ScopedFormalPipelineError("Provider secret is unavailable")


def _enrichment_resolver(
    configuration: ScopedOperatorConfiguration,
    engine: Engine,
    principal_id: PrincipalId,
) -> ScopedEnrichmentAccessResolver:
    access_bindings = ProviderAccessBindingRegistry(
        ProviderAccessBinding(
            binding.principal_id,
            binding.observation_scope_id,
            binding.provider_type,
            binding.secret_env,
        )
        for binding in configuration.bindings.values()
    )

    def configured(binding):
        return configuration.bindings[
            (binding.principal_id, binding.observation_scope_id)
        ]

    return ScopedEnrichmentAccessResolver(
        principal_id,
        PostgreSQLProviderIdentityRepository(engine),
        access_bindings,
        _ConfiguredSecretResolver(configuration),
        {
            "nextcloud": lambda binding, material, native_id: NextcloudAdapter(
                configured(binding).endpoint,
                configured(binding).username or "",
                material.value,
            ),
            "immich": lambda binding, material, native_id: ImmichOCRReader(
                ImmichSettings(
                    url=configured(binding).endpoint,
                    api_key=material.value,
                ),
                expected_user_id=native_id,
            ),
        },
    )


class ExecutableEnrichmentOperation:
    def __init__(
        self, configuration: ScopedOperatorConfiguration, pipeline_key: str
    ) -> None:
        self._configuration = configuration
        self._pipeline_key = pipeline_key

    def __call__(self, engine: Engine, target: FormalScopeTarget | None) -> None:
        if target is None:
            raise ScopedFormalPipelineError("Enrichment requires Principal")
        repository = PostgreSQLObservationRepository(engine)
        if self._pipeline_key == "enrichment.file_metadata":
            extractors = (
                (FileMetadataExtractor(), FileMetadataExtractor.discovery_providers),
            )
        elif self._pipeline_key == "enrichment.immich_geo":
            extractors = ((ImmichGeoExtractor(), "immich"),)
        elif self._pipeline_key == "enrichment.immich_metadata":
            extractors = ((ImmichMetadataExtractor(), "immich"),)
        else:
            resolver = _enrichment_resolver(
                self._configuration, engine, target.principal_id
            )
            if self._pipeline_key == "enrichment.immich_ocr":
                extractors = ((ImmichOCRExtractor(ScopedImmichOCRReader(resolver)), "immich"),)
            elif self._pipeline_key == "enrichment.nextcloud_text":
                extractors = ((NextcloudTextExtractor(ScopedNextcloudContentReader(resolver)), "nextcloud"),)
            elif self._pipeline_key == "enrichment.nextcloud_documents":
                reader = ScopedNextcloudContentReader(resolver)
                extractors = tuple(
                    (extractor(reader), "nextcloud")
                    for extractor in (
                        NextcloudPDFExtractor,
                        NextcloudODTExtractor,
                        NextcloudDOCXExtractor,
                    )
                )
            else:
                raise ScopedFormalPipelineError("Unknown enrichment operation")
        try:
            batch_size = ENRICHMENT_BATCH_SIZES[self._pipeline_key]
        except KeyError as error:
            raise ScopedFormalPipelineError("Unknown enrichment operation") from error
        failures = 0
        for extractor, provider in extractors:
            result = EnrichmentWorker(
                repository, extractor, provider=provider
            ).run_once(batch_size=batch_size)
            failures += result.failed
        if failures:
            raise ScopedFormalPipelineError("Enrichment operation failed")


def build_executable_scoped_runner(
    configuration: ScopedOperatorConfiguration,
    *,
    lock_path: Path = LOCK_PATH,
) -> PrincipalFormalPipelineRunner:
    operation_names = {
        "sync": "full",
        "incremental": "incremental",
        "bootstrap": "bootstrap",
        "recovery": "recover",
    }
    executors: dict[str, FormalOperationExecutor] = {}
    for provider in ("nextcloud", "immich"):
        for suffix, operation in operation_names.items():
            key = f"provider.{provider}.{suffix}"
            executors[key] = ExecutableScopedProviderOperation(
                configuration, operation
            )
    executors["person.immich.sync"] = ExecutableScopedPersonOperation(
        configuration
    )
    executors["relation.immich.sync"] = ExecutableScopedRelationOperation(
        configuration
    )
    for key in (
        "enrichment.file_metadata",
        "enrichment.immich_geo",
        "enrichment.immich_metadata",
        "enrichment.immich_ocr",
        "enrichment.nextcloud_text",
        "enrichment.nextcloud_documents",
    ):
        executors[key] = ExecutableEnrichmentOperation(configuration, key)
    return PrincipalFormalPipelineRunner(
        configuration.router, executors, lock_path=lock_path
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one trusted Principal-bound scoped PDI pipeline."
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--principal-ref", required=True)
    parser.add_argument(
        "--pipeline-key",
        required=True,
        choices=tuple(SCOPED_FORMAL_PIPELINES),
    )
    parser.add_argument("--lock-timeout", required=True, type=float)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configuration = load_scoped_operator_configuration(args.config)
    runner = build_executable_scoped_runner(configuration)
    return runner.run(
        args.principal_ref,
        args.pipeline_key,
        lock_timeout=args.lock_timeout,
    )


GMAIL_PRODUCTION_TRANSITION_MODE = "LEGACY_SINGLE_PRINCIPAL_DEFERRED"
GMAIL_INCREMENTAL_MODE = "NOT_IMPLEMENTED_EXISTING_BEHAVIOR"


if __name__ == "__main__":
    raise SystemExit(main())
