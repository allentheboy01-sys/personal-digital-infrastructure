from copy import deepcopy

from pdi.decision import ActionType, Decision
from pdi.models import Asset, AssetSource, Blob

from .base import Repository, SourceIdentityAmbiguityError


class InMemoryRepository(Repository):
    def find_source_in_scope(
        self,
        observation_scope_id: str,
        external_id: str,
    ) -> AssetSource | None:
        matches = [
            source
            for source in self.sources.values()
            if source.observation_scope_id == observation_scope_id
            and source.external_id == external_id
        ]
        if len(matches) > 1:
            raise RuntimeError("Ambiguous scoped Source identity")
        return matches[0] if matches else None

    def list_active_sources_in_scope(
        self,
        observation_scope_id: str,
    ) -> list[AssetSource]:
        return [
            source
            for source in self.sources.values()
            if source.observation_scope_id == observation_scope_id
            and source.is_active
        ]

    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}
        self.blobs: dict[str, Blob] = {}
        self.sources: dict[str, AssetSource] = {}

    def find_source(
        self,
        provider: str,
        external_id: str,
    ) -> AssetSource | None:
        scoped_matches = []
        for source in self.sources.values():
            if (
                source.observation_scope_id is None
                and
                source.provider == provider
                and source.external_id == external_id
            ):
                return source

            if source.provider == provider and source.external_id == external_id:
                scoped_matches.append(source)

        if len(scoped_matches) > 1:
            raise SourceIdentityAmbiguityError(
                "Legacy Source identity is ambiguous across Observation Scopes"
            )

        return None

    def list_active_sources(
        self,
        provider: str,
    ) -> list[AssetSource]:
        return [
            source
            for source in self.sources.values()
            if (
                source.observation_scope_id is None
                and
                source.provider == provider
                and source.is_active
            )
        ]

    def find_blob_by_hash(
        self,
        content_hash: str,
    ) -> Blob | None:
        for blob in self.blobs.values():
            if blob.hash == content_hash:
                return blob

        return None

    def find_blob_by_hash_in_asset(
        self,
        content_hash: str,
        asset_id: str,
    ) -> Blob | None:
        for blob in self.blobs.values():
            if (
                blob.hash == content_hash
                and blob.asset_id == asset_id
            ):
                return blob

        return None

    def get_blob(
        self,
        blob_id: str,
    ) -> Blob | None:
        return self.blobs.get(blob_id)

    def get_asset(
        self,
        asset_id: str,
    ) -> Asset | None:
        return self.assets.get(asset_id)

    def execute(
        self,
        decision: Decision,
    ) -> None:
        self.execute_many((decision,))

    def execute_many(
        self,
        decisions: tuple[Decision, ...],
    ) -> None:
        snapshot = deepcopy((self.assets, self.blobs, self.sources))
        try:
            for decision in decisions:
                self._execute_decision(decision)
        except Exception:
            self.assets, self.blobs, self.sources = snapshot
            raise

    def _execute_decision(self, decision: Decision) -> None:
        for action in decision.actions:
            if action.type == ActionType.CREATE_ASSET:
                if action.asset is None:
                    raise ValueError(
                        "CREATE_ASSET requires asset"
                    )

                self.assets[action.asset.id] = action.asset

            elif action.type == ActionType.CREATE_BLOB:
                if action.blob is None:
                    raise ValueError(
                        "CREATE_BLOB requires blob"
                    )

                self.blobs[action.blob.id] = action.blob

            elif action.type == ActionType.CREATE_SOURCE:
                if action.source is None:
                    raise ValueError(
                        "CREATE_SOURCE requires source"
                    )

                self.sources[action.source.id] = action.source

            elif action.type == ActionType.UPDATE_SOURCE:
                if action.source is None:
                    raise ValueError(
                        "UPDATE_SOURCE requires source"
                    )

                if action.source.id not in self.sources:
                    raise ValueError(
                        f"Source not found: {action.source.id}"
                    )

                self.sources[action.source.id] = action.source

            elif action.type == ActionType.DEACTIVATE_SOURCE:
                if action.source is None:
                    raise ValueError(
                        "DEACTIVATE_SOURCE requires source"
                    )

                if action.source.id not in self.sources:
                    raise ValueError(
                        f"Source not found: {action.source.id}"
                    )

                stored = self.sources[action.source.id]
                stored.is_active = action.source.is_active
                stored.deleted_at = action.source.deleted_at

            else:
                raise ValueError(
                    f"Unsupported action type: {action.type}"
                )
