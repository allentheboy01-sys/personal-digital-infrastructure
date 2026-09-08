from abc import ABC, abstractmethod

from pdi.decision import Decision
from pdi.models import Asset, AssetSource, Blob


class SourceIdentityAmbiguityError(RuntimeError):
    """A legacy identity is ambiguous across multiple scoped Sources."""


class Repository(ABC):
    @abstractmethod
    def find_source_in_scope(
        self,
        observation_scope_id: str,
        external_id: str,
    ) -> AssetSource | None:
        """Find a Source by its authoritative scoped observation identity."""
        raise NotImplementedError

    @abstractmethod
    def list_active_sources_in_scope(
        self,
        observation_scope_id: str,
    ) -> list[AssetSource]:
        """List active Sources belonging to one Observation Scope."""
        raise NotImplementedError

    @abstractmethod
    def find_source(
        self,
        provider: str,
        external_id: str,
    ) -> AssetSource | None:
        """根据 Provider 内部身份查找已有 Source。"""
        raise NotImplementedError

    @abstractmethod
    def list_active_sources(
        self,
        provider: str,
    ) -> list[AssetSource]:
        """列出指定 Provider 当前仍处于 active 状态的 Sources。"""
        raise NotImplementedError

    @abstractmethod
    def find_blob_by_hash(
        self,
        content_hash: str,
    ) -> Blob | None:
        """根据内容 Hash 查找已有 Blob。"""
        raise NotImplementedError

    @abstractmethod
    def find_blob_by_hash_in_asset(
        self,
        content_hash: str,
        asset_id: str,
    ) -> Blob | None:
        """在指定 Asset 内根据内容 Hash 查找 Blob。"""
        raise NotImplementedError

    @abstractmethod
    def get_blob(
        self,
        blob_id: str,
    ) -> Blob | None:
        """根据 PDI 内部 ID 查找 Blob。"""
        raise NotImplementedError

    @abstractmethod
    def get_asset(
        self,
        asset_id: str,
    ) -> Asset | None:
        """根据 PDI 内部 ID 查找 Asset。"""
        raise NotImplementedError

    @abstractmethod
    def execute(
        self,
        decision: Decision,
    ) -> None:
        """执行 Identity 生成的 Decision。"""
        raise NotImplementedError

    @abstractmethod
    def execute_many(
        self,
        decisions: tuple[Decision, ...],
    ) -> None:
        """Atomically execute one reconciliation-critical Decision set."""
        raise NotImplementedError
