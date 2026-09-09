import logging
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import deque
from typing import Iterable
from xml.sax.saxutils import escape

import requests

from pdi.adapters.base import (
    Adapter,
    ProviderFact,
    ProviderResourceDisappearedError,
)


logger = logging.getLogger(__name__)


class NextcloudAdapter(Adapter):
    provider_name = "nextcloud"
    _CONTENT_READ_ATTEMPTS = 2

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password

    def connect(self) -> None:
        """Validate credentials against the configured user's WebDAV root."""
        facts = self._request_propfind(
            "",
            depth="0",
            include_self=True,
        )
        if len(facts) != 1 or facts[0].kind != "folder":
            raise ValueError(
                "Nextcloud user WebDAV root is unavailable or malformed"
            )

    def scan(self, path: str = "") -> Iterable[ProviderFact]:
        """扫描指定 Nextcloud 目录下的完整可见文件树。"""
        started_at = time.perf_counter()
        root_path = self._normalize_traversal_path(path)
        pending_directories = deque([root_path])
        visited_directories: set[str] = set()
        fact_count = 0

        logger.info(
            "Scanning Nextcloud recursively path=%s",
            root_path or "/",
        )

        while pending_directories:
            current_path = pending_directories.popleft()

            if current_path in visited_directories:
                continue

            visited_directories.add(current_path)

            for fact in self._propfind(current_path):
                fact_count += 1

                if fact.kind == "folder":
                    directory_path = fact.attributes.get("path")

                    if not isinstance(directory_path, str):
                        raise ValueError(
                            "Nextcloud folder does not contain a valid path"
                        )

                    normalized_path = self._normalize_traversal_path(
                        directory_path
                    )

                    if not normalized_path:
                        raise ValueError(
                            "Nextcloud child folder has an empty path"
                        )

                    if normalized_path not in visited_directories:
                        pending_directories.append(normalized_path)

                yield fact

        duration = time.perf_counter() - started_at

        logger.info(
            "Nextcloud scan finished directories=%d facts=%d duration=%.2fs",
            len(visited_directories),
            fact_count,
            duration,
        )

    def open(
        self,
        fact: ProviderFact,
    ) -> Iterable[bytes]:
        if fact.provider != self.provider_name:
            raise ValueError(
                f"ProviderFact belongs to {fact.provider}, "
                f"not {self.provider_name}"
            )

        if fact.kind != "file":
            raise ValueError("Only files can be opened")

        href = fact.raw.get("href")
        if not isinstance(href, str) or not href:
            raise ValueError("ProviderFact does not contain a valid href")

        url = f"{self.base_url}{href}"

        for attempt in range(self._CONTENT_READ_ATTEMPTS):
            response = requests.get(
                url,
                auth=(self.username, self.password),
                stream=True,
                timeout=30,
            )

            try:
                response.raise_for_status()
            except requests.HTTPError:
                status_code = response.status_code
                response.close()

                if status_code not in {404, 410}:
                    raise

                if attempt + 1 < self._CONTENT_READ_ATTEMPTS:
                    continue

                raise ProviderResourceDisappearedError(
                    self.provider_name
                ) from None

            try:
                for chunk in response.iter_content(
                    chunk_size=1024 * 1024,
                ):
                    if chunk:
                        yield chunk
            finally:
                response.close()

            return

    def _propfind(self, path: str) -> list[ProviderFact]:
        """向 Nextcloud WebDAV 发送 PROPFIND 请求。"""
        return self._request_propfind(path, depth="1", include_self=False)

    def propfind_exact(self, path: str) -> ProviderFact | None:
        """Revalidate one current resource without traversing its subtree."""
        facts = self._request_propfind(path, depth="0", include_self=True)
        if not facts:
            return None
        if len(facts) != 1:
            raise ValueError("Exact Nextcloud PROPFIND returned multiple resources")
        return facts[0]

    def search_by_fileid(self, file_id: str) -> ProviderFact | None:
        """Locate a current WebDAV resource in the configured user scope."""
        if not isinstance(file_id, str) or not file_id:
            raise ValueError("Nextcloud fileid must be a non-empty string")
        scope = f"/files/{self.username}"
        body = f"""<?xml version="1.0" encoding="UTF-8"?>
<d:searchrequest xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:basicsearch>
    <d:select><d:prop><oc:id/><oc:fileid/><d:getcontentlength/>
      <d:getcontenttype/><d:getetag/><d:getlastmodified/>
      <d:resourcetype/></d:prop></d:select>
    <d:from><d:scope><d:href>{scope}</d:href><d:depth>infinity</d:depth>
      </d:scope></d:from>
    <d:where><d:eq><d:prop><oc:fileid/></d:prop>
      <d:literal>{escape(file_id)}</d:literal></d:eq></d:where>
  </d:basicsearch>
</d:searchrequest>
"""
        response = requests.request(
            method="SEARCH",
            url=f"{self.base_url}/remote.php/dav/",
            headers={"Content-Type": "application/xml"},
            data=body,
            auth=(self.username, self.password),
            timeout=10,
        )
        response.raise_for_status()
        facts = self._parse_webdav_response(
            response.text, current_path="", include_self=True
        )
        if len(facts) > 1:
            raise ValueError("Nextcloud fileid SEARCH returned multiple resources")
        return facts[0] if facts else None

    def _request_propfind(
        self,
        path: str,
        *,
        depth: str,
        include_self: bool,
    ) -> list[ProviderFact]:
        normalized_path = self._normalize_traversal_path(path)
        encoded_path = urllib.parse.quote(
            normalized_path,
            safe="/",
        )

        url = (
            f"{self.base_url}"
            f"/remote.php/dav/files/{self.username}/"
        )

        if encoded_path:
            url += encoded_path
            if depth == "1":
                url += "/"

        headers = {
            "Depth": depth,
            "Content-Type": "application/xml",
        }

        body = """<?xml version="1.0" encoding="UTF-8"?>
<d:propfind
    xmlns:d="DAV:"
    xmlns:oc="http://owncloud.org/ns">
  <d:prop>
    <oc:id />
    <oc:fileid />
    <d:getcontentlength />
    <d:getcontenttype />
    <d:getetag />
    <d:getlastmodified />
    <d:resourcetype />
  </d:prop>
</d:propfind>
"""

        response = requests.request(
            method="PROPFIND",
            url=url,
            headers=headers,
            data=body,
            auth=(self.username, self.password),
            timeout=10,
        )

        try:
            response.raise_for_status()
        except requests.HTTPError:
            if include_self and response.status_code in {404, 410}:
                return []
            raise

        return self._parse_webdav_response(
            response.text,
            current_path=normalized_path,
            include_self=include_self,
        )

    def _parse_webdav_response(
        self,
        xml_text: str,
        current_path: str,
        include_self: bool = False,
    ) -> list[ProviderFact]:
        """把 Nextcloud WebDAV XML 转换成统一的 ProviderFact。"""
        namespace = {
            "d": "DAV:",
            "oc": "http://owncloud.org/ns",
        }

        root = ET.fromstring(xml_text)

        facts: list[ProviderFact] = []

        for item in root.findall("d:response", namespace):
            href = self._get_text(
                item,
                "d:href",
                namespace,
            )

            if not isinstance(href, str) or not href:
                raise ValueError(
                    "Nextcloud WebDAV response contains an invalid href"
                )

            path = self._clean_href(href)

            if not isinstance(path, str):
                raise ValueError(
                    "Nextcloud WebDAV response contains an invalid path"
                )

            # 每次 Depth=1 PROPFIND 通常都会返回当前 collection 自身。
            if not include_self and self._normalize_traversal_path(
                path
            ) == self._normalize_traversal_path(current_path):
                continue

            prop = item.find(
                "d:propstat/d:prop",
                namespace,
            )

            if prop is None:
                raise ValueError(
                    "Nextcloud WebDAV response does not contain properties"
                )

            resource_type = prop.find(
                "d:resourcetype",
                namespace,
            )

            is_collection = (
                resource_type is not None
                and resource_type.find(
                    "d:collection",
                    namespace,
                )
                is not None
            )

            oc_id = self._get_text(
                prop,
                "oc:id",
                namespace,
            )

            if not oc_id:
                raise ValueError(
                    "Nextcloud WebDAV response does not contain oc:id"
                )

            file_id = self._get_text(
                prop,
                "oc:fileid",
                namespace,
            )

            size_text = self._get_text(
                prop,
                "d:getcontentlength",
                namespace,
            )

            size = int(size_text) if size_text else None

            name = (
                path.rstrip("/").split("/")[-1]
                if path
                else None
            )

            mime_type = self._get_text(
                prop,
                "d:getcontenttype",
                namespace,
            )

            modified_at = self._get_text(
                prop,
                "d:getlastmodified",
                namespace,
            )

            etag = self._get_text(
                prop,
                "d:getetag",
                namespace,
            )

            facts.append(
                ProviderFact(
                    provider=self.provider_name,
                    kind=(
                        "folder"
                        if is_collection
                        else "file"
                    ),

                    # oc:id 在 Nextcloud 实例标识的基础上，
                    # 对 fileid 进行了命名空间处理。
                    external_id=oc_id,

                    name=name,

                    # attributes 中保存已经标准化的数据。
                    attributes={
                        "path": path,
                        "size": size,
                        "mime_type": mime_type,
                        "modified_at": modified_at,

                        # Nextcloud ETag 只作为 Provider 版本标识，
                        # 不能作为跨 Provider 内容 Hash。
                        "version_tag": etag,

                        # 当前 Adapter 还没有下载内容计算 Hash。
                        "content_hash": None,
                    },

                    # raw 中保存 Provider 原始或特有数据，
                    # Identity 不应该直接依赖这些字段。
                    raw={
                        "href": href,
                        "oc_id": oc_id,
                        "file_id": file_id,
                        "is_collection": is_collection,
                        "getlastmodified": modified_at,
                    },
                )
            )

        return facts

    @staticmethod
    def _normalize_traversal_path(path: str) -> str:
        """Normalize a WebDAV path only for traversal bookkeeping."""
        return path.strip("/")

    def _clean_href(
        self,
        href: str | None,
    ) -> str | None:
        """把 WebDAV href 转换为用户目录内的相对路径。"""
        if href is None:
            return None

        prefix = (
            f"/remote.php/dav/files/"
            f"{self.username}/"
        )

        decoded = urllib.parse.unquote(href)

        if decoded.startswith(prefix):
            return decoded[len(prefix):]

        return None

    @staticmethod
    def _get_text(
        element: ET.Element,
        path: str,
        namespace: dict[str, str],
    ) -> str | None:
        found = element.find(
            path,
            namespace,
        )

        if found is None:
            return None

        return found.text
