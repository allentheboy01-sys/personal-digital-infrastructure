from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from hashlib import sha256
from io import BytesIO
import json
from pathlib import PurePosixPath
import re
import signal
import sys
import tempfile
import threading
from typing import BinaryIO
from xml.etree.ElementTree import Element, ParseError
from zipfile import BadZipFile, ZipFile, ZipInfo

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from .errors import ObservationExtractionError
from .models import (
    EnrichmentResource,
    EnrichmentSource,
    Evidence,
    EvidenceSourceKind,
    GeneratorIdentity,
    ObservationBatch,
    StatementDraft,
    StatementValueType,
    TypedStatementValue,
)
from .nextcloud_text import (
    NextcloudContentReader,
    _extraction_error,
    _normalized_mime_type,
    _truncate_text,
)
from .predicates import DOCUMENT_TEXT_EXCERPT


PDF_MAX_SOURCE_BYTES = 32 * 1024 * 1024
ZIP_MAX_SOURCE_BYTES = 8 * 1024 * 1024
PDF_SPOOL_MEMORY_BYTES = 8 * 1024 * 1024
PDF_MAX_PAGES = 500
MAX_EXTRACTED_CHARACTERS = 1_048_576
ZIP_MAX_ENTRIES = 1024
ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
ZIP_MAX_ENTRY_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
ZIP_MAX_BODY_XML_BYTES = 16 * 1024 * 1024
ZIP_MAX_COMPRESSION_RATIO = 100
PARSER_DEADLINE_SECONDS = 30

DOCUMENT_GENERATOR_FAMILY = (
    "nextcloud_text",
    "nextcloud_pdf",
    "nextcloud_odt",
    "nextcloud_docx",
)

_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
_DRIVE_PATH = re.compile(r"[A-Za-z]:")
_OLE_COMPOUND_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")

_PDF_MIME = "application/pdf"
_ODT_MIME = "application/vnd.oasis.opendocument.text"
_DOCX_MIME = (
    "application/vnd.openxmlformats-officedocument."
    "wordprocessingml.document"
)

_ODF_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
_ODF_TEXT = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"
_ODF_TABLE = "urn:oasis:names:tc:opendocument:xmlns:table:1.0"
_ODF_MANIFEST = (
    "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
)
_WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

_ODT_EXCLUDED = {
    f"{{{_ODF_OFFICE}}}annotation",
    f"{{{_ODF_TEXT}}}tracked-changes",
    f"{{{_ODF_TEXT}}}change",
    f"{{{_ODF_TEXT}}}change-start",
    f"{{{_ODF_TEXT}}}change-end",
}
_DOCX_EXCLUDED = {
    f"{{{_WORD}}}ins",
    f"{{{_WORD}}}del",
    f"{{{_WORD}}}moveFrom",
    f"{{{_WORD}}}moveTo",
    f"{{{_WORD}}}drawing",
    f"{{{_WORD}}}pict",
    f"{{{_WORD}}}txbxContent",
}


class _ParserDeadlineExpired(Exception):
    pass


class _CharacterCollector:
    def __init__(self, limit: int = MAX_EXTRACTED_CHARACTERS) -> None:
        self._limit = limit
        self._parts: list[str] = []
        self._used = 0
        self._units = 0
        self.truncated = False

    @property
    def full(self) -> bool:
        return self._used >= self._limit

    def append(self, value: str) -> None:
        if not value or self.full:
            if value and self.full:
                self.truncated = True
            return
        remaining = self._limit - self._used
        if len(value) > remaining:
            self._parts.append(value[:remaining])
            self._used = self._limit
            self.truncated = True
            return
        self._parts.append(value)
        self._used += len(value)

    def add_unit(self, value: str, *, separator: str = "\n") -> None:
        if self._units:
            self.append(separator)
        self._units += 1
        self.append(value)

    def value(self) -> str:
        return "".join(self._parts)


def _eligible_source(
    source: EnrichmentSource,
    *,
    mime_type: str,
    extension: str,
) -> bool:
    if source.provider != "nextcloud":
        return False
    normalized_mime = _normalized_mime_type(source.mime_type)
    if normalized_mime == mime_type:
        return True
    if normalized_mime not in ("", "application/octet-stream"):
        return False
    candidate = source.name or source.path or ""
    return PurePosixPath(candidate).suffix.lower() == extension


def _selected_source(
    resource: EnrichmentResource,
    *,
    mime_type: str,
    extension: str,
) -> EnrichmentSource:
    eligible = tuple(
        source
        for source in resource.sources
        if _eligible_source(
            source,
            mime_type=mime_type,
            extension=extension,
        )
    )
    if not eligible:
        raise _extraction_error(
            "unsupported_document",
            "Resource has no eligible active Nextcloud document source",
        )

    by_digest: dict[str, list[EnrichmentSource]] = {}
    for source in eligible:
        digest = source.blob_sha256
        if (
            not isinstance(digest, str)
            or _SHA256_HEX.fullmatch(digest) is None
        ):
            raise _extraction_error(
                "invalid_blob_digest",
                "Nextcloud document source has no valid current Blob digest",
            )
        by_digest.setdefault(digest.lower(), []).append(source)
    if len(by_digest) != 1:
        raise _extraction_error(
            "ambiguous_active_nextcloud_content",
            "Multiple active Nextcloud document contents are ambiguous",
        )
    return min(
        next(iter(by_digest.values())),
        key=lambda source: source.source_id,
    )


def _input_fingerprint(
    source: EnrichmentSource,
    *,
    format_name: str,
    extractor: GeneratorIdentity,
) -> str:
    digest = source.blob_sha256
    if (
        not isinstance(digest, str)
        or _SHA256_HEX.fullmatch(digest) is None
    ):
        raise _extraction_error(
            "invalid_blob_digest",
            "Nextcloud document source has no valid current Blob digest",
        )
    payload = {
        "format": format_name,
        "provider": "nextcloud",
        "blob_sha256": digest.lower(),
        "mime_type": _normalized_mime_type(source.mime_type),
        "extractor_name": extractor.generator_name,
        "extractor_version": extractor.generator_version,
    }
    if source.observation_scope_id is not None:
        payload["source_id"] = source.source_id
        payload["observation_scope_id"] = source.observation_scope_id
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def _validate_declared_size(
    source: EnrichmentSource,
    maximum: int,
) -> None:
    if source.size is None:
        return
    if type(source.size) is not int or source.size < 0:
        raise _extraction_error(
            "invalid_source_size",
            "Nextcloud document source size is invalid",
        )
    if source.size > maximum:
        raise _extraction_error(
            "document_too_large",
            "Nextcloud document exceeds the extraction limit",
        )


def _read_chunks(
    reader: NextcloudContentReader,
    source: EnrichmentSource,
) -> Iterator[bytes]:
    stream = iter(reader.open(source))
    try:
        for chunk in stream:
            if not isinstance(chunk, bytes):
                raise _extraction_error(
                    "provider_invalid_response",
                    "Nextcloud content reader returned invalid bytes",
                )
            yield chunk
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            close()


def _verified_bytes(
    reader: NextcloudContentReader,
    source: EnrichmentSource,
    maximum: int,
) -> bytes:
    _validate_declared_size(source, maximum)
    content = bytearray()
    digest = sha256()
    for chunk in _read_chunks(reader, source):
        remaining = maximum + 1 - len(content)
        if remaining > 0:
            accepted = chunk[:remaining]
            content.extend(accepted)
            digest.update(accepted)
        if len(content) > maximum:
            raise _extraction_error(
                "document_too_large",
                "Nextcloud document exceeds the extraction limit",
            )
    if digest.hexdigest() != source.blob_sha256.lower():
        raise _extraction_error(
            "content_changed_since_sync",
            "Nextcloud content no longer matches the current Blob",
        )
    return bytes(content)


@contextmanager
def _verified_pdf_stream(
    reader: NextcloudContentReader,
    source: EnrichmentSource,
) -> Iterator[BinaryIO]:
    _validate_declared_size(source, PDF_MAX_SOURCE_BYTES)
    content = tempfile.SpooledTemporaryFile(
        max_size=PDF_SPOOL_MEMORY_BYTES,
        mode="w+b",
    )
    digest = sha256()
    size = 0
    try:
        for chunk in _read_chunks(reader, source):
            remaining = PDF_MAX_SOURCE_BYTES + 1 - size
            if remaining > 0:
                accepted = chunk[:remaining]
                content.write(accepted)
                digest.update(accepted)
                size += len(accepted)
            if size > PDF_MAX_SOURCE_BYTES:
                raise _extraction_error(
                    "document_too_large",
                    "Nextcloud document exceeds the extraction limit",
                )
        if digest.hexdigest() != source.blob_sha256.lower():
            raise _extraction_error(
                "content_changed_since_sync",
                "Nextcloud content no longer matches the current Blob",
            )
        content.seek(0)
        yield content
    finally:
        content.close()


@contextmanager
def _parser_deadline() -> Iterator[None]:
    supported = (
        sys.platform.startswith("linux")
        and threading.current_thread() is threading.main_thread()
        and hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
    )
    if not supported or signal.getitimer(signal.ITIMER_REAL)[0] != 0:
        yield
        return

    previous_handler = signal.getsignal(signal.SIGALRM)

    def expire(signum, frame) -> None:
        raise _ParserDeadlineExpired()

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, PARSER_DEADLINE_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _statement_batch(
    resource: EnrichmentResource,
    source: EnrichmentSource,
    *,
    generator: GeneratorIdentity,
    format_name: str,
    extracted_text: str,
) -> ObservationBatch:
    normalized = _normalize_newlines(extracted_text)
    statements: tuple[StatementDraft, ...] = ()
    if normalized.strip():
        statements = (
            StatementDraft(
                DOCUMENT_TEXT_EXCERPT,
                TypedStatementValue(
                    StatementValueType.STRING,
                    _truncate_text(normalized),
                ),
                Evidence(
                    EvidenceSourceKind.RESOURCE_CONTENT,
                    "nextcloud.webdav.content",
                ),
                None,
            ),
        )
    return ObservationBatch(
        resource.resource_ref,
        generator,
        (DOCUMENT_TEXT_EXCERPT,),
        _input_fingerprint(
            source,
            format_name=format_name,
            extractor=generator,
        ),
        statements,
    )


def _extract_pdf_text(stream: BinaryIO) -> str:
    collector = _CharacterCollector()
    try:
        with _parser_deadline():
            reader = PdfReader(stream, strict=False)
            if reader.is_encrypted:
                raise _extraction_error(
                    "encrypted_document",
                    "Encrypted PDF documents are not supported",
                )
            if len(reader.pages) > PDF_MAX_PAGES:
                raise _extraction_error(
                    "document_too_large",
                    "PDF exceeds the page extraction limit",
                )
            for page in reader.pages:
                if collector.full:
                    collector.truncated = True
                    break
                page_text = page.extract_text() or ""
                page_text = _normalize_newlines(
                    page_text.replace("\f", "\n")
                )
                collector.add_unit(page_text, separator="\n\n")
    except ObservationExtractionError:
        raise
    except _ParserDeadlineExpired as error:
        raise _extraction_error(
            "document_parse_failed",
            "Document parsing exceeded the resource deadline",
        ) from error
    except PdfReadError as error:
        raise _extraction_error(
            "invalid_document",
            "PDF document is invalid",
        ) from error
    except Exception as error:
        raise _extraction_error(
            "document_parse_failed",
            "PDF document could not be parsed",
        ) from error
    return collector.value()


def _unsafe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        not name
        or "\\" in name
        or name.startswith("/")
        or bool(_DRIVE_PATH.match(name))
        or path.is_absolute()
        or ".." in path.parts
    )


def _validate_zip_inventory(infos: list[ZipInfo]) -> None:
    if len(infos) > ZIP_MAX_ENTRIES:
        raise _extraction_error(
            "archive_limit_exceeded",
            "Document archive contains too many entries",
        )
    if len({info.filename for info in infos}) != len(infos):
        raise _extraction_error(
            "invalid_document",
            "Document archive contains duplicate entries",
        )
    total = 0
    for info in infos:
        if _unsafe_archive_name(info.filename):
            raise _extraction_error(
                "invalid_document",
                "Document archive contains an unsafe entry name",
            )
        if info.flag_bits & 0x1:
            raise _extraction_error(
                "encrypted_document",
                "Encrypted document archives are not supported",
            )
        if info.file_size > ZIP_MAX_ENTRY_UNCOMPRESSED_BYTES:
            raise _extraction_error(
                "archive_limit_exceeded",
                "Document archive entry exceeds the extraction limit",
            )
        total += info.file_size
        if total > ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise _extraction_error(
                "archive_limit_exceeded",
                "Document archive exceeds the extraction limit",
            )
        if info.file_size > 0 and info.compress_size == 0:
            raise _extraction_error(
                "invalid_document",
                "Document archive entry has an impossible size",
            )
        if (
            info.compress_size > 0
            and info.file_size / info.compress_size
            > ZIP_MAX_COMPRESSION_RATIO
        ):
            raise _extraction_error(
                "archive_limit_exceeded",
                "Document archive compression ratio exceeds the limit",
            )


def _read_archive_parts(
    content: bytes,
    *,
    required_body: str,
    retained: Iterable[str] = (),
) -> dict[str, bytes]:
    wanted = {required_body, *retained}
    retained_parts: dict[str, bytes] = {}
    try:
        with ZipFile(BytesIO(content)) as archive:
            infos = archive.infolist()
            _validate_zip_inventory(infos)
            by_name = {info.filename: info for info in infos}
            body_info = by_name.get(required_body)
            if body_info is None or body_info.is_dir():
                raise _extraction_error(
                    "invalid_document",
                    "Document archive is missing its required body",
                )
            if body_info.file_size > ZIP_MAX_BODY_XML_BYTES:
                raise _extraction_error(
                    "archive_limit_exceeded",
                    "Document body XML exceeds the extraction limit",
                )

            actual_total = 0
            for info in infos:
                if info.is_dir():
                    continue
                entry = bytearray()
                actual_entry = 0
                with archive.open(info, "r") as source:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        actual_entry += len(chunk)
                        actual_total += len(chunk)
                        if (
                            actual_entry
                            > ZIP_MAX_ENTRY_UNCOMPRESSED_BYTES
                            or actual_total
                            > ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES
                        ):
                            raise _extraction_error(
                                "archive_limit_exceeded",
                                "Document archive exceeds the extraction limit",
                            )
                        if info.filename in wanted:
                            if len(entry) + len(chunk) > ZIP_MAX_BODY_XML_BYTES:
                                raise _extraction_error(
                                    "archive_limit_exceeded",
                                    "Document XML exceeds the extraction limit",
                                )
                            entry.extend(chunk)
                if actual_entry != info.file_size:
                    raise _extraction_error(
                        "invalid_document",
                        "Document archive entry size is inconsistent",
                    )
                if info.filename in wanted:
                    retained_parts[info.filename] = bytes(entry)
    except ObservationExtractionError:
        raise
    except (BadZipFile, RuntimeError, NotImplementedError, EOFError) as error:
        raise _extraction_error(
            "invalid_document",
            "Document archive is invalid",
        ) from error
    return retained_parts


def _safe_xml_root(content: bytes) -> Element:
    if len(content) > ZIP_MAX_BODY_XML_BYTES:
        raise _extraction_error(
            "archive_limit_exceeded",
            "Document XML exceeds the extraction limit",
        )
    try:
        with _parser_deadline():
            return SafeElementTree.fromstring(
                content,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
    except _ParserDeadlineExpired as error:
        raise _extraction_error(
            "document_parse_failed",
            "Document parsing exceeded the resource deadline",
        ) from error
    except (DefusedXmlException, ParseError) as error:
        raise _extraction_error(
            "invalid_document",
            "Document XML is invalid",
        ) from error


def _parse_document(
    operation: Callable[[], str],
    document_type: str,
) -> str:
    try:
        with _parser_deadline():
            return operation()
    except ObservationExtractionError:
        raise
    except _ParserDeadlineExpired as error:
        raise _extraction_error(
            "document_parse_failed",
            "Document parsing exceeded the resource deadline",
        ) from error
    except Exception as error:
        raise _extraction_error(
            "document_parse_failed",
            f"{document_type} document could not be parsed",
        ) from error


def _render_odt_inline(element: Element) -> str:
    collector = _CharacterCollector()

    def visit(node: Element) -> None:
        if collector.full or node.tag in _ODT_EXCLUDED:
            return
        collector.append(node.text or "")
        for child in node:
            if collector.full:
                collector.truncated = True
                return
            if child.tag in _ODT_EXCLUDED:
                pass
            elif child.tag == f"{{{_ODF_TEXT}}}s":
                raw_count = child.attrib.get(f"{{{_ODF_TEXT}}}c", "1")
                try:
                    count = int(raw_count)
                except ValueError as error:
                    raise _extraction_error(
                        "invalid_document",
                        "ODT explicit space count is invalid",
                    ) from error
                if count < 1:
                    raise _extraction_error(
                        "invalid_document",
                        "ODT explicit space count is invalid",
                    )
                collector.append(" " * min(count, MAX_EXTRACTED_CHARACTERS))
            elif child.tag == f"{{{_ODF_TEXT}}}tab":
                collector.append("\t")
            elif child.tag == f"{{{_ODF_TEXT}}}line-break":
                collector.append("\n")
            else:
                visit(child)
            collector.append(child.tail or "")

    visit(element)
    return collector.value()


def _odt_cell_text(cell: Element) -> str:
    values: list[str] = []

    def visit(node: Element) -> None:
        if node.tag in _ODT_EXCLUDED:
            return
        if node.tag in (
            f"{{{_ODF_TEXT}}}p",
            f"{{{_ODF_TEXT}}}h",
        ):
            values.append(_render_odt_inline(node))
            return
        if node.tag == f"{{{_ODF_TABLE}}}table":
            values.append(_odt_table_text(node))
            return
        for child in node:
            visit(child)

    for child in cell:
        visit(child)
    return "\n".join(values)


def _odt_table_rows(table: Element) -> Iterator[Element]:
    def visit(node: Element) -> Iterator[Element]:
        for child in node:
            if child.tag == f"{{{_ODF_TABLE}}}table-row":
                yield child
            elif child.tag != f"{{{_ODF_TABLE}}}table":
                yield from visit(child)

    yield from visit(table)


def _odt_table_text(table: Element) -> str:
    rows: list[str] = []
    for row in _odt_table_rows(table):
        cells = [
            child
            for child in row
            if child.tag
            in (
                f"{{{_ODF_TABLE}}}table-cell",
                f"{{{_ODF_TABLE}}}covered-table-cell",
            )
        ]
        rows.append("\t".join(_odt_cell_text(cell) for cell in cells))
    return "\n".join(rows)


def _extract_odt_body(root: Element) -> str:
    body = root.find(
        f".//{{{_ODF_OFFICE}}}body/{{{_ODF_OFFICE}}}text"
    )
    if body is None:
        raise _extraction_error(
            "invalid_document",
            "ODT document body is missing",
        )
    collector = _CharacterCollector()

    def visit(node: Element) -> None:
        if collector.full or node.tag in _ODT_EXCLUDED:
            return
        if node.tag in (
            f"{{{_ODF_TEXT}}}p",
            f"{{{_ODF_TEXT}}}h",
        ):
            collector.add_unit(_render_odt_inline(node))
            return
        if node.tag == f"{{{_ODF_TABLE}}}table":
            for row_text in _odt_table_text(node).split("\n"):
                collector.add_unit(row_text)
                if collector.full:
                    break
            return
        for child in node:
            visit(child)
            if collector.full:
                break

    visit(body)
    return collector.value()


def _extract_odt_text(content: bytes) -> str:
    parts = _read_archive_parts(
        content,
        required_body="content.xml",
        retained=("META-INF/manifest.xml",),
    )
    manifest = parts.get("META-INF/manifest.xml")
    if manifest is not None:
        manifest_root = _safe_xml_root(manifest)
        if manifest_root.find(
            f".//{{{_ODF_MANIFEST}}}encryption-data"
        ) is not None:
            raise _extraction_error(
                "encrypted_document",
                "Encrypted ODT documents are not supported",
            )
    return _extract_odt_body(_safe_xml_root(parts["content.xml"]))


def _render_docx_inline(element: Element) -> str:
    collector = _CharacterCollector()

    def visit(node: Element) -> None:
        if collector.full or node.tag in _DOCX_EXCLUDED:
            return
        if node.tag == f"{{{_WORD}}}t":
            collector.append(node.text or "")
            return
        if node.tag == f"{{{_WORD}}}tab":
            collector.append("\t")
            return
        if node.tag in (f"{{{_WORD}}}br", f"{{{_WORD}}}cr"):
            collector.append("\n")
            return
        for child in node:
            visit(child)
            if collector.full:
                break

    visit(element)
    return collector.value()


def _docx_cell_text(cell: Element) -> str:
    values: list[str] = []
    for child in cell:
        if child.tag == f"{{{_WORD}}}p":
            values.append(_render_docx_inline(child))
        elif child.tag == f"{{{_WORD}}}tbl":
            values.append(_docx_table_text(child))
    return "\n".join(values)


def _docx_table_text(table: Element) -> str:
    rows: list[str] = []
    for row in table:
        if row.tag != f"{{{_WORD}}}tr":
            continue
        cells = [
            _docx_cell_text(cell)
            for cell in row
            if cell.tag == f"{{{_WORD}}}tc"
        ]
        rows.append("\t".join(cells))
    return "\n".join(rows)


def _extract_docx_body(root: Element) -> str:
    body = root.find(f"{{{_WORD}}}body")
    if body is None:
        raise _extraction_error(
            "invalid_document",
            "DOCX document body is missing",
        )
    collector = _CharacterCollector()
    for child in body:
        if child.tag == f"{{{_WORD}}}p":
            collector.add_unit(_render_docx_inline(child))
        elif child.tag == f"{{{_WORD}}}tbl":
            collector.add_unit(_docx_table_text(child))
        if collector.full:
            break
    return collector.value()


def _extract_docx_text(content: bytes) -> str:
    if content.startswith(_OLE_COMPOUND_MAGIC):
        raise _extraction_error(
            "encrypted_document",
            "Encrypted DOCX documents are not supported",
        )
    parts = _read_archive_parts(
        content,
        required_body="word/document.xml",
    )
    return _extract_docx_body(
        _safe_xml_root(parts["word/document.xml"])
    )


class NextcloudPDFExtractor:
    generator = GeneratorIdentity(
        "deterministic_extractor",
        "nextcloud_pdf",
        "1",
    )
    covered_predicates = (DOCUMENT_TEXT_EXCERPT,)
    exclusive_generator_family = DOCUMENT_GENERATOR_FAMILY

    def __init__(self, reader: NextcloudContentReader) -> None:
        self._reader = reader

    @staticmethod
    def is_eligible(resource: EnrichmentResource) -> bool:
        return any(
            _eligible_source(
                source,
                mime_type=_PDF_MIME,
                extension=".pdf",
            )
            for source in resource.sources
        )

    def _source(self, resource: EnrichmentResource) -> EnrichmentSource:
        return _selected_source(
            resource,
            mime_type=_PDF_MIME,
            extension=".pdf",
        )

    def input_fingerprint(self, resource: EnrichmentResource) -> str:
        return _input_fingerprint(
            self._source(resource),
            format_name="pdi.nextcloud_pdf.input.v1",
            extractor=self.generator,
        )

    def extract(self, resource: EnrichmentResource) -> ObservationBatch:
        source = self._source(resource)
        with _verified_pdf_stream(self._reader, source) as stream:
            text = _extract_pdf_text(stream)
        return _statement_batch(
            resource,
            source,
            generator=self.generator,
            format_name="pdi.nextcloud_pdf.input.v1",
            extracted_text=text,
        )


class NextcloudODTExtractor:
    generator = GeneratorIdentity(
        "deterministic_extractor",
        "nextcloud_odt",
        "1",
    )
    covered_predicates = (DOCUMENT_TEXT_EXCERPT,)
    exclusive_generator_family = DOCUMENT_GENERATOR_FAMILY

    def __init__(self, reader: NextcloudContentReader) -> None:
        self._reader = reader

    @staticmethod
    def is_eligible(resource: EnrichmentResource) -> bool:
        return any(
            _eligible_source(
                source,
                mime_type=_ODT_MIME,
                extension=".odt",
            )
            for source in resource.sources
        )

    def _source(self, resource: EnrichmentResource) -> EnrichmentSource:
        return _selected_source(
            resource,
            mime_type=_ODT_MIME,
            extension=".odt",
        )

    def input_fingerprint(self, resource: EnrichmentResource) -> str:
        return _input_fingerprint(
            self._source(resource),
            format_name="pdi.nextcloud_odt.input.v1",
            extractor=self.generator,
        )

    def extract(self, resource: EnrichmentResource) -> ObservationBatch:
        source = self._source(resource)
        content = _verified_bytes(
            self._reader,
            source,
            ZIP_MAX_SOURCE_BYTES,
        )
        return _statement_batch(
            resource,
            source,
            generator=self.generator,
            format_name="pdi.nextcloud_odt.input.v1",
            extracted_text=_parse_document(
                lambda: _extract_odt_text(content),
                "ODT",
            ),
        )


class NextcloudDOCXExtractor:
    generator = GeneratorIdentity(
        "deterministic_extractor",
        "nextcloud_docx",
        "1",
    )
    covered_predicates = (DOCUMENT_TEXT_EXCERPT,)
    exclusive_generator_family = DOCUMENT_GENERATOR_FAMILY

    def __init__(self, reader: NextcloudContentReader) -> None:
        self._reader = reader

    @staticmethod
    def is_eligible(resource: EnrichmentResource) -> bool:
        return any(
            _eligible_source(
                source,
                mime_type=_DOCX_MIME,
                extension=".docx",
            )
            for source in resource.sources
        )

    def _source(self, resource: EnrichmentResource) -> EnrichmentSource:
        return _selected_source(
            resource,
            mime_type=_DOCX_MIME,
            extension=".docx",
        )

    def input_fingerprint(self, resource: EnrichmentResource) -> str:
        return _input_fingerprint(
            self._source(resource),
            format_name="pdi.nextcloud_docx.input.v1",
            extractor=self.generator,
        )

    def extract(self, resource: EnrichmentResource) -> ObservationBatch:
        source = self._source(resource)
        content = _verified_bytes(
            self._reader,
            source,
            ZIP_MAX_SOURCE_BYTES,
        )
        return _statement_batch(
            resource,
            source,
            generator=self.generator,
            format_name="pdi.nextcloud_docx.input.v1",
            extracted_text=_parse_document(
                lambda: _extract_docx_text(content),
                "DOCX",
            ),
        )
