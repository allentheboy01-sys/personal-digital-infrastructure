from __future__ import annotations

from base64 import b64encode
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from uuid import UUID, uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from pdi.database import create_postgres_engine
from pdi.production_ops.contracts import QUALIFICATION, parse_env
from pdi.production_ops.cutover import Host as FrozenP3CHost, Paths as FrozenP3CPaths
from pdi.production_ops.p3d_disposable_rehearsal import (
    CANONICAL_PIPELINES,
    SERVICE_UNITS,
    machine_name_for,
)
from pdi.production_ops.enrichment_cutover import P3D_TIMER_UNITS
from pdi.production_ops.p3d_preparation_contracts import (
    OperatorToolIdentity,
    ToolName,
)
from pdi.production_ops.p3d_release_bootstrap import (
    BootstrapInputs,
    BootstrapPolicy,
    QualificationHostRuntimeAuthorityProvider,
    ReleaseBootstrap,
    resolve_runtime_identity,
)
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.scope_sync_state import PostgreSQLScopeSyncStateRepository
from tests.integration.database_guard import require_safe_test_database_url
from tests.integration.test_p3d_inert_asset_install import (
    _clean,
    _create_complete_gate_a,
    _write,
)


ROOT = Path(__file__).resolve().parents[2]
H1 = "1" * 64
SOURCE = "b" * 40
IMMICH_ACCOUNT_ID = "33333333-3333-4333-8333-333333333333"
PRINCIPAL_ID = "44444444-4444-4444-8444-444444444444"
SYSTEMD_NSPAWN = Path("/usr/bin/systemd-nspawn")
MACHINECTL = Path("/usr/bin/machinectl")
_DIAGNOSTIC_LIMIT = 64 * 1024
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(DATABASE__URL|PASSWORD|API[_-]?KEY|ACCESS[_-]?TOKEN|"
    r"REFRESH[_-]?TOKEN|OAUTH|SECRET)\b\s*[:=]\s*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s\r\n]+)"
)
_PROTECTED_SECRET_MARKERS = (
    "DATABASE__URL",
    "NEXTCLOUD__PASSWORD",
    "IMMICH__API_KEY",
)


@dataclass(frozen=True)
class _ManagerStartupDiagnostic:
    failure_class: str
    diagnostic_class: str
    nspawn_exit_code: int | None
    nspawn_stdout_sha256: str
    nspawn_stderr_sha256: str
    machinectl_return_code: int
    machinectl_stdout_sha256: str
    machinectl_stderr_sha256: str
    diagnostic_safe_excerpt: str
    nspawn_stderr_safe_excerpt: str
    machinectl_stderr_safe_excerpt: str
    sanitized_nspawn_stdout: str
    sanitized_nspawn_stderr: str
    sanitized_machinectl_stdout: str
    sanitized_machinectl_stderr: str

    def safe_message(self) -> str:
        exit_code = -1 if self.nspawn_exit_code is None else self.nspawn_exit_code
        lines = [
            self.failure_class,
            f"NSPAWN_EXIT_CODE={exit_code}",
            f"NSPAWN_FAILURE_CLASS={self.failure_class}",
            f"NSPAWN_DIAGNOSTIC_CLASS={self.diagnostic_class}",
            f"NSPAWN_STDOUT_SHA256={self.nspawn_stdout_sha256}",
            f"NSPAWN_STDERR_SHA256={self.nspawn_stderr_sha256}",
            f"MACHINECTL_RETURN_CODE={self.machinectl_return_code}",
            f"MACHINECTL_STDOUT_SHA256={self.machinectl_stdout_sha256}",
            f"MACHINECTL_STDERR_SHA256={self.machinectl_stderr_sha256}",
        ]
        if self.diagnostic_safe_excerpt == "PASS":
            lines.extend((
                "DIAGNOSTIC_SAFE_EXCERPT=PASS",
                f"NSPAWN_STDERR_SAFE_EXCERPT={self.nspawn_stderr_safe_excerpt}",
                "MACHINECTL_STDERR_SAFE_EXCERPT="
                f"{self.machinectl_stderr_safe_excerpt}",
            ))
        else:
            lines.append("DIAGNOSTIC_SAFE_EXCERPT=REDACTED")
        return "\n".join(lines)


class _ManagerStartupError(AssertionError):
    def __init__(self, diagnostic: _ManagerStartupDiagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.safe_message())


def _environment() -> tuple[Path, Path, Path, Path, str]:
    names = (
        "PDI_P3D_WP7_BUNDLE",
        "PDI_P3D_WP7_DIGESTS",
        "PDI_P3D_WP7_REHEARSAL_ROOT",
        "PDI_P3D_WP7_SYSTEM_PYTHON",
        "PDI_P3D_WP7_CANDIDATE_SHA",
    )
    if any(not os.environ.get(name) for name in names):
        pytest.skip("dedicated WP7 disposable real-systemd qualification only")
    return (
        Path(os.environ[names[0]]),
        Path(os.environ[names[1]]),
        Path(os.environ[names[2]]),
        Path(os.environ[names[3]]),
        os.environ[names[4]],
    )


def _docx(content: str) -> bytes:
    output = BytesIO()
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
        'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
        f"{content}"
        "</w:t></w:r></w:p></w:body></w:document>"
    ).encode()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", document)
    return output.getvalue()


class _ProviderFixtureHandler(BaseHTTPRequestHandler):
    text_content = b"Synthetic scoped Nextcloud text\n"
    document_content = _docx("Synthetic scoped Nextcloud document")
    nextcloud_authorization = "Basic " + b64encode(
        b"synthetic:synthetic-nextcloud-password"
    ).decode()
    immich_key = "synthetic-immich-api-key"
    calls: list[str] = []

    def log_message(self, format, *args):  # noqa: A002 - stdlib override
        return

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_PROPFIND(self):  # noqa: N802 - HTTP handler API
        if self.headers.get("Authorization") != self.nextcloud_authorization:
            self._send(401, b"", "text/plain")
            return
        self.calls.append("nextcloud-propfind")
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
            '<d:response><d:href>/remote.php/dav/files/synthetic/</d:href>'
            '<d:propstat><d:prop><oc:id>synthetic-root</oc:id>'
            '<oc:fileid>synthetic-root</oc:fileid>'
            '<d:resourcetype><d:collection/></d:resourcetype>'
            '</d:prop></d:propstat></d:response></d:multistatus>'
        ).encode()
        self._send(207, payload, "application/xml")

    def do_GET(self):  # noqa: N802 - HTTP handler API
        if self.path.startswith("/content/"):
            if self.headers.get("Authorization") != self.nextcloud_authorization:
                self._send(401, b"", "text/plain")
                return
            self.calls.append("nextcloud-content")
            payload = (
                self.text_content
                if self.path == "/content/notes.md"
                else self.document_content
            )
            self._send(200, payload, "application/octet-stream")
            return
        if self.headers.get("x-api-key") != self.immich_key:
            self._send(401, b"{}", "application/json")
            return
        if self.path == "/api/users/me":
            self.calls.append("immich-account")
            self._send(
                200,
                json.dumps({"id": IMMICH_ACCOUNT_ID}).encode(),
                "application/json",
            )
            return
        if self.path == f"/api/assets/{IMMICH_ACCOUNT_ID}/ocr":
            self.calls.append("immich-ocr")
            self._send(
                200,
                json.dumps([{"text": "Synthetic OCR evidence"}]).encode(),
                "application/json",
            )
            return
        self._send(404, b"{}", "application/json")


@contextmanager
def _provider_fixture():
    _ProviderFixtureHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], _ProviderFixtureHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _seed_database(url: str):
    engine = create_postgres_engine(url)
    with engine.connect() as connection:
        config = Config(str(ROOT / "alembic.ini"))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    _clean(engine)
    identities = PostgreSQLProviderIdentityRepository(engine)
    scopes = {}
    for provider, enabled in (
        ("nextcloud", True),
        ("immich", True),
        ("gmail", False),
        ("integration-test", False),
    ):
        instance = identities.create_instance(
            provider_type=provider,
            instance_key=f"wp7-{provider}",
            enabled=enabled,
        )
        account = None
        if enabled:
            account = identities.create_account(
                provider_instance_id=instance.id,
                account_key=f"wp7-{provider}",
                provider_native_id=(
                    IMMICH_ACCOUNT_ID if provider == "immich" else "synthetic-nextcloud"
                ),
                enabled=True,
            )
        scopes[provider] = identities.create_scope(
            provider_instance_id=instance.id,
            provider_account_id=None if account is None else account.id,
            scope_key=f"wp7-{provider}",
            enabled=enabled,
        )

    text_content = _ProviderFixtureHandler.text_content
    document_content = _ProviderFixtureHandler.document_content
    resources = (
        (
            "nextcloud", scopes["nextcloud"].id, "nextcloud-text",
            text_content, "text/markdown", "notes.md", "/content/notes.md",
            {"href": "/content/notes.md", "getlastmodified": "Sat, 26 Sep 2026 01:00:00 GMT"},
        ),
        (
            "nextcloud", scopes["nextcloud"].id, "nextcloud-document",
            document_content,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "document.docx", "/content/document.docx",
            {"href": "/content/document.docx", "getlastmodified": "Sat, 26 Sep 2026 01:00:00 GMT"},
        ),
        (
            "immich", scopes["immich"].id, IMMICH_ACCOUNT_ID,
            b"synthetic-image", "image/jpeg", "image.jpg", None,
            {
                "fileModifiedAt": "2026-09-26T01:00:00Z",
                "exif": {
                    "dateTimeOriginal": "2026-09-26T01:00:00Z",
                    "latitude": 1.25,
                    "longitude": 103.8,
                    "country": "Synthetic Country",
                    "state": "Synthetic State",
                    "city": "Synthetic City",
                    "make": "Synthetic Camera",
                    "model": "Synthetic Model",
                },
            },
        ),
        (
            "gmail", scopes["gmail"].id, "synthetic-gmail-preserved",
            b"g", "message/rfc822", "message.eml", None, {},
        ),
        (
            "integration-test", scopes["integration-test"].id,
            "synthetic-integration-quarantine", b"i", "application/octet-stream",
            "quarantine.bin", None, {},
        ),
    )
    with engine.begin() as connection:
        for provider, scope_id, external_id, content, mime, name, href, metadata in resources:
            asset_id, blob_id, source_id = uuid4(), uuid4(), uuid4()
            connection.execute(text(
                "INSERT INTO assets(id,resource_type,title,metadata,created_at,updated_at) "
                "VALUES (:id,'file',:title,'{}'::jsonb,now(),now())"
            ), {"id": asset_id, "title": f"Synthetic {provider}"})
            connection.execute(text(
                "INSERT INTO blobs(id,asset_id,hash,size,mime_type) "
                "VALUES (:id,:asset,:hash,:size,:mime)"
            ), {
                "id": blob_id,
                "asset": asset_id,
                "hash": sha256(content).hexdigest(),
                "size": len(content),
                "mime": mime,
            })
            connection.execute(text(
                "INSERT INTO asset_sources("
                "id,blob_id,provider,external_id,observation_scope_id,path,name,"
                "version_tag,provider_mime_type,provider_size,metadata,is_active) "
                "VALUES (:id,:blob,:provider,:external,:scope,:path,:name,'synthetic-v1',"
                ":mime,:size,CAST(:metadata AS jsonb),true)"
            ), {
                "id": source_id,
                "blob": blob_id,
                "provider": provider,
                "external": external_id,
                "scope": scope_id,
                "path": name,
                "name": name,
                "mime": mime,
                "size": len(content),
                "metadata": json.dumps(metadata),
            })
    sync = PostgreSQLScopeSyncStateRepository(engine)
    for provider, mechanism in (
        ("nextcloud", "activity_v2_hint_v1"),
        ("immich", "metadata_updated_at_v1"),
    ):
        row = sync.get_or_create(scopes[provider].id, mechanism)
        assert sync.compare_and_swap_checkpoint(
            scopes[provider].id,
            mechanism,
            expected_version=row.version,
            checkpoint=f"synthetic-{provider}",
        ) is not None
    return engine, scopes


def _clean_rehearsal_database(engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM resource_statements"))
        connection.execute(text("DELETE FROM resource_enrichments"))
    _clean(engine)


def _tree_snapshot(paths: tuple[Path, ...]) -> str:
    facts = []
    for root in paths:
        if not root.exists() and not root.is_symlink():
            facts.append((str(root), "absent"))
            continue
        members = (root, *sorted(root.rglob("*"))) if root.is_dir() else (root,)
        for path in members:
            info = path.lstat()
            relative = str(path)
            if stat.S_ISREG(info.st_mode):
                facts.append((relative, "file", stat.S_IMODE(info.st_mode), sha256(path.read_bytes()).hexdigest()))
            elif stat.S_ISLNK(info.st_mode):
                facts.append((relative, "symlink", os.readlink(path)))
            elif stat.S_ISDIR(info.st_mode):
                facts.append((relative, "directory", stat.S_IMODE(info.st_mode)))
    return sha256(json.dumps(facts, sort_keys=True, default=str).encode()).hexdigest()


def _host_systemd_snapshot() -> str:
    facts = []
    units = tuple(SERVICE_UNITS.values()) + tuple(
        P3D_TIMER_UNITS[key] for key in CANONICAL_PIPELINES
    )
    for unit in units:
        result = subprocess.run(
            (
                "/usr/bin/systemctl", "--no-pager", "show", unit,
                "--property=LoadState", "--property=ActiveState",
                "--property=SubState", "--property=UnitFileState",
            ),
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            shell=False,
        )
        facts.append((unit, result.returncode, result.stdout))
    return sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest()


def _prepare_rootfs(root: Path, runtime_uid: int, runtime_gid: int) -> None:
    for relative, mode in (
        ("usr", 0o755), ("etc", 0o755), ("etc/systemd", 0o755),
        ("etc/systemd/system", 0o755), ("opt", 0o755), ("opt/pdi", 0o755),
        ("var", 0o755), ("var/lib", 0o755), ("var/lib/pdi-p3d", 0o700),
        ("run", 0o755), ("run/lock", 0o755), ("tmp", 0o1777), ("root", 0o700),
    ):
        path = root / relative
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, 0, 0)
        os.chmod(path, mode)
    for name, target in (
        ("bin", "usr/bin"), ("sbin", "usr/sbin"),
        ("lib", "usr/lib"), ("lib64", "usr/lib64"),
    ):
        path = root / name
        if not path.exists() and not path.is_symlink():
            path.symlink_to(target)
    (root / "etc/os-release").symlink_to("../usr/lib/os-release")
    _write(
        root / "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        f"pdi:x:{runtime_uid}:{runtime_gid}:pdi:/nonexistent:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
        0o644, 0, 0,
    )
    _write(
        root / "etc/group",
        "root:x:0:\n"
        f"pdi:x:{runtime_gid}:\n"
        "nogroup:x:65534:\n",
        0o644, 0, 0,
    )
    _write(root / "etc/nsswitch.conf", "passwd: files\ngroup: files\nhosts: files dns\n", 0o644, 0, 0)
    _write(root / "etc/hosts", "127.0.0.1 localhost\n::1 localhost\n", 0o644, 0, 0)
    _write(root / "etc/machine-id", "", 0o644, 0, 0)
    default_target = root / "etc/systemd/system/default.target"
    default_target.symlink_to("/usr/lib/systemd/system/basic.target")


def _tool(candidate: str) -> OperatorToolIdentity:
    source = Path(__import__(
        "pdi.production_ops.p3d_release_bootstrap", fromlist=["__file__"]
    ).__file__)
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": ToolName.RELEASE_BOOTSTRAP.value,
        "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": sha256(source.read_bytes()).hexdigest(),
        "TOOL_SOURCE_SHA": candidate,
    })


def _secure_diagnostic_stream(path: Path):
    parent = path.parent
    if parent.exists() or parent.is_symlink():
        existing = parent.lstat()
        assert stat.S_ISDIR(existing.st_mode) and not parent.is_symlink()
    else:
        parent.mkdir(mode=0o700)
    os.chown(parent, 0, 0)
    os.chmod(parent, 0o700)
    parent_info = parent.lstat()
    assert stat.S_ISDIR(parent_info.st_mode) and not parent.is_symlink()
    assert parent_info.st_uid == 0 and parent_info.st_gid == 0
    assert stat.S_IMODE(parent_info.st_mode) == 0o700
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        assert stat.S_ISREG(info.st_mode)
        assert info.st_uid == 0 and info.st_gid == 0
        assert stat.S_IMODE(info.st_mode) == 0o600
        return os.fdopen(descriptor, "wb", buffering=0)
    except BaseException:
        os.close(descriptor)
        raise


def _sanitize_diagnostic(value: str, secret_values: tuple[str, ...]) -> str:
    sanitized = value
    for secret in sorted((item for item in secret_values if item), key=len, reverse=True):
        sanitized = sanitized.replace(secret, "[REDACTED]")
    return _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        sanitized,
    )


def _read_diagnostic(
    path: Path,
    secret_values: tuple[str, ...],
) -> tuple[str, str]:
    payload = path.read_bytes()
    digest = sha256(payload).hexdigest()
    excerpt = payload[-_DIAGNOSTIC_LIMIT:].decode("utf-8", errors="replace")
    return digest, _sanitize_diagnostic(excerpt, secret_values)


def _contains_unsafe_secret_material(
    value: str,
    secret_values: tuple[str, ...],
) -> bool:
    folded = value.casefold()
    if any(marker.casefold() in folded for marker in _PROTECTED_SECRET_MARKERS):
        return True
    if any(secret in value for secret in secret_values if secret):
        return True
    return _SECRET_ASSIGNMENT.search(value) is not None


def _escaped_tail(value: str, limit: int) -> str:
    pieces = []
    length = 0
    for character in reversed(value):
        escaped = json.dumps(character, ensure_ascii=False)[1:-1]
        if length + len(escaped) > limit:
            break
        pieces.append(escaped)
        length += len(escaped)
    return "".join(reversed(pieces))


def _safe_diagnostic_excerpts(
    nspawn_stderr: str,
    machinectl_stderr: str,
    secret_values: tuple[str, ...],
) -> tuple[str, str, str]:
    if any(
        _contains_unsafe_secret_material(value, secret_values)
        for value in (nspawn_stderr, machinectl_stderr)
    ):
        return "REDACTED", "", ""
    return (
        "PASS",
        _escaped_tail(nspawn_stderr, 1024),
        _escaped_tail(machinectl_stderr, 512),
    )


def _diagnostic_class(*values: str) -> str:
    combined = "\n".join(values).casefold()
    categories = (
        (
            "MOUNT_OR_BIND_FAILURE",
            ("failed to mount", "mount failed", "failed to bind", "bind mount"),
        ),
        (
            "ROOTFS_FAILURE",
            ("invalid rootfs", "root directory", "os tree", "root filesystem"),
        ),
        (
            "NAMESPACE_OR_CGROUP_FAILURE",
            ("namespace", "failed to clone", "failed to unshare", "cgroup"),
        ),
        (
            "MACHINE_REGISTRATION_FAILURE",
            ("no machine", "not registered", "failed to register machine"),
        ),
        (
            "PID1_EXEC_FAILURE",
            (
                "failed to execute /sbin/init",
                "failed to execute /usr/lib/systemd/systemd",
                "failed to exec pid 1",
            ),
        ),
        (
            "SYSTEMD_BOOT_FAILURE",
            (
                "failed to boot",
                "failed to start systemd",
                "failed to invoke systemd",
                "pid 1 exited",
            ),
        ),
    )
    for category, markers in categories:
        if any(marker in combined for marker in markers):
            return category
    return "UNCLASSIFIED"


def _manager_startup_error(
    failure_class: str,
    *,
    machine_process,
    nspawn_stdout: Path,
    nspawn_stderr: Path,
    last_machinectl,
    secret_values: tuple[str, ...],
) -> _ManagerStartupError:
    stdout_sha, sanitized_stdout = _read_diagnostic(nspawn_stdout, secret_values)
    stderr_sha, sanitized_stderr = _read_diagnostic(nspawn_stderr, secret_values)
    machinectl_return_code = -1
    machinectl_stdout = ""
    machinectl_stderr = ""
    if last_machinectl is not None:
        machinectl_return_code = last_machinectl.returncode
        machinectl_stdout = _sanitize_diagnostic(last_machinectl.stdout, secret_values)
        machinectl_stderr = _sanitize_diagnostic(last_machinectl.stderr, secret_values)
    safe_state, nspawn_safe_excerpt, machinectl_safe_excerpt = (
        _safe_diagnostic_excerpts(
            sanitized_stderr,
            machinectl_stderr,
            secret_values,
        )
    )
    diagnostic = _ManagerStartupDiagnostic(
        failure_class=failure_class,
        diagnostic_class=_diagnostic_class(
            sanitized_stdout,
            sanitized_stderr,
            machinectl_stdout,
            machinectl_stderr,
        ),
        nspawn_exit_code=machine_process.poll(),
        nspawn_stdout_sha256=stdout_sha,
        nspawn_stderr_sha256=stderr_sha,
        machinectl_return_code=machinectl_return_code,
        machinectl_stdout_sha256=sha256(machinectl_stdout.encode()).hexdigest(),
        machinectl_stderr_sha256=sha256(machinectl_stderr.encode()).hexdigest(),
        diagnostic_safe_excerpt=safe_state,
        nspawn_stderr_safe_excerpt=nspawn_safe_excerpt,
        machinectl_stderr_safe_excerpt=machinectl_safe_excerpt,
        sanitized_nspawn_stdout=sanitized_stdout,
        sanitized_nspawn_stderr=sanitized_stderr,
        sanitized_machinectl_stdout=machinectl_stdout,
        sanitized_machinectl_stderr=machinectl_stderr,
    )
    return _ManagerStartupError(diagnostic)


def _wait_for_machine(
    machine: str,
    machine_process,
    *,
    nspawn_stdout: Path,
    nspawn_stderr: Path,
    secret_values: tuple[str, ...] = (),
    timeout: float = 30,
    runner=subprocess.run,
    monotonic=time.monotonic,
    sleeper=time.sleep,
) -> int:
    deadline = monotonic() + timeout
    last_machinectl = None
    while monotonic() < deadline:
        if machine_process.poll() is not None:
            raise _manager_startup_error(
                "DISPOSABLE_SYSTEMD_MANAGER_EXITED_EARLY",
                machine_process=machine_process,
                nspawn_stdout=nspawn_stdout,
                nspawn_stderr=nspawn_stderr,
                last_machinectl=last_machinectl,
                secret_values=secret_values,
            )
        result = runner(
            (str(MACHINECTL), "show", machine, "--property=Leader", "--value"),
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        last_machinectl = result
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
        sleeper(0.25)
    if machine_process.poll() is not None:
        raise _manager_startup_error(
            "DISPOSABLE_SYSTEMD_MANAGER_EXITED_EARLY",
            machine_process=machine_process,
            nspawn_stdout=nspawn_stdout,
            nspawn_stderr=nspawn_stderr,
            last_machinectl=last_machinectl,
            secret_values=secret_values,
        )
    raise _manager_startup_error(
        "DISPOSABLE_SYSTEMD_MANAGER_REGISTRATION_TIMEOUT",
        machine_process=machine_process,
        nspawn_stdout=nspawn_stdout,
        nspawn_stderr=nspawn_stderr,
        last_machinectl=last_machinectl,
        secret_values=secret_values,
    )


class _SyntheticProcess:
    def __init__(self, returncode: int | None) -> None:
        self.returncode = returncode

    def poll(self):
        return self.returncode


def _synthetic_diagnostics(tmp_path: Path) -> tuple[Path, Path]:
    stdout = tmp_path / "nspawn.stdout"
    stderr = tmp_path / "nspawn.stderr"
    stdout.write_text("", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    return stdout, stderr


def test_wait_for_machine_detects_early_exit_with_sanitized_diagnostics(
    tmp_path: Path,
) -> None:
    stdout, stderr = _synthetic_diagnostics(tmp_path)
    secret = "postgresql://synthetic:do-not-print@127.0.0.1/test"
    stderr.write_text(
        f"Failed to mount rootfs DATABASE__URL={secret}\n",
        encoding="utf-8",
    )

    def unexpected_runner(*args, **kwargs):
        raise AssertionError("machinectl must not run after child exit")

    with pytest.raises(_ManagerStartupError) as raised:
        _wait_for_machine(
            "pdi-p3d-synthetic",
            _SyntheticProcess(1),
            nspawn_stdout=stdout,
            nspawn_stderr=stderr,
            secret_values=(secret, "do-not-print"),
            runner=unexpected_runner,
        )

    diagnostic = raised.value.diagnostic
    assert diagnostic.failure_class == "DISPOSABLE_SYSTEMD_MANAGER_EXITED_EARLY"
    assert diagnostic.nspawn_exit_code == 1
    assert diagnostic.diagnostic_class == "MOUNT_OR_BIND_FAILURE"
    assert diagnostic.machinectl_return_code == -1
    assert "[REDACTED]" in diagnostic.sanitized_nspawn_stderr
    assert secret not in diagnostic.sanitized_nspawn_stderr
    assert secret not in str(raised.value)
    assert diagnostic.diagnostic_safe_excerpt == "REDACTED"
    assert "DIAGNOSTIC_SAFE_EXCERPT=REDACTED" in str(raised.value)
    assert "NSPAWN_STDERR_SAFE_EXCERPT=" not in str(raised.value)


def test_wait_for_machine_emits_safe_nspawn_stderr_excerpt(tmp_path: Path) -> None:
    stdout, stderr = _synthetic_diagnostics(tmp_path)
    stderr.write_text(
        "Failed to execute /usr/lib/systemd/systemd\nSecond safe line\n",
        encoding="utf-8",
    )

    with pytest.raises(_ManagerStartupError) as raised:
        _wait_for_machine(
            "pdi-p3d-synthetic",
            _SyntheticProcess(1),
            nspawn_stdout=stdout,
            nspawn_stderr=stderr,
            runner=lambda *args, **kwargs: None,
        )

    diagnostic = raised.value.diagnostic
    assert diagnostic.diagnostic_class == "PID1_EXEC_FAILURE"
    assert diagnostic.diagnostic_safe_excerpt == "PASS"
    assert diagnostic.nspawn_stderr_safe_excerpt == (
        "Failed to execute /usr/lib/systemd/systemd\\nSecond safe line\\n"
    )
    assert "NSPAWN_STDERR_SAFE_EXCERPT=" in str(raised.value)
    assert "Second safe line\\n" in str(raised.value)


def test_wait_for_machine_distinguishes_registration_timeout(tmp_path: Path) -> None:
    stdout, stderr = _synthetic_diagnostics(tmp_path)
    clock = [0.0]
    calls = []

    def monotonic():
        return clock[0]

    def sleeper(interval):
        clock[0] += interval

    def runner(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return subprocess.CompletedProcess(argv, 1, "", "No machine known\n")

    with pytest.raises(_ManagerStartupError) as raised:
        _wait_for_machine(
            "pdi-p3d-synthetic",
            _SyntheticProcess(None),
            nspawn_stdout=stdout,
            nspawn_stderr=stderr,
            timeout=0.5,
            runner=runner,
            monotonic=monotonic,
            sleeper=sleeper,
        )

    diagnostic = raised.value.diagnostic
    assert diagnostic.failure_class == (
        "DISPOSABLE_SYSTEMD_MANAGER_REGISTRATION_TIMEOUT"
    )
    assert diagnostic.nspawn_exit_code is None
    assert diagnostic.diagnostic_class == "MACHINE_REGISTRATION_FAILURE"
    assert diagnostic.machinectl_return_code == 1
    assert diagnostic.sanitized_machinectl_stderr == "No machine known\n"
    assert diagnostic.diagnostic_safe_excerpt == "PASS"
    assert diagnostic.machinectl_stderr_safe_excerpt == "No machine known\\n"
    assert "MACHINECTL_STDERR_SAFE_EXCERPT=No machine known\\n" in str(
        raised.value
    )
    assert len(calls) == 2


def test_safe_diagnostic_excerpt_escapes_newlines_and_caps_lengths() -> None:
    nspawn = "nspawn diagnostic\n" * 200
    machinectl = "machine diagnostic\n" * 100
    state, nspawn_excerpt, machinectl_excerpt = _safe_diagnostic_excerpts(
        nspawn,
        machinectl,
        (),
    )
    assert state == "PASS"
    assert len(nspawn_excerpt) <= 1024
    assert len(machinectl_excerpt) <= 512
    assert "\n" not in nspawn_excerpt and "\r" not in nspawn_excerpt
    assert "\n" not in machinectl_excerpt and "\r" not in machinectl_excerpt
    assert "\\n" in nspawn_excerpt
    assert "\\n" in machinectl_excerpt


@pytest.mark.parametrize(
    ("nspawn", "machinectl", "secret_values"),
    (
        ("DATABASE__URL=[REDACTED]", "", ()),
        ("PASSWORD=[REDACTED]", "", ()),
        ("ordinary leaked-value text", "", ("leaked-value",)),
        ("", "IMMICH__API_KEY=[REDACTED]", ()),
    ),
)
def test_unsafe_diagnostic_excerpt_is_suppressed(
    nspawn: str,
    machinectl: str,
    secret_values: tuple[str, ...],
) -> None:
    assert _safe_diagnostic_excerpts(
        nspawn,
        machinectl,
        secret_values,
    ) == ("REDACTED", "", "")


def test_diagnostic_class_prefers_specific_failure_over_systemd_boot() -> None:
    assert _diagnostic_class(
        "Failed to mount root filesystem; failed to boot systemd",
    ) == "MOUNT_OR_BIND_FAILURE"
    assert _diagnostic_class(
        "Failed to unshare namespace before failed to boot",
    ) == "NAMESPACE_OR_CGROUP_FAILURE"


def test_plain_systemd_occurrence_is_not_systemd_boot_failure() -> None:
    assert _diagnostic_class(
        "systemd-nspawn terminated before registration",
    ) == "UNCLASSIFIED"
    assert _diagnostic_class(
        "Failed to invoke systemd",
    ) == "SYSTEMD_BOOT_FAILURE"


def test_wait_for_machine_accepts_successful_registration(tmp_path: Path) -> None:
    stdout, stderr = _synthetic_diagnostics(tmp_path)
    calls = []

    def runner(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, "4321\n", "")

    assert _wait_for_machine(
        "pdi-p3d-synthetic",
        _SyntheticProcess(None),
        nspawn_stdout=stdout,
        nspawn_stderr=stderr,
        runner=runner,
    ) == 4321
    assert len(calls) == 1


@pytest.mark.skipif(os.geteuid() != 0, reason="root ownership assertion")
def test_nspawn_diagnostic_stream_is_root_only(tmp_path: Path) -> None:
    stdout = tmp_path / "diagnostics/nspawn.stdout"
    stderr = tmp_path / "diagnostics/nspawn.stderr"
    streams = (
        _secure_diagnostic_stream(stdout),
        _secure_diagnostic_stream(stderr),
    )
    try:
        for path in (stdout, stderr):
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
            assert info.st_uid == 0 and info.st_gid == 0
            assert stat.S_IMODE(info.st_mode) == 0o600
        parent = stdout.parent.lstat()
        assert parent.st_uid == 0 and parent.st_gid == 0
        assert stat.S_IMODE(parent.st_mode) == 0o700
    finally:
        for stream in streams:
            stream.close()


def _terminate_machine(machine: str, process: subprocess.Popen) -> bool:
    subprocess.run(
        (str(MACHINECTL), "terminate", machine),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=30,
    )
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.send_signal(signal.SIGRTMIN + 3)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    return process.poll() is not None


@pytest.mark.skipif(os.geteuid() != 0, reason="WP7 requires disposable root authority")
def test_cross_gate_disposable_real_systemd_six_pipeline_rehearsal() -> None:
    bundle, digest_path, root, system_python, candidate = _environment()
    assert os.environ.get("PDI_P3D_WP7_DISPOSABLE") == "1"
    assert root != Path("/") and str(root).startswith("/tmp/pdi-p3d-rehearsal-")
    assert SYSTEMD_NSPAWN.is_file() and MACHINECTL.is_file()
    assert bundle.is_file() and digest_path.is_file() and system_python.is_file()
    assert not root.exists()
    root.mkdir(mode=0o755)
    os.chown(root, 0, 0)
    os.chmod(root, 0o755)
    account = pwd.getpwnam("pdi")
    group = grp.getgrnam("pdi")
    assert account.pw_uid > 0 and group.gr_gid > 0 and account.pw_gid == group.gr_gid
    _prepare_rootfs(root, account.pw_uid, group.gr_gid)
    digests = json.loads(digest_path.read_text(encoding="utf-8"))
    assert digests["CANDIDATE_SHA"] == candidate
    assert len(candidate) == 40
    url = require_safe_test_database_url()
    assert (make_url(url).database or "").startswith("pdi_wp7_")
    host_paths = (
        Path("/opt/pdi"), Path("/etc/pdi"), Path("/var/lib/pdi-p3d"),
        Path("/etc/systemd/system/pdi-scoped-pipeline@.service"),
    )
    host_before = _tree_snapshot(host_paths)
    host_systemd_before = _host_systemd_snapshot()
    engine = None
    machine_process = None
    diagnostic_streams = []
    machine = ""
    complete_fingerprint = None
    manager_cleaned = False
    db_cleaned = False
    filesystem_cleaned = False
    try:
        with _provider_fixture() as (provider_port, fixture):
            engine, scopes = _seed_database(url)
            releases_root = root / "opt/pdi/releases"
            preparation_root = root / "var/lib/pdi-p3d/preparation"
            bootstrap_lock = root / "run/lock/pdi/p3d-release-bootstrap.lock"
            current = root / "opt/pdi/current"
            bootstrap = ReleaseBootstrap(
                inputs=BootstrapInputs(
                    bundle.absolute(), candidate, digests["BUNDLE_SHA256"],
                    digests["OS_RUNTIME_MANIFEST_SHA256"], "QUALIFICATION_ONLY",
                    _tool(candidate), releases_root, preparation_root,
                    bootstrap_lock, current, "pdi", "pdi",
                ),
                policy=BootstrapPolicy.qualification(
                    disposable_root=root, owner_uid=0, owner_gid=0,
                    runtime_uid=account.pw_uid, runtime_gid=group.gr_gid,
                ),
                host_runtime_provider=QualificationHostRuntimeAuthorityProvider(
                    system_python, digests["OS_RUNTIME_MANIFEST_SHA256"],
                ),
            ).run()
            assert bootstrap.final_state.phase == "COMPLETE"
            release = releases_root / candidate

            gate_a_operation = str(uuid4())
            rollback_metadata, _ = _create_complete_gate_a(
                preparation_root,
                operation_id=gate_a_operation,
                candidate=candidate,
                source=SOURCE,
            )
            current.symlink_to(f"/opt/pdi/releases/{SOURCE}")

            p3c_state_root = root / "var/lib/pdi-p3c"
            frozen_host = FrozenP3CHost(
                FrozenP3CPaths(
                    staging=root / "p3c-unused/staging",
                    env=root / "p3c-unused/pdi.env",
                    recovery=root / "p3c-unused/recovery",
                    config=root / "p3c-unused/config",
                    units=root / "p3c-unused/units",
                    current=root / "p3c-unused/current",
                    releases=root / "p3c-unused/releases",
                    state=p3c_state_root,
                    control=root / "p3c-unused/control.lock",
                    sync=root / "p3c-unused/sync.lock",
                ),
                root / "p3c-unused/release", SOURCE,
                "synthetic-host", H1, SOURCE,
            )
            frozen_host.save({
                "phase": "PASS",
                "sha": SOURCE,
                "old_target": "/opt/pdi/releases/" + "c" * 40,
                "context": rollback_metadata.p3c_context_fingerprint,
                "baseline": {"synthetic": "private-baseline-evidence"},
                "qualified": list(QUALIFICATION),
                "verified": {"synthetic": "private-verified-evidence"},
            })

            endpoint = f"http://127.0.0.1:{provider_port}"
            environment = root / "etc/pdi/pdi.env"
            _write(
                environment,
                f'DATABASE__URL="{url}"\n'
                f'NEXTCLOUD__URL="{endpoint}"\n'
                'NEXTCLOUD__USER="synthetic"\n'
                'NEXTCLOUD__PASSWORD="synthetic-nextcloud-password"\n'
                f'IMMICH__URL="{endpoint}"\n'
                'IMMICH__API_KEY="synthetic-immich-api-key"\n',
                0o600, 0, 0,
            )
            registry = root / "etc/pdi/scoped/registry.toml"
            _write(
                registry,
                '[[principals]]\n'
                f'id = "{PRINCIPAL_ID}"\n'
                'database_ref = "wp7-personal-db"\n'
                'enabled = true\n\n'
                '[[databases]]\nref = "wp7-personal-db"\n'
                'url_env = "DATABASE__URL"\n\n'
                '[[provider_bindings]]\n'
                f'principal_id = "{PRINCIPAL_ID}"\n'
                f'scope_id = "{scopes["nextcloud"].id}"\n'
                'provider_type = "nextcloud"\n'
                f'endpoint = "{endpoint}"\n'
                'secret_env = "NEXTCLOUD__PASSWORD"\n'
                'username = "synthetic"\n\n'
                '[[provider_bindings]]\n'
                f'principal_id = "{PRINCIPAL_ID}"\n'
                f'scope_id = "{scopes["immich"].id}"\n'
                'provider_type = "immich"\n'
                f'endpoint = "{endpoint}"\n'
                'secret_env = "IMMICH__API_KEY"\n',
                0o640, 0, group.gr_gid,
            )
            profiles = root / "etc/pdi/scoped/units"
            profiles.mkdir(mode=0o700)
            os.chown(profiles, 0, 0)
            os.chmod(profiles, 0o700)

            gate_c = subprocess.run(
                (
                    str(release / ".venv/bin/python"),
                    str(release / "scripts/pdi_p3d_inert_asset_install.py"),
                    "--mode", "QUALIFICATION",
                    "--expected-candidate-sha", candidate,
                    "--gate-a-operation-id", gate_a_operation,
                    "--gate-b-operation-id", bootstrap.operation_id,
                    "--expected-systemd-asset-fingerprint",
                    digests["SYSTEMD_ASSET_FINGERPRINT"],
                    "--qualification-root", str(root),
                    "--qualification-runtime-user", "pdi",
                    "--qualification-runtime-group", "pdi",
                ),
                cwd=release,
                env={
                    "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                },
                capture_output=True, text=True, timeout=300, shell=False,
            )
            assert gate_c.returncode == 0, "GATE_C_FAILED"
            gate_c_result = json.loads(gate_c.stdout)
            assert gate_c_result["PHASE"] == "COMPLETE"
            for key in CANONICAL_PIPELINES:
                profile = profiles / f"{key}.env"
                info = profile.lstat()
                assert info.st_uid == 0 and info.st_gid == 0
                assert stat.S_IMODE(info.st_mode) == 0o600
                values = parse_env(profile.read_text(encoding="utf-8"))
                expected_keys = {
                    "PDI_PRINCIPAL_REF", "PDI_SCOPED_PIPELINE_KEY",
                    "DATABASE__URL",
                }
                if key.startswith("enrichment.nextcloud_"):
                    expected_keys.add("NEXTCLOUD__PASSWORD")
                elif key == "enrichment.immich_ocr":
                    expected_keys.add("IMMICH__API_KEY")
                assert set(values) == expected_keys

            rehearsal_operation = str(uuid4())
            machine = machine_name_for(rehearsal_operation)
            command = (
                str(SYSTEMD_NSPAWN), "--quiet", "--boot", "--register=yes",
                f"--machine={machine}", f"--directory={root}",
                "--bind-ro=/usr:/usr",
                f"--bind-ro={system_python.parent.parent}:{system_python.parent.parent}",
                "--console=pipe", "--link-journal=no", "--settings=no",
                "--resolv-conf=off", "--timezone=off", "--unit=basic.target",
            )
            diagnostic_root = root / "var/lib/pdi-p3d/rehearsal-diagnostics"
            nspawn_stdout = diagnostic_root / "nspawn.stdout"
            nspawn_stderr = diagnostic_root / "nspawn.stderr"
            diagnostic_streams.append(_secure_diagnostic_stream(nspawn_stdout))
            diagnostic_streams.append(_secure_diagnostic_stream(nspawn_stderr))
            machine_process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL,
                stdout=diagnostic_streams[0], stderr=diagnostic_streams[1],
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            database_password = make_url(url).password or ""
            leader = _wait_for_machine(
                machine,
                machine_process,
                nspawn_stdout=nspawn_stdout,
                nspawn_stderr=nspawn_stderr,
                secret_values=(
                    url,
                    database_password,
                    "synthetic-nextcloud-password",
                    "synthetic-immich-api-key",
                ),
            )
            lock = Path(f"/proc/{leader}/root/run/lock/pdi-sync.lock")
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.touch(exist_ok=False)
            os.chown(lock, account.pw_uid, group.gr_gid)
            os.chmod(lock, 0o600)

            wp7 = subprocess.run(
                (
                    str(release / ".venv/bin/python"),
                    str(release / "scripts/pdi_p3d_disposable_rehearsal.py"),
                    "run",
                    "--expected-candidate-sha", candidate,
                    "--gate-a-operation-id", gate_a_operation,
                    "--gate-b-operation-id", bootstrap.operation_id,
                    "--gate-c-operation-id", gate_c_result["OPERATION_ID"],
                    "--rehearsal-operation-id", rehearsal_operation,
                    "--rehearsal-root", str(root),
                ),
                cwd=release,
                env={
                    "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                },
                capture_output=True, text=True, timeout=1800, shell=False,
            )
            assert wp7.returncode == 0, wp7.stdout
            assert wp7.stderr == ""
            result = json.loads(wp7.stdout)
            assert result["P3D_DISPOSABLE_REHEARSAL"] == "PASS"
            assert result["P3D_SERVICE_START_COUNT"] == 6
            assert result["P3D_TIMER_ENABLE_COUNT"] == 0
            assert result["P3D_TIMER_START_COUNT"] == 0
            assert result["POSTGRESQL_MAJOR"] == 16
            assert result["RUNTIME_PIPELINE_COVERAGE"] == "6/6"
            assert result["POST_REHEARSAL_RUNTIME_LEDGER_PROOF"] == "PASS"
            assert result["TIMERS_FINAL_STATE"] == "DISABLED_INACTIVE"
            complete_fingerprint = result["REHEARSAL_COMPLETE_MARKER_FINGERPRINT"]
            assert len(complete_fingerprint) == 64
            assert fixture.calls.count("nextcloud-propfind") >= 2
            assert fixture.calls.count("nextcloud-content") >= 2
            assert fixture.calls.count("immich-account") >= 1
            assert fixture.calls.count("immich-ocr") >= 1
            assert os.readlink(current) == f"/opt/pdi/releases/{candidate}"
            with engine.connect() as connection:
                assert connection.scalar(text("SELECT count(*) FROM pipeline_runs")) == 6
                assert connection.scalar(text(
                    "SELECT count(*) FROM pipeline_runs WHERE status='completed' "
                    "AND finished_at IS NOT NULL AND error_code IS NULL"
                )) == 6
                assert connection.scalar(text(
                    "SELECT count(DISTINCT pipeline_key) FROM pipeline_runs"
                )) == 6
    finally:
        if machine_process is not None:
            manager_cleaned = _terminate_machine(machine, machine_process)
        for stream in diagnostic_streams:
            stream.close()
        if engine is not None:
            _clean_rehearsal_database(engine)
            with engine.connect() as connection:
                db_cleaned = connection.scalar(text("SELECT count(*) FROM pipeline_runs")) == 0
            engine.dispose()
        if root.exists():
            shutil.rmtree(root)
        filesystem_cleaned = not root.exists()

    assert complete_fingerprint is not None
    assert manager_cleaned
    assert db_cleaned
    assert filesystem_cleaned
    assert _tree_snapshot(host_paths) == host_before
    assert _host_systemd_snapshot() == host_systemd_before
    print("P3D_DISPOSABLE_REHEARSAL=PASS")
    print("SYSTEMD_MANAGER_REAL=PASS")
    print("SYSTEMD_MANAGER_ISOLATED=PASS")
    print("P3D_SERVICE_START_COUNT=6")
    print("P3D_TIMER_ENABLE_COUNT=0")
    print("POSTGRESQL_MAJOR=16")
    print("RUNTIME_PIPELINE_COVERAGE=6/6")
    print("POST_REHEARSAL_RUNTIME_LEDGER_PROOF=PASS")
    print("TIMERS_FINAL_STATE=DISABLED_INACTIVE")
    print(f"REHEARSAL_COMPLETE_MARKER_FINGERPRINT={complete_fingerprint}")
    print("PRODUCTION_TOUCHED=NO")
