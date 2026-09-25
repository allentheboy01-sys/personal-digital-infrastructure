from __future__ import annotations

import io
import inspect
import json
import os
from pathlib import Path
import subprocess
import tarfile
import zipfile

import pytest

from pdi.production_ops.p3d_preparation_contracts import (
    OSRuntimeManifestV1,
    OperatorToolIdentity,
    ReleaseInputBundleManifestV1,
    ToolName,
    WheelhouseManifestV1,
    canonical_json_bytes,
    os_runtime_manifest_fingerprint,
    release_bundle_fingerprint,
    wheel_inventory_fingerprint,
    wheelhouse_manifest_fingerprint,
)
from pdi.production_ops import p3d_release_bundle as subject


H1 = "1" * 64
CANDIDATE = "a" * 40
WORKFLOW_SOURCE = "b" * 40


def os_mapping(**changes):
    value = {
        "MANIFEST_VERSION": "1",
        "OS_ID": "ubuntu",
        "OS_VERSION_ID": "24.04",
        "ARCH": "x86_64",
        "APPROVED_PACKAGE_NAMES_AND_VERSIONS": [
            {"NAME": "libc6", "VERSION": "2.39-0ubuntu8.6"},
            {"NAME": "python313", "VERSION": "3.13.15"},
        ],
        "SYSTEM_PYTHON_PATH": "/usr/bin/python3.13",
        "PYTHON_IMPLEMENTATION": "CPython",
        "PYTHON_VERSION": "3.13.15",
        "PYTHON_ABI": "cp313",
        "SYSTEM_RUNTIME_FILE_SHA256": H1,
        "NATIVE_LIBRARY_PACKAGE_SET": ["libc6", "python313"],
    }
    value.update(changes)
    return value


def make_wheel(
    path: Path, name: str, version: str, tag: str = "py3-none-any",
    requires: tuple[str, ...] = (),
) -> Path:
    dist = name.replace("-", "_")
    package = name.replace("-", "_")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr(f"{package}/__init__.py", "")
        requirement_lines = "".join(f"Requires-Dist: {item}\n" for item in requires)
        archive.writestr(
            f"{dist}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n{requirement_lines}\n",
        )
        archive.writestr(
            f"{dist}-{version}.dist-info/WHEEL",
            f"Wheel-Version: 1.0\nGenerator: pdi-test\nRoot-Is-Purelib: true\nTag: {tag}\n\n",
        )
        archive.writestr(f"{dist}-{version}.dist-info/RECORD", "")
    return path


def git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", "-C", str(cwd), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(cwd),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        },
    )
    return completed.stdout.strip()


def init_repo(root: Path) -> str:
    root.mkdir()
    git(root, "init", "--quiet")
    (root / "tracked.txt").write_text("candidate\n")
    git(root, "add", "tracked.txt")
    subprocess.run(
        ["/usr/bin/git", "-C", str(root), "-c", "user.name=PDI Test",
         "-c", "user.email=pdi-test@example.invalid", "commit", "--quiet", "-m", "candidate"],
        check=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(root),
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_OPTIONAL_LOCKS": "0"},
    )
    return git(root, "rev-parse", "HEAD")


def write_json(path: Path, value) -> bytes:
    data = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def valid_bundle(tmp_path: Path) -> tuple[Path, str, str]:
    candidate_repo = tmp_path / "repo"
    candidate = init_repo(candidate_repo)
    payload = tmp_path / "payload"
    payload.mkdir()
    source_bundle = payload / "source/pdi.git.bundle"
    source_bundle.parent.mkdir()
    git(candidate_repo, "bundle", "create", str(source_bundle), "HEAD")

    wheelhouse = payload / "wheelhouse"
    wheelhouse.mkdir()
    pdi_wheel = make_wheel(
        wheelhouse / "pdi-0.6.0-py3-none-any.whl", "pdi", "0.6.0",
        requires=("psycopg==3.3.4", "SQLAlchemy==2.0.52"),
    )
    psycopg_wheel = make_wheel(wheelhouse / "psycopg-3.3.4-py3-none-any.whl", "psycopg", "3.3.4")
    sqlalchemy_wheel = make_wheel(wheelhouse / "sqlalchemy-2.0.52-py3-none-any.whl", "sqlalchemy", "2.0.52")
    os_manifest = OSRuntimeManifestV1.from_mapping(os_mapping())
    wheel_entries = tuple(subject.inspect_wheel(path).entry for path in (
        pdi_wheel, psycopg_wheel, sqlalchemy_wheel,
    ))
    wheel_manifest = WheelhouseManifestV1.from_mapping({
        "MANIFEST_VERSION": "1",
        "PYTHON_IMPLEMENTATION": "CPython",
        "PYTHON_VERSION": "3.13.15",
        "PYTHON_ABI": "cp313",
        "PLATFORM_TAG": "manylinux_2_34_x86_64",
        "ARCH": "x86_64",
        "OS_RUNTIME_MANIFEST_SHA256": os_runtime_manifest_fingerprint(os_manifest),
        "WHEELHOUSE_MANIFEST_SHA256": wheel_inventory_fingerprint(wheel_entries),
        "WHEELS": [entry.to_mapping() for entry in wheel_entries],
    })
    lock = payload / "requirements/runtime.lock"
    lock.parent.mkdir()
    lock.write_bytes(subject.runtime_lock_bytes(wheel_manifest))
    sdist = payload / "dist/pdi-0.6.0.tar.gz"
    sdist.parent.mkdir()
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo("pdi-0.6.0/PKG-INFO")
        data = b"Metadata-Version: 2.4\nName: pdi\nVersion: 0.6.0\n\n"
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    systemd = payload / "systemd"
    systemd.mkdir()
    assets = []
    for name in subject.CANONICAL_SYSTEMD_ASSETS:
        path = systemd / name
        path.write_text(f"# {name}\n")
        assets.append(subject.SystemdAssetV1(
            f"deployment/systemd/{name}", f"/etc/systemd/system/{name}",
            subject.sha256_file(path), "0644",
        ))
    systemd_hash = subject.systemd_asset_fingerprint(assets)

    entries = [
        subject._payload_entry(source_bundle, payload, "GIT_BUNDLE"),
        subject._payload_entry(sdist, payload, "PDI_SDIST"),
        subject._payload_entry(lock, payload, "RUNTIME_LOCK"),
    ]
    entries += [subject._payload_entry(path, payload, "RUNTIME_WHEEL") for path in wheelhouse.iterdir()]
    entries += [subject._payload_entry(systemd / name, payload, "SYSTEMD_UNIT") for name in subject.CANONICAL_SYSTEMD_ASSETS]
    file_manifest = subject.ReleaseBundleFileManifestV1(tuple(sorted(entries)))
    files_bytes = write_json(payload / "manifests/files.json", file_manifest.to_mapping())
    write_json(payload / "manifests/os-runtime.json", os_manifest.to_mapping())
    write_json(payload / "manifests/wheelhouse.json", wheel_manifest.to_mapping())
    wheel_hash = subject.sha256_file(pdi_wheel)
    builder = OperatorToolIdentity.from_mapping({
        "TOOL_NAME": ToolName.RELEASE_BUNDLE_BUILD.value,
        "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": wheel_hash,
        "TOOL_SOURCE_SHA": candidate,
    })
    provenance = subject.P3DReleaseBundleProvenanceV1(
        "example/pdi", candidate,
        f"github:example/pdi@{WORKFLOW_SOURCE}:.github/workflows/ci.yml",
        WORKFLOW_SOURCE, "1", "1", f"github-run:1:1:{subject.BUNDLE_PREFIX}-{candidate}",
        builder, subject.sha256_file(source_bundle), wheel_hash, subject.sha256_file(sdist),
        wheelhouse_manifest_fingerprint(wheel_manifest), os_runtime_manifest_fingerprint(os_manifest),
        systemd_hash, subject.sha256_file(lock), subject.contract_fingerprint(file_manifest.to_mapping()),
    )
    provenance_bytes = write_json(payload / "provenance/provenance.json", provenance.to_mapping())
    release = ReleaseInputBundleManifestV1.from_mapping({
        "MANIFEST_VERSION": "1", "CANDIDATE_SHA": candidate,
        "GIT_BUNDLE_SHA256": subject.sha256_file(source_bundle),
        "GIT_BUNDLE_SOURCE_SHA": candidate,
        "PDI_WHEEL_SHA256": wheel_hash, "PDI_WHEEL_SOURCE_SHA": candidate,
        "PDI_SDIST_SHA256": subject.sha256_file(sdist), "PDI_SDIST_SOURCE_SHA": candidate,
        "WHEELHOUSE_MANIFEST_SHA256": wheelhouse_manifest_fingerprint(wheel_manifest),
        "OS_RUNTIME_MANIFEST_SHA256": os_runtime_manifest_fingerprint(os_manifest),
        "SYSTEMD_ASSET_FINGERPRINT": systemd_hash,
        "BUILD_WORKFLOW_IDENTITY": provenance.workflow_identity,
        "BUILD_ARTIFACT_IDENTITY": provenance.artifact_identity,
        "PROVENANCE_SHA256": subject.contract_fingerprint(provenance.to_mapping()),
        "BUILDER_TOOL": builder.to_mapping(),
    })
    write_json(payload / "manifests/release-input.json", release.to_mapping())
    bundle = tmp_path / "bundle.tar"
    members = [path.relative_to(payload).as_posix() for path in payload.rglob("*") if path.is_file()]
    subject._write_canonical_tar(payload, members, bundle)
    return bundle, candidate, subject.sha256_file(bundle)


def test_clean_candidate_checkout_enforces_exact_sha_and_untracked_cleanliness(tmp_path: Path):
    repo = tmp_path / "repo"
    candidate = init_repo(repo)
    home = tmp_path / "home"
    home.mkdir()
    subject.verify_clean_candidate_checkout(repo, candidate, home=home)
    with pytest.raises(subject.ReleaseBundleError, match="CANDIDATE_MISMATCH"):
        subject.verify_clean_candidate_checkout(repo, "f" * 40, home=home)
    (repo / "untracked").write_text("no")
    with pytest.raises(subject.ReleaseBundleError, match="SOURCE_DIRTY"):
        subject.verify_clean_candidate_checkout(repo, candidate, home=home)


def test_git_commands_use_fixed_non_persisting_environment(monkeypatch, tmp_path: Path):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((tuple(map(os.fspath, argv)), kwargs["env"]))
        output = CANDIDATE + "\n" if "rev-parse" in argv else ""
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(subject.subprocess, "run", fake_run)
    monkeypatch.setattr(subject.Path, "is_file", lambda self: True)
    monkeypatch.setattr(subject.Path, "is_dir", lambda self: True)
    monkeypatch.setattr(subject.Path, "is_symlink", lambda self: False)
    monkeypatch.setenv("GIT_DIR", "/tmp/foreign")
    monkeypatch.setenv("GIT_INDEX_FILE", "/tmp/foreign-index")
    subject.verify_clean_candidate_checkout(tmp_path, CANDIDATE, home=tmp_path / "home")
    for _, env in calls:
        assert env == {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(tmp_path / "home"),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        }


def test_self_contained_git_bundle_verifies_in_empty_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    candidate = init_repo(repo)
    home = tmp_path / "home"
    home.mkdir()
    output = tmp_path / "source/pdi.git.bundle"
    work = tmp_path / "work"
    work.mkdir()
    subject.create_and_verify_git_bundle(repo, candidate, output, work_root=work, home=home)
    assert output.is_file()


def test_candidate_source_tree_is_bound_to_git_bundle(tmp_path: Path):
    repo = tmp_path / "repo"
    candidate = init_repo(repo)
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    bundle = tmp_path / "pdi.git.bundle"
    subject.create_and_verify_git_bundle(repo, candidate, bundle, work_root=work, home=home)
    source = tmp_path / "candidate"
    archive_work = tmp_path / "archive-work"
    archive_work.mkdir()
    subject.archive_exact_source(repo, candidate, source, work_root=archive_work, home=home)
    subject.verify_source_tree_from_git_bundle(source, bundle, candidate)
    (source / "tracked.txt").write_text("foreign\n")
    with pytest.raises(subject.ReleaseBundleError, match="SOURCE_INVALID"):
        subject.verify_source_tree_from_git_bundle(source, bundle, candidate)


@pytest.mark.parametrize("tag,expected", [
    ("py3-none-any", True),
    ("cp313-cp313-manylinux_2_17_x86_64", True),
    ("cp313-abi3-manylinux2014_x86_64", True),
    ("cp39-abi3-manylinux_2_17_x86_64", True),
    ("cp312-cp312-manylinux_2_17_x86_64", False),
    ("cp313-cp313-musllinux_1_2_x86_64", False),
    ("cp313-cp313-manylinux_2_35_x86_64", False),
    ("cp313-cp313-manylinux_2_17_aarch64", False),
])
def test_wheel_tag_compatibility(tmp_path: Path, tag: str, expected: bool):
    wheel = make_wheel(tmp_path / "sample-1.0.0-py3-none-any.whl", "sample", "1.0.0", tag)
    entry = subject.inspect_wheel(wheel).entry
    manifest = OSRuntimeManifestV1.from_mapping(os_mapping())
    assert subject.wheel_is_target_compatible(entry, manifest, "manylinux_2_34_x86_64") is expected


def test_wheelhouse_manifest_and_runtime_lock_are_derived_and_exact(tmp_path: Path):
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    make_wheel(wheelhouse / "pdi-0.6.0-py3-none-any.whl", "PDI", "0.6.0")
    make_wheel(wheelhouse / "SQLAlchemy-2.0.52-py3-none-any.whl", "SQLAlchemy", "2.0.52")
    manifest = subject.build_wheelhouse_manifest(
        wheelhouse, OSRuntimeManifestV1.from_mapping(os_mapping()), "manylinux_2_34_x86_64",
    )
    assert [entry.package for entry in manifest.wheels] == ["pdi", "sqlalchemy"]
    lock = subject.runtime_lock_bytes(manifest)
    subject.verify_runtime_lock(lock, manifest)
    for mutation in (
        lock.replace(b"pdi==", b"pdi>=", 1),
        lock + b"foreign==1.0 --hash=sha256:" + b"f" * 64 + b"\n",
        lock.replace(b" --hash=sha256:", b"", 1),
        b"pdi @ https://example.invalid/pdi.whl\n",
    ):
        with pytest.raises(subject.ReleaseBundleError):
            subject.verify_runtime_lock(mutation, manifest)


def test_pip_platform_resolution_includes_all_compatible_manylinux_floors():
    values = subject.compatible_pip_platforms("manylinux_2_34_x86_64", "x86_64")
    assert values[0] == "manylinux_2_34_x86_64"
    assert "manylinux_2_28_x86_64" in values
    assert "manylinux_2_17_x86_64" in values
    assert "manylinux2014_x86_64" in values
    assert "manylinux1_x86_64" in values
    with pytest.raises(subject.ReleaseBundleError):
        subject.compatible_pip_platforms("musllinux_1_2_x86_64", "x86_64")


def test_wheelhouse_rejects_extra_non_wheel_and_duplicate_package(tmp_path: Path):
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    make_wheel(wheelhouse / "one.whl", "sample", "1.0.0")
    (wheelhouse / "foreign.tar.gz").write_bytes(b"x")
    with pytest.raises(subject.ReleaseBundleError, match="WHEELHOUSE_INVALID"):
        subject.build_wheelhouse_manifest(
            wheelhouse, OSRuntimeManifestV1.from_mapping(os_mapping()), "manylinux_2_34_x86_64",
        )


def test_systemd_authority_is_exact_seven_and_content_bound(tmp_path: Path):
    source = tmp_path / "source/deployment/systemd"
    source.mkdir(parents=True)
    payload = tmp_path / "payload"
    payload.mkdir()
    for name in subject.CANONICAL_SYSTEMD_ASSETS:
        (source / name).write_text(name)
    assets = subject.collect_systemd_assets(tmp_path / "source", payload)
    first = subject.systemd_asset_fingerprint(assets)
    assert len(assets) == 7
    (source / "pdi-scoped-enrichment-foreign.timer").write_text("foreign")
    with pytest.raises(subject.ReleaseBundleError, match="SYSTEMD_SET_INVALID"):
        subject.collect_systemd_assets(tmp_path / "source", tmp_path / "other")
    assert len(first) == 64


def test_file_manifest_rejects_paths_duplicates_and_classes():
    base = {"SHA256": H1, "SIZE": 1, "MODE": "0644", "FILE_CLASS": "GIT_BUNDLE"}
    for path in ("/absolute", "../escape", "a/../escape", "./relative"):
        with pytest.raises(subject.ReleaseBundleError):
            subject.ReleaseBundleFileEntryV1.from_mapping({"RELATIVE_PATH": path, **base})
    entry = {"RELATIVE_PATH": "source/a", **base}
    with pytest.raises(subject.ReleaseBundleError):
        subject.ReleaseBundleFileManifestV1.from_mapping({
            "MANIFEST_VERSION": "1", "SCOPE": "PAYLOAD_ONLY", "ENTRIES": [entry, entry],
        })


def test_provenance_separates_candidate_from_workflow_source_and_builder_role():
    builder = {
        "TOOL_NAME": ToolName.RELEASE_BUNDLE_BUILD.value, "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": H1, "TOOL_SOURCE_SHA": CANDIDATE,
    }
    value = {
        "PROVENANCE_VERSION": "1", "AUTHORITY_CLASS": subject.AUTHORITY_CLASS,
        "REPOSITORY_IDENTITY": "example/pdi", "CANDIDATE_SHA": CANDIDATE,
        "WORKFLOW_IDENTITY": (
            f"github:example/pdi@{WORKFLOW_SOURCE}:.github/workflows/ci.yml"
        ),
        "WORKFLOW_SOURCE_SHA": WORKFLOW_SOURCE,
        "RUN_IDENTITY": "1", "RUN_ATTEMPT": "1", "ARTIFACT_IDENTITY": "artifact",
        "BUILDER_TOOL": builder, "GIT_BUNDLE_SHA256": H1, "PDI_WHEEL_SHA256": H1,
        "PDI_SDIST_SHA256": H1, "WHEELHOUSE_MANIFEST_SHA256": H1,
        "OS_RUNTIME_MANIFEST_SHA256": H1, "SYSTEMD_ASSET_FINGERPRINT": H1,
        "RUNTIME_LOCK_SHA256": H1, "FILE_MANIFEST_SHA256": H1,
    }
    provenance = subject.P3DReleaseBundleProvenanceV1.from_mapping(value)
    assert provenance.candidate_sha == CANDIDATE
    assert provenance.workflow_source_sha == WORKFLOW_SOURCE
    assert f"@{WORKFLOW_SOURCE}:" in provenance.workflow_identity
    assert provenance.builder_tool.tool_source_sha == CANDIDATE
    with pytest.raises(subject.ReleaseBundleError):
        subject.P3DReleaseBundleProvenanceV1.from_mapping({
            **value, "WORKFLOW_SOURCE_SHA": "c" * 40,
        })
    with pytest.raises(subject.ReleaseBundleError):
        subject.P3DReleaseBundleProvenanceV1.from_mapping({
            **value,
            "WORKFLOW_IDENTITY": f"github:example/pdi@{CANDIDATE}:.github/workflows/ci.yml",
        })
    with pytest.raises(Exception):
        subject.P3DReleaseBundleProvenanceV1.from_mapping({
            **value, "BUILDER_TOOL": {**builder, "TOOL_NAME": ToolName.RELEASE_BOOTSTRAP.value},
        })


def test_canonical_tar_metadata_and_round_trip(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "b").write_bytes(b"b")
    (root / "a").write_bytes(b"a")
    bundle = tmp_path / "bundle.tar"
    subject._write_canonical_tar(root, ("b", "a"), bundle)
    with tarfile.open(bundle, "r:") as archive:
        assert [item.name for item in archive] == ["a", "b"]
        archive.members
        for item in archive.getmembers():
            assert (item.uid, item.gid, item.uname, item.gname, item.mtime, item.mode) == (0, 0, "", "", 0, 0o644)
            assert item.isfile()
    target = tmp_path / "target"
    assert subject.safe_extract_bundle(bundle, target) == ("a", "b")


def test_canonical_tar_supports_only_the_required_long_path_pax_header(tmp_path: Path):
    root = tmp_path / "root"
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    relative = "wheelhouse/" + "x" * 105 + ".whl"
    (root / relative).write_bytes(b"wheel")
    bundle = tmp_path / "bundle.tar"

    subject._write_canonical_tar(root, (relative,), bundle)

    with tarfile.open(bundle, "r:") as archive:
        member = archive.getmembers()[0]
        assert member.name == relative
        assert member.pax_headers == {"path": relative}
    assert subject.safe_extract_bundle(bundle, tmp_path / "target") == (relative,)


def test_canonical_tar_uses_exact_path_header_for_splittable_path_over_100_bytes(tmp_path: Path):
    root = tmp_path / "root"
    prefix = root / ("p" * 20)
    prefix.mkdir(parents=True)
    relative = "p" * 20 + "/" + "x" * 85
    (root / relative).write_bytes(b"asset")
    bundle = tmp_path / "bundle.tar"

    subject._write_canonical_tar(root, (relative,), bundle)

    with tarfile.open(bundle, "r:") as archive:
        member = archive.getmembers()[0]
        assert member.pax_headers == {"path": relative}
    assert subject.safe_extract_bundle(bundle, tmp_path / "target") == (relative,)


def test_archive_rejects_unapproved_pax_metadata(tmp_path: Path):
    bundle = tmp_path / "unsafe-pax.tar"
    with tarfile.open(bundle, "w:", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("safe")
        info.size = 1
        info.mode = 0o644
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ""
        info.pax_headers = {"comment": "not-authoritative"}
        archive.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(subject.ReleaseBundleError, match="ARCHIVE_METADATA_INVALID"):
        subject.safe_extract_bundle(bundle, tmp_path / "target")


@pytest.mark.parametrize("kind,name", [
    ("symlink", "safe"), ("hardlink", "safe"), ("fifo", "safe"),
    ("file", "/absolute"), ("file", "../escape"),
])
def test_archive_rejects_special_and_unsafe_members(tmp_path: Path, kind: str, name: str):
    bundle = tmp_path / "unsafe.tar"
    with tarfile.open(bundle, "w:") as archive:
        info = tarfile.TarInfo(name)
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        info.mode = 0o644
        if kind == "symlink":
            info.type = tarfile.SYMTYPE
            info.linkname = "/tmp/escape"
        elif kind == "hardlink":
            info.type = tarfile.LNKTYPE
            info.linkname = "other"
        elif kind == "fifo":
            info.type = tarfile.FIFOTYPE
        else:
            info.size = 1
        archive.addfile(info, io.BytesIO(b"x") if info.size else None)
    with pytest.raises(subject.ReleaseBundleError):
        subject.safe_extract_bundle(bundle, tmp_path / "target")


def test_archive_rejects_duplicate_member(tmp_path: Path):
    bundle = tmp_path / "duplicate.tar"
    with tarfile.open(bundle, "w:") as archive:
        for _ in range(2):
            info = tarfile.TarInfo("same")
            info.size = 1
            info.mode = 0o644
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(subject.ReleaseBundleError):
        subject.safe_extract_bundle(bundle, tmp_path / "target")


def test_valid_bundle_cross_binding_and_empty_repo_verification(tmp_path: Path):
    bundle, candidate, digest = valid_bundle(tmp_path)
    result = subject.verify_release_input_bundle(
        bundle, expected_candidate_sha=candidate, expected_bundle_sha256=digest,
        perform_offline_install=False,
    )
    assert result["CANDIDATE_SHA"] == candidate
    assert result["BUNDLE_SHA256"] == digest


def rewrite_bundle(tmp_path: Path, bundle: Path, mutate) -> Path:
    root = tmp_path / "unpacked"
    subject.safe_extract_bundle(bundle, root)
    mutate(root)
    output = tmp_path / "tampered.tar"
    members = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]
    subject._write_canonical_tar(root, members, output)
    return output


@pytest.mark.parametrize(("field", "foreign"), [
    ("WORKFLOW_IDENTITY", f"github:example/pdi@{WORKFLOW_SOURCE}:.github/workflows/foreign.yml"),
    ("ARTIFACT_IDENTITY", "github-run:foreign:1:pdi-p3d-release-input-foreign"),
    ("SYSTEMD_ASSET_FINGERPRINT", "f" * 64),
])
def test_release_authority_cross_bindings_fail_closed(
    tmp_path: Path, field: str, foreign: str,
):
    bundle, candidate, _ = valid_bundle(tmp_path)

    def mutate(root: Path) -> None:
        provenance_path = root / "provenance/provenance.json"
        release_path = root / "manifests/release-input.json"
        provenance = json.loads(provenance_path.read_text())
        release = json.loads(release_path.read_text())
        provenance[field] = foreign
        write_json(provenance_path, provenance)
        release["PROVENANCE_SHA256"] = subject.contract_fingerprint(provenance)
        write_json(release_path, release)

    tampered = rewrite_bundle(tmp_path, bundle, mutate)
    with pytest.raises(subject.ReleaseBundleError, match="CROSS_BINDING_INVALID"):
        subject.verify_release_input_bundle(
            tampered,
            expected_candidate_sha=candidate,
            expected_bundle_sha256=subject.sha256_file(tampered),
            perform_offline_install=False,
        )


@pytest.mark.parametrize("mutation", [
    lambda root: (root / "source/pdi.git.bundle").write_bytes(b"bad"),
    lambda root: (root / "wheelhouse/pdi-0.6.0-py3-none-any.whl").write_bytes(b"bad"),
    lambda root: (root / "dist/pdi-0.6.0.tar.gz").write_bytes(b"bad"),
    lambda root: (root / "requirements/runtime.lock").write_bytes(b"pdi>=0\n"),
    lambda root: (root / "systemd/pdi-scoped-pipeline@.service").write_bytes(b"tampered"),
    lambda root: (root / "provenance/provenance.json").write_bytes(b"{}\n"),
    lambda root: (root / "manifests/os-runtime.json").write_bytes(b"{}\n"),
    lambda root: (root / "manifests/wheelhouse.json").write_bytes(b"{}\n"),
    lambda root: (root / "manifests/release-input.json").write_bytes(b"{}\n"),
    lambda root: (root / "extra").write_bytes(b"unexpected"),
    lambda root: (root / "systemd/pdi-scoped-enrichment-immich-ocr.timer").unlink(),
])
def test_tamper_matrix_fails_closed(tmp_path: Path, mutation):
    bundle, candidate, _ = valid_bundle(tmp_path)
    tampered = rewrite_bundle(tmp_path, bundle, mutation)
    with pytest.raises(Exception):
        subject.verify_release_input_bundle(
            tampered, expected_candidate_sha=candidate,
            expected_bundle_sha256=subject.sha256_file(tampered),
            perform_offline_install=False,
        )


def test_wrong_outer_hash_candidate_and_os_hash_fail(tmp_path: Path):
    bundle, candidate, digest = valid_bundle(tmp_path)
    cases = (
        {"expected_candidate_sha": "f" * 40, "expected_bundle_sha256": digest},
        {"expected_candidate_sha": candidate, "expected_bundle_sha256": "f" * 64},
        {"expected_candidate_sha": candidate, "expected_bundle_sha256": digest,
         "expected_os_manifest_sha256": "f" * 64},
    )
    for kwargs in cases:
        with pytest.raises(Exception):
            subject.verify_release_input_bundle(bundle, perform_offline_install=False, **kwargs)


def test_builder_runtime_must_be_the_exact_wheel_module(tmp_path: Path):
    wheel = make_wheel(tmp_path / "pdi.whl", "pdi", "0.6.0")
    with pytest.raises(subject.ReleaseBundleError, match="BUILDER_INVALID"):
        subject.verify_builder_runtime(wheel)


def test_fixed_python_environments_disable_config_and_offline_index(monkeypatch):
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://foreign.invalid/simple")
    monkeypatch.setenv("PIP_INDEX_URL", "https://foreign.invalid/simple")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    online = subject._fixed_python_env(network=True)
    offline = subject._fixed_python_env(network=False)
    assert online["PIP_CONFIG_FILE"] == "/dev/null"
    assert "PIP_EXTRA_INDEX_URL" not in online
    assert "PIP_INDEX_URL" not in online
    assert online["HTTPS_PROXY"] == "http://proxy.invalid:8080"
    assert offline["PIP_NO_INDEX"] == "1"
    assert "HTTPS_PROXY" not in offline


def test_subprocess_boundary_propagates_only_fixed_child_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(
            1, args[0], stderr="private detail suppressed\nFAILURE_CODE=P3D_RELEASE_BUNDLE_SOURCE_INVALID\n",
        )

    monkeypatch.setattr(subject.subprocess, "run", fail)
    with pytest.raises(subject.ReleaseBundleError, match="SOURCE_INVALID") as error:
        subject._run((Path("/usr/bin/false"),), env={})
    assert "private detail" not in str(error.value)


def test_subprocess_boundary_uses_stage_specific_fixed_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], stderr="untrusted failure text")

    monkeypatch.setattr(subject.subprocess, "run", fail)
    with pytest.raises(subject.ReleaseBundleError, match="DISTRIBUTION_BUILD_FAILED"):
        subject._run(
            (Path("/usr/bin/false"),), env={},
            failure_code="P3D_RELEASE_BUNDLE_DISTRIBUTION_BUILD_FAILED",
        )


def test_source_bundle_proof_uses_fixed_stage_failure(monkeypatch, tmp_path):
    observed = []

    def fail(argv, **kwargs):
        observed.append(kwargs.get("failure_code"))
        raise subject.ReleaseBundleError(kwargs["failure_code"])

    monkeypatch.setattr(subject, "_run", fail)
    with pytest.raises(subject.ReleaseBundleError, match="SOURCE_PROOF_FAILED"):
        subject.verify_source_tree_from_git_bundle(
            tmp_path / "source", tmp_path / "source.bundle", CANDIDATE,
        )
    assert observed == ["P3D_RELEASE_BUNDLE_SOURCE_PROOF_FAILED"]


def test_current_python_executable_preserves_venv_symlink_boundary(tmp_path, monkeypatch):
    venv_python = tmp_path / "venv/bin/python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_bytes(b"")
    target = tmp_path / "system-python"
    target.write_bytes(b"")
    venv_python.unlink()
    venv_python.symlink_to(target)
    monkeypatch.setattr(subject.sys, "executable", str(venv_python))

    assert subject._current_python_executable() == venv_python
    assert subject._current_python_executable() != venv_python.resolve()


def test_assembly_uses_active_builder_environment_for_wheel_resolution():
    source = inspect.getsource(subject.assemble_release_input_bundle)

    assert "python = _current_python_executable()" in source
    assert "Path(sys.executable).resolve()" not in source


def test_cli_has_no_production_capabilities():
    actions = subject._parser()._subparsers._group_actions[0].choices
    assert set(actions) == {"build", "verify", "_assemble"}
    source = Path(subject.__file__).read_text()
    for forbidden in ("sudo", "systemctl", "apt-get", "/opt/pdi/releases", "/etc/pdi", "/var/lib/pdi"):
        assert forbidden not in source


def test_ci_uses_exact_pr_head_pinned_attestation_and_independent_verification():
    workflow = Path(".github/workflows/ci.yml").read_text()
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert 'test "$(git rev-parse HEAD)" = "$EXPECTED_CANDIDATE_SHA"' in workflow
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2" in workflow
    assert "actions/attest-build-provenance@" not in workflow
    assert "id: attest" in workflow
    assert "predicate-type:" not in workflow
    assert "predicate-path:" not in workflow
    assert "sbom-path:" not in workflow
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
    assert "gh attestation verify" in workflow
    assert workflow.count("scripts/build_p3d_release_bundle.py verify") == 2
    assert "attestations: write" in workflow
    assert "id-token: write" in workflow
    assert "artifact-metadata: write" in workflow
    assert '--workflow-source-sha "$GITHUB_WORKFLOW_SHA"' in workflow
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/ci.yml"' in workflow
    assert '--signer-digest "$GITHUB_WORKFLOW_SHA"' in workflow
    assert "--deny-self-hosted-runners" in workflow
    assert "--format=json" in workflow
    assert 'subject.get("digest", {}).get("sha256")' in workflow
    assert "ATTESTATION_SUBJECT_DIGEST_MISMATCH" in workflow


def test_pr_merge_sha_cannot_replace_expected_candidate(tmp_path: Path):
    repo = tmp_path / "repo"
    head = init_repo(repo)
    (repo / "merge-only.txt").write_text("merge\n")
    git(repo, "add", "merge-only.txt")
    subprocess.run(
        ["/usr/bin/git", "-C", str(repo), "-c", "user.name=PDI Test",
         "-c", "user.email=pdi-test@example.invalid", "commit", "--quiet", "-m", "merge sha"],
        check=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(repo),
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_OPTIONAL_LOCKS": "0"},
    )
    home = tmp_path / "home"
    home.mkdir()
    with pytest.raises(subject.ReleaseBundleError, match="CANDIDATE_MISMATCH"):
        subject.verify_clean_candidate_checkout(repo, head, home=home)
