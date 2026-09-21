import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from pdi.production_ops.cutover import trusted_path
from pdi.production_ops.enrichment_cutover import (
    GIT_READ_ONLY_ENV,
    P3DControlRefused,
    build_pre_rehearsal_qualification_proof,
    verify_release,
    verify_release_immutability,
)


def _metadata(kind: str, mode: int, *, uid: int = 0, gid: int = 0):
    kinds = {
        "file": stat.S_IFREG,
        "directory": stat.S_IFDIR,
        "symlink": stat.S_IFLNK,
    }
    return SimpleNamespace(st_mode=kinds[kind] | mode, st_uid=uid, st_gid=gid)


def _path_reader(leaf: Path, leaf_info, *, overrides=None):
    overrides = dict(overrides or {})

    def read(path: Path):
        if path == leaf:
            return leaf_info
        if path in overrides:
            return overrides[path]
        return _metadata("directory", 0o755)

    return read


def test_unit_root_root_0644_is_trusted():
    path = Path("/etc/systemd/system/pdi-scoped-pipeline@.service")
    assert trusted_path(
        path,
        expected_kind="file",
        exact_mode=0o644,
        require_root_group=True,
        stat_reader=_path_reader(path, _metadata("file", 0o644)),
    )


@pytest.mark.parametrize(
    ("leaf", "overrides"),
    (
        (_metadata("file", 0o644, uid=1001), {}),
        (_metadata("file", 0o644, gid=1001), {}),
        (_metadata("file", 0o664, gid=1001), {}),
        (_metadata("file", 0o666), {}),
        (_metadata("symlink", 0o777), {}),
        (
            _metadata("file", 0o644),
            {Path("/etc/systemd/system"): _metadata("directory", 0o775)},
        ),
        (
            _metadata("file", 0o644),
            {Path("/etc/systemd/system"): _metadata("directory", 0o755, uid=1001)},
        ),
        (
            _metadata("file", 0o644),
            {Path("/etc/systemd"): _metadata("symlink", 0o777)},
        ),
    ),
)
def test_unit_untrusted_owner_mode_link_or_parent_fails(leaf, overrides):
    path = Path("/etc/systemd/system/pdi-scoped-pipeline@.service")
    assert not trusted_path(
        path,
        expected_kind="file",
        exact_mode=0o644,
        require_root_group=True,
        stat_reader=_path_reader(path, leaf, overrides=overrides),
    )


def test_profile_root_root_0600_is_trusted():
    path = Path("/etc/pdi/scoped/units/enrichment.immich_ocr.env")
    assert trusted_path(
        path,
        expected_kind="file",
        exact_mode=0o600,
        private=True,
        require_root_group=True,
        stat_reader=_path_reader(path, _metadata("file", 0o600)),
    )


@pytest.mark.parametrize(
    ("leaf", "overrides"),
    (
        (_metadata("file", 0o600, uid=1001), {}),
        (_metadata("file", 0o600, gid=1001), {}),
        (_metadata("file", 0o640, gid=1001), {}),
        (_metadata("file", 0o644), {}),
        (_metadata("symlink", 0o777), {}),
        (
            _metadata("file", 0o600),
            {Path("/etc/pdi/scoped/units"): _metadata("directory", 0o770)},
        ),
        (
            _metadata("file", 0o600),
            {Path("/etc/pdi/scoped/units"): _metadata("directory", 0o700, uid=1001)},
        ),
        (
            _metadata("file", 0o600),
            {Path("/etc/pdi/scoped"): _metadata("symlink", 0o777)},
        ),
    ),
)
def test_profile_untrusted_owner_mode_link_or_parent_fails(leaf, overrides):
    path = Path("/etc/pdi/scoped/units/enrichment.immich_ocr.env")
    assert not trusted_path(
        path,
        expected_kind="file",
        exact_mode=0o600,
        private=True,
        require_root_group=True,
        stat_reader=_path_reader(path, leaf, overrides=overrides),
    )


def _release_tree():
    sha = "c" * 40
    releases_root = Path("/opt/pdi/releases")
    release = releases_root / sha
    python_link = release / ".venv/bin/python"
    python_target = Path("/usr/bin/python3.13")
    source = release / "src/pdi/scoped_operational.py"
    enrichment = release / "src/pdi/production_ops/enrichment.py"
    cutover = release / "scripts/mu13_p3d_cutover.py"
    package = release / ".venv/lib/python3.13/site-packages/pdi_runtime.py"
    lib64_link = release / ".venv/lib64"
    lib_target = release / ".venv/lib"
    entries = (
        release / ".git",
        release / ".git/HEAD",
        release / "src",
        release / "src/pdi",
        source,
        release / "src/pdi/production_ops",
        enrichment,
        release / "scripts",
        cutover,
        release / ".venv",
        release / ".venv/bin",
        python_link,
        release / ".venv/lib",
        release / ".venv/lib/python3.13",
        release / ".venv/lib/python3.13/site-packages",
        package,
        lib64_link,
    )
    metadata = {
        Path("/"): _metadata("directory", 0o755),
        Path("/opt"): _metadata("directory", 0o755),
        Path("/opt/pdi"): _metadata("directory", 0o755),
        releases_root: _metadata("directory", 0o755),
        release: _metadata("directory", 0o755),
        Path("/usr"): _metadata("directory", 0o755),
        Path("/usr/bin"): _metadata("directory", 0o755),
        python_target: _metadata("file", 0o755),
    }
    for entry in entries:
        if entry == python_link:
            metadata[entry] = _metadata("symlink", 0o777)
        elif entry.suffix in {".py"} or entry.name == "HEAD":
            metadata[entry] = _metadata("file", 0o644)
        else:
            metadata[entry] = _metadata("directory", 0o755)
    metadata[lib64_link] = _metadata("symlink", 0o777)
    resolvers = {python_link: python_target, lib64_link: lib_target}

    def read(path: Path):
        try:
            return metadata[path]
        except KeyError:
            raise OSError("synthetic missing path") from None

    def resolve(path: Path):
        return resolvers.get(path, path)

    return SimpleNamespace(
        sha=sha,
        releases_root=releases_root,
        release=release,
        source=source,
        python_link=python_link,
        python_target=python_target,
        lib64_link=lib64_link,
        package=package,
        entries=entries,
        metadata=metadata,
        resolvers=resolvers,
        read=read,
        resolve=resolve,
    )


def _verify_tree(tree) -> bool:
    return verify_release_immutability(
        tree.release,
        tree.sha,
        releases_root=tree.releases_root,
        stat_reader=tree.read,
        tree_entries=lambda _root: tree.entries,
        resolver=tree.resolve,
    )


def test_trusted_root_owned_release_tree_passes():
    assert _verify_tree(_release_tree())


@pytest.mark.parametrize("target", ("release", "source", "package", "python_target"))
def test_release_runtime_owner_must_be_root(target):
    tree = _release_tree()
    path = getattr(tree, target)
    current = tree.metadata[path]
    kind = "directory" if stat.S_ISDIR(current.st_mode) else "file"
    tree.metadata[path] = _metadata(kind, stat.S_IMODE(current.st_mode), uid=1001)
    assert not _verify_tree(tree)


def test_release_runtime_group_must_be_root():
    tree = _release_tree()
    tree.metadata[tree.package] = _metadata("file", 0o644, gid=1001)
    assert not _verify_tree(tree)


def test_release_source_owned_and_writable_by_runtime_user_fails():
    tree = _release_tree()
    tree.metadata[tree.source] = _metadata("file", 0o644, uid=1001, gid=1001)
    assert not _verify_tree(tree)


def test_release_runtime_directory_group_writable_fails():
    tree = _release_tree()
    runtime_dir = tree.release / ".venv/lib/python3.13/site-packages"
    tree.metadata[runtime_dir] = _metadata("directory", 0o775)
    assert not _verify_tree(tree)


def test_release_symlink_escaping_to_tmp_fails():
    tree = _release_tree()
    tree.resolvers[tree.python_link] = Path("/tmp/untrusted-python")
    assert not _verify_tree(tree)


def test_release_interpreter_link_to_user_owned_target_fails():
    tree = _release_tree()
    tree.metadata[tree.python_target] = _metadata("file", 0o755, uid=1001, gid=1001)
    assert not _verify_tree(tree)


def test_release_python_symlink_must_be_root_owned():
    tree = _release_tree()
    tree.metadata[tree.python_link] = _metadata("symlink", 0o777, uid=1001, gid=1001)
    assert not _verify_tree(tree)


def test_release_internal_symlink_requires_trusted_target():
    tree = _release_tree()
    tree.metadata[tree.release / ".venv/lib"] = _metadata("directory", 0o775)
    assert not _verify_tree(tree)


def test_release_ancestor_symlink_fails():
    tree = _release_tree()
    tree.metadata[Path("/opt/pdi")] = _metadata("symlink", 0o777)
    assert not _verify_tree(tree)


def test_release_symlink_resolution_error_fails_closed():
    tree = _release_tree()

    def resolve(path):
        if path == tree.python_link:
            raise RuntimeError("synthetic symlink loop")
        return tree.resolve(path)

    assert not verify_release_immutability(
        tree.release,
        tree.sha,
        releases_root=tree.releases_root,
        stat_reader=tree.read,
        tree_entries=lambda _root: tree.entries,
        resolver=resolve,
    )


def test_release_path_must_be_exact_sha_directory():
    tree = _release_tree()
    assert not verify_release_immutability(
        Path("/tmp") / tree.sha,
        tree.sha,
        releases_root=tree.releases_root,
        stat_reader=tree.read,
        tree_entries=lambda _root: tree.entries,
        resolver=tree.resolve,
    )


def test_verify_release_requires_exact_git_sha_and_clean_source():
    tree = _release_tree()
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[3:5] == ("rev-parse", "HEAD"):
            return SimpleNamespace(returncode=0, stdout=tree.sha + "\n")
        if argv[3] == "status":
            return SimpleNamespace(returncode=0, stdout="")
        raise AssertionError(argv)

    assert verify_release(
        tree.release,
        tree.sha,
        runner=runner,
        releases_root=tree.releases_root,
        immutability_verifier=lambda *_args, **_kwargs: True,
    )
    assert [call[0][3:] for call in calls] == [
        ("rev-parse", "HEAD"),
        ("status", "--porcelain", "--untracked-files=all"),
    ]
    assert all(call[1]["env"] == GIT_READ_ONLY_ENV for call in calls)

    def wrong_sha_runner(argv, **_kwargs):
        return SimpleNamespace(returncode=0, stdout="f" * 40 + "\n")

    assert not verify_release(
        tree.release,
        tree.sha,
        runner=wrong_sha_runner,
        releases_root=tree.releases_root,
        immutability_verifier=lambda *_args, **_kwargs: True,
    )


def test_verify_release_git_environment_is_allowlisted(monkeypatch):
    tree = _release_tree()
    for name, value in {
        "GIT_OPTIONAL_LOCKS": "1",
        "GIT_INDEX_FILE": "/tmp/evil-index",
        "GIT_DIR": "/tmp/evil-git",
        "GIT_WORK_TREE": "/tmp/evil-worktree",
    }.items():
        monkeypatch.setenv(name, value)
    environments = []

    def runner(argv, **kwargs):
        environments.append(kwargs["env"])
        output = tree.sha + "\n" if argv[3] == "rev-parse" else ""
        return SimpleNamespace(returncode=0, stdout=output)

    assert verify_release(
        tree.release,
        tree.sha,
        runner=runner,
        releases_root=tree.releases_root,
        immutability_verifier=lambda *_args, **_kwargs: True,
    )
    assert environments == [GIT_READ_ONLY_ENV, GIT_READ_ONLY_ENV]
    assert set(environments[0]) == {"PATH", "LC_ALL", "GIT_OPTIONAL_LOCKS"}


def test_verify_release_rejects_dirty_worktree():
    tree = _release_tree()

    def dirty_runner(argv, **_kwargs):
        if argv[3:5] == ("rev-parse", "HEAD"):
            return SimpleNamespace(returncode=0, stdout=tree.sha + "\n")
        return SimpleNamespace(returncode=0, stdout=" M src/pdi/runtime.py\n")

    assert not verify_release(
        tree.release,
        tree.sha,
        runner=dirty_runner,
        releases_root=tree.releases_root,
        immutability_verifier=lambda *_args, **_kwargs: True,
    )


def test_static_proof_rejects_untrusted_asset_before_read(monkeypatch):
    calls = []

    def reject(path, **_kwargs):
        calls.append(path)
        return False

    monkeypatch.setattr(
        "pdi.production_ops.enrichment_cutover.trusted_path", reject
    )
    context = {
        "release_sha": "c" * 40,
        "p3c_pass": True,
        "writers_healthy": True,
        "legacy_enrichment_disabled": True,
        "p3d_timers_off": True,
        "gmail_disabled": True,
        "rollback_qualified": True,
        "read_only_db_guarantee": True,
        "principal_ref": "synthetic-principal",
        "db_route": "synthetic-db",
        "db_identity_fingerprint": "f" * 64,
        "enabled_scope_ids": ["scope-a"],
    }
    with pytest.raises(P3DControlRefused, match="ASSET_UNTRUSTED"):
        build_pre_rehearsal_qualification_proof(
            candidate_sha="c" * 40,
            rollback_source_sha="a" * 40,
            context=context,
            unit_dir=Path("/does/not/need/to/exist"),
            profile_dir=Path("/does/not/need/to/exist"),
        )
    assert len(calls) == 1
