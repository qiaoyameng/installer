import base64
import hashlib
import os
import shutil
from importlib.util import MAGIC_NUMBER
from pathlib import Path

import pytest

from installer import apply_uninstall, plan_uninstall
from installer import uninstall as installer_uninstall
from installer.exceptions import UninstallPlanChanged, UninstallPlanError


def record_row(path: Path, data: bytes | None = None) -> str:
    if data is None:
        return f"{path},,"
    digest = (
        base64.urlsafe_b64encode(hashlib.sha256(data).digest())
        .decode()
        .rstrip("=")
    )
    return f"{path},sha256={digest},{len(data)}"


def make_installation(tmp_path: Path, *, roots=None):
    root = tmp_path / "root"
    root.mkdir()
    dist_info = root / "fancy-1.0.dist-info"
    dist_info.mkdir()
    package = root / "fancy"
    package.mkdir()
    source = package / "__init__.py"
    source.write_bytes(b"print('fancy')\n")
    metadata = dist_info / "METADATA"
    metadata.write_bytes(b"Metadata-Version: 2.1\nName: fancy\nVersion: 1.0\n")
    record = dist_info / "RECORD"
    record.write_text(
        "\n".join(
            [
                record_row(Path("fancy/__init__.py"), source.read_bytes()),
                record_row(Path("fancy-1.0.dist-info/METADATA"), metadata.read_bytes()),
                "fancy-1.0.dist-info/RECORD,,",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return root, dist_info, [source, metadata, record]


def make_pyc(source: Path, level=0) -> Path:
    pycache = source.parent / "__pycache__"
    pycache.mkdir(exist_ok=True)
    tag = __import__("sys").implementation.cache_tag
    suffix = f".opt-{level}.pyc" if level else ".pyc"
    pyc = pycache / f"{source.stem}.{tag}{suffix}"
    source_stat = source.stat()
    header = (
        MAGIC_NUMBER
        + b"\0" * 4
        + int(source_stat.st_mtime).to_bytes(4, "little")
        + source_stat.st_size.to_bytes(4, "little")
    )
    pyc.write_bytes(header + b"bytecode")
    return pyc


def test_plan_lists_verified_files_and_owned_empty_directories(tmp_path):
    root, dist_info, installed = make_installation(tmp_path)

    plan = plan_uninstall(dist_info, [root])

    assert {item.path for item in plan.files_to_delete} == set(installed)
    assert [
        item.reason
        for item in plan.files
        if item.path == dist_info / "RECORD"
    ] == [
        "record-manifest"
    ]
    assert {item.path for item in plan.directories if item.action == "remove"} == {
        dist_info,
        root / "fancy",
    }
    assert not plan.blocked


def test_apply_deletes_record_files_and_removes_empty_owned_directories(tmp_path):
    root, dist_info, installed = make_installation(tmp_path)
    plan = plan_uninstall(dist_info, [root])

    result = apply_uninstall(plan)

    assert not result.failures
    assert set(result.removed_files) == set(installed)
    assert all(not path.exists() for path in installed)
    assert not dist_info.exists()
    assert not (root / "fancy").exists()


def test_empty_subdirectory_below_recorded_file_is_removed(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    empty_data = source.parent / "data"
    empty_data.mkdir()

    result = apply_uninstall(plan_uninstall(dist_info, [root]))

    assert not result.failures
    assert not empty_data.exists()


def test_unrecorded_nonempty_subdirectory_is_retained(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    user_directory = root / "fancy" / "user-data"
    user_directory.mkdir()
    (user_directory / "user.txt").write_text("user", encoding="utf-8")

    plan = plan_uninstall(dist_info, [root])
    package_plan = next(
        item for item in plan.directories if item.path == root / "fancy"
    )

    assert package_plan.action == "retain"
    assert package_plan.reason == "contains-unowned-file"
    result = apply_uninstall(plan)
    assert not result.failures
    assert user_directory.exists()


def test_deep_unowned_directory_retains_all_parents(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    nested = root / "fancy" / "nested" / "deep"
    nested.mkdir(parents=True)
    (nested / "user.txt").write_text("user", encoding="utf-8")

    plan = plan_uninstall(dist_info, [root])

    for directory in (nested, nested.parent, root / "fancy"):
        planned = next(item for item in plan.directories if item.path == directory)
        assert planned.action == "retain"
        assert planned.reason == "contains-unowned-file"

    result = apply_uninstall(plan)
    assert not result.failures
    assert nested.exists()


def test_directory_scan_failure_is_retained_and_blocks_parents(tmp_path, monkeypatch):
    root, dist_info, _ = make_installation(tmp_path)
    target_directory = root / "fancy"
    original_rglob = Path.rglob
    calls = 0

    def fail_second_scan(self, pattern):
        nonlocal calls
        if self == target_directory:
            calls += 1
            if calls == 2:
                raise PermissionError("denied")
        return original_rglob(self, pattern)

    monkeypatch.setattr(Path, "rglob", fail_second_scan)
    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.directories if item.path == target_directory)

    assert planned.action == "retain"
    assert planned.reason == "unable-to-scan: denied"
    assert target_directory.exists()


def test_traversal_is_rejected(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    record = dist_info / "RECORD"
    record.write_text("../evil.py,sha256=x,1\n", encoding="utf-8")

    plan = plan_uninstall(dist_info, [root])

    assert any(
        "outside of the allowed install roots" in blocker
        for blocker in plan.blockers
    )
    with pytest.raises(UninstallPlanError):
        apply_uninstall(plan)


def test_absolute_and_root_record_paths_are_rejected(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    record = dist_info / "RECORD"

    record.write_text(f"{root}/file.py,sha256=x,1\n", encoding="utf-8")
    plan = plan_uninstall(dist_info, [root])
    assert any("invalid relative RECORD path" in blocker for blocker in plan.blockers)

    record.write_text("../site-packages,sha256=x,1\n", encoding="utf-8")
    plan = plan_uninstall(dist_info, [root])
    assert any(
        "outside of the allowed install roots" in blocker
        for blocker in plan.blockers
    )


def test_duplicate_record_paths_block_apply(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    record = dist_info / "RECORD"
    text = record.read_text(encoding="utf-8")
    record.write_text(text + text.splitlines()[0] + "\n", encoding="utf-8")

    plan = plan_uninstall(dist_info, [root])

    assert any("duplicate paths" in blocker for blocker in plan.blockers)
    with pytest.raises(UninstallPlanError):
        apply_uninstall(plan)


def test_record_path_occupied_by_directory_is_retained(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    source.unlink()
    source.mkdir()

    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == source)

    assert planned.action == "retain"
    assert planned.reason == "not-a-regular-file"


def test_size_only_entry_is_verified_by_size(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    record = dist_info / "RECORD"
    lines = record.read_text(encoding="utf-8").splitlines()
    lines[0] = f"fancy/__init__.py,,{source.stat().st_size}"
    record.write_text("\n".join(lines) + "\n", encoding="utf-8")

    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == source)
    assert planned.action == "delete"

    source.write_bytes(b"different length")
    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == source)
    assert planned.action == "retain"
    assert planned.reason == "modified"


def test_symlinks_are_retained(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    target = tmp_path / "outside.py"
    target.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(target)

    plan = plan_uninstall(dist_info, [root])

    planned = next(item for item in plan.files if item.path == source)
    assert planned.action == "retain"
    assert planned.reason == "symlink"


def test_intermediate_symlink_is_retained(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    (root / "fancy").rename(root / "real-package")
    (root / "fancy").symlink_to(root / "real-package", target_is_directory=True)

    plan = plan_uninstall(dist_info, [root])
    planned = next(
        item for item in plan.files if item.path == root / "fancy" / "__init__.py"
    )

    assert planned.action == "retain"
    assert planned.reason == "symlink"


def test_modified_hashed_file_is_retained(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    source.write_bytes(b"changed\n")

    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == source)

    assert planned.action == "retain"
    assert planned.reason == "modified"
    assert apply_uninstall(plan).failures == ()
    assert source.exists()


def test_entry_without_hash_or_size_is_conservatively_retained(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    record = dist_info / "RECORD"
    lines = record.read_text(encoding="utf-8").splitlines()
    lines[0] = "fancy/__init__.py,,"
    record.write_text("\n".join(lines) + "\n", encoding="utf-8")

    default_plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in default_plan.files if item.path == source)
    assert planned.action == "retain"
    assert planned.reason == "record-entry-without-hash-or-size"

    explicit_plan = plan_uninstall(dist_info, [root], unverified_policy="all")
    explicit = next(item for item in explicit_plan.files if item.path == source)
    assert explicit.action == "delete"


def test_shared_records_keep_path_and_report_owners(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    other = root / "other-1.0.dist-info"
    other.mkdir()
    other_record = other / "RECORD"
    other_record.write_text(
        "fancy/__init__.py,sha256=abc,1\n",
        encoding="utf-8",
    )

    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == source)

    assert planned.action == "retain"
    assert planned.reason == "shared-by-other-distribution"
    assert planned.owners == ("fancy-1.0.dist-info", "other-1.0.dist-info")
    assert apply_uninstall(plan).failures == ()
    assert source.exists()
    assert other_record.exists()


def test_generated_pyc_is_removed_only_when_header_proves_source(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    pyc = make_pyc(source)

    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == pyc)

    assert planned.action == "delete"
    assert planned.reason == "generated-bytecode-opt-0"
    result = apply_uninstall(plan)
    assert not pyc.exists()
    assert not result.failures


def test_hash_based_pyc_is_retained_conservatively(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    pyc = make_pyc(source)
    data = bytearray(pyc.read_bytes())
    data[4] = 1
    pyc.write_bytes(bytes(data))

    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == pyc)

    assert planned.action == "retain"
    assert planned.reason == "bytecode-source-mismatch"
    assert apply_uninstall(plan).failures == ()
    assert pyc.exists()


def test_abi_mismatched_pyc_is_reported_and_retained(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    pycache = source.parent / "__pycache__"
    pycache.mkdir(exist_ok=True)
    foreign = pycache / "__init__.cpython-311.pyc"
    foreign.write_bytes(b"foreign bytecode")

    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == foreign)

    assert planned.action == "retain"
    assert planned.reason == "bytecode-abi-mismatch"
    assert apply_uninstall(plan).failures == ()
    assert foreign.exists()


def test_unrelated_pyc_keeps_pycache_and_source_directory(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    pycache = source.parent / "__pycache__"
    pycache.mkdir()
    user_pyc = pycache / "__init__.cpython-999.pyc"
    user_pyc.write_bytes(b"user bytecode")

    plan = plan_uninstall(dist_info, [root])

    pycache_plan = next(item for item in plan.directories if item.path == pycache)
    package_plan = next(
        item for item in plan.directories if item.path == source.parent
    )
    assert pycache_plan.action == "retain"
    assert package_plan.action == "retain"
    result = apply_uninstall(plan)
    assert not result.failures
    assert user_pyc.exists()


def test_unrelated_pyc_is_retained_without_scanning_user_files(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    unrelated_package = root / "userpkg"
    unrelated_package.mkdir()
    pycache = unrelated_package / "__pycache__"
    pycache.mkdir()
    user_pyc = pycache / "user.cpython-999.pyc"
    user_pyc.write_bytes(b"user")

    result = apply_uninstall(plan_uninstall(dist_info, [root]))

    assert not result.failures
    assert user_pyc.exists()


def test_record_relative_path_can_span_allowed_roots(tmp_path):
    site_packages = tmp_path / "site-packages"
    scripts = tmp_path / "bin"
    site_packages.mkdir()
    scripts.mkdir()
    dist_info = site_packages / "fancy-1.0.dist-info"
    dist_info.mkdir()
    script = scripts / "fancy"
    script.write_bytes(b"#!/python\n")
    record = dist_info / "RECORD"
    record.write_text(
        record_row(Path("../bin/fancy"), script.read_bytes()) + "\n",
        encoding="utf-8",
    )

    plan = plan_uninstall(dist_info, [scripts, site_packages])

    assert next(item for item in plan.files if item.path == script).action == "delete"
    result = apply_uninstall(plan)
    assert not result.failures
    assert not script.exists()


def test_apply_rejects_plan_changed_after_planning(tmp_path):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    plan = plan_uninstall(dist_info, [root])
    source.write_bytes(b"changed\n")

    with pytest.raises(UninstallPlanChanged):
        apply_uninstall(plan)
    assert source.exists()


def test_unlink_failure_is_reported_as_partial_without_pretending_atomicity(
    tmp_path, monkeypatch
):
    root, dist_info, (source, metadata, record) = make_installation(tmp_path)
    plan = plan_uninstall(dist_info, [root])
    original_unlink = Path.unlink

    def fail_metadata(self, *args, **kwargs):
        if self == metadata:
            raise PermissionError("denied")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_metadata)
    result = apply_uninstall(plan)

    assert not result.rolled_back
    assert source in result.removed_files
    assert record in result.removed_files
    assert metadata.exists()
    assert (metadata, "denied") in result.failures


def test_directory_replaced_before_removal_is_reported_without_staging(
    tmp_path, monkeypatch
):
    root, dist_info, _ = make_installation(tmp_path)
    plan = plan_uninstall(dist_info, [root])

    def replace_first_directory(self):
        if self == root / "fancy":
            target = tmp_path / "package-link-target"
            target.mkdir()
            self.symlink_to(target, target_is_directory=True)
        return os.rmdir(self)

    monkeypatch.setattr(Path, "rmdir", replace_first_directory)
    result = apply_uninstall(plan)

    assert any(
        path == root / "fancy" and "replaced" in message
        for path, message in result.failures
    )


def test_staged_apply_rolls_back_directory_failure(tmp_path, monkeypatch):
    root, dist_info, (source, metadata, record) = make_installation(tmp_path)
    plan = plan_uninstall(dist_info, [root])
    original_rmdir = Path.rmdir

    def fail_dist_info(self):
        if self == dist_info:
            raise OSError("busy")
        return original_rmdir(self)

    monkeypatch.setattr(Path, "rmdir", fail_dist_info)
    result = apply_uninstall(plan, staging_directory=tmp_path / "staging")

    assert result.rolled_back
    assert result.staged_directory is not None
    assert source.exists()
    assert metadata.exists()
    assert record.exists()
    assert result.staged_directory.exists()


def test_staged_apply_moves_files_and_removes_staging_on_success(tmp_path):
    root, dist_info, installed = make_installation(tmp_path)
    staging_parent = tmp_path / "recovery"

    result = apply_uninstall(
        plan_uninstall(dist_info, [root]), staging_directory=staging_parent
    )

    assert not result.failures
    assert not result.rolled_back
    assert set(result.removed_files) == set(installed)
    assert not any(staging_parent.iterdir())


def test_staged_cleanup_failure_keeps_recovery_directory(tmp_path, monkeypatch):
    root, dist_info, installed = make_installation(tmp_path)
    staging_parent = tmp_path / "recovery"

    def fail_rmtree(path, *args, **kwargs):
        if str(path).startswith(str(staging_parent)):
            raise OSError("cleanup denied")
        return shutil.rmtree(path, *args, **kwargs)

    monkeypatch.setattr("installer.uninstall.shutil.rmtree", fail_rmtree)
    result = apply_uninstall(
        plan_uninstall(dist_info, [root]), staging_directory=staging_parent
    )

    assert set(result.removed_files) == set(installed)
    assert result.staged_directory is not None
    assert result.staged_directory.exists()
    assert result.failures


def test_staged_apply_reports_failed_rollback_and_keeps_stage(tmp_path, monkeypatch):
    root, dist_info, _ = make_installation(tmp_path)
    staging_parent = tmp_path / "recovery"
    plan = plan_uninstall(dist_info, [root])
    outbound_moves = 0
    rollback_moves = 0
    original_rename = os.rename
    original_move = installer_uninstall._move_to_stage

    def controlled_outbound(src, dst):
        nonlocal outbound_moves
        outbound_moves += 1
        if outbound_moves == 3:
            raise OSError("outbound failed")
        return original_move(src, dst)

    def controlled_rename(src, dst):
        nonlocal rollback_moves
        if str(staging_parent) not in str(src):
            rollback_moves += 1
            if rollback_moves == 1:
                raise OSError("rollback failed")
        return original_rename(src, dst)

    monkeypatch.setattr("installer.uninstall._move_to_stage", controlled_outbound)
    monkeypatch.setattr("installer.uninstall.os.rename", controlled_rename)
    result = apply_uninstall(plan, staging_directory=staging_parent)

    assert result.rolled_back
    assert result.staged_directory is not None
    assert result.staged_directory.exists()
    assert any("rollback failed" in message for _, message in result.failures)


def test_plan_rejects_invalid_inputs(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)

    with pytest.raises(UninstallPlanError, match="At least one allowed install root"):
        plan_uninstall(dist_info, [])
    with pytest.raises(UninstallPlanError, match="Install root"):
        plan_uninstall(dist_info, [tmp_path / "missing-root"])
    with pytest.raises(UninstallPlanError, match="Not a valid .dist-info"):
        plan_uninstall(root / "fancy", [root])
    with pytest.raises(UninstallPlanError, match="Missing real RECORD"):
        (dist_info / "RECORD").unlink()
        plan_uninstall(dist_info, [root])


def test_invalid_arguments_are_rejected(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)

    with pytest.raises(UninstallPlanError, match="unverified_policy"):
        plan_uninstall(dist_info, [root], unverified_policy="never")
    with pytest.raises(UninstallPlanError, match="Invalid bytecode"):
        plan_uninstall(dist_info, [root], bytecode_optimization_levels=[3])


def test_symlinked_dist_info_blocks_ownership(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    alias = root / "evil-1.0.dist-info"
    alias.symlink_to(dist_info, target_is_directory=True)

    plan = plan_uninstall(dist_info, [root])

    assert any("Symlinked dist-info" in blocker for blocker in plan.blockers)
    with pytest.raises(UninstallPlanError):
        apply_uninstall(plan)


def test_malformed_current_record_blocks_apply(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    (dist_info / "RECORD").write_text("only-one-field\n", encoding="utf-8")

    plan = plan_uninstall(dist_info, [root])

    assert plan.blocked
    with pytest.raises(UninstallPlanError):
        apply_uninstall(plan)


def test_unreadable_install_root_blocks_apply(tmp_path, monkeypatch):
    root, dist_info, _ = make_installation(tmp_path)
    original_iterdir = Path.iterdir

    def fail_root(self):
        if self == root:
            raise PermissionError("denied")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", fail_root)
    plan = plan_uninstall(dist_info, [root])

    assert any("Unable to scan install root" in blocker for blocker in plan.blockers)
    with pytest.raises(UninstallPlanError):
        apply_uninstall(plan)


def test_unreadable_bytecode_directory_blocks_apply(tmp_path, monkeypatch):
    root, dist_info, (source, _, _) = make_installation(tmp_path)
    cache_directory = source.parent / "__pycache__"
    cache_directory.mkdir()
    original_iterdir = Path.iterdir

    def fail_cache(self):
        if self == cache_directory:
            raise PermissionError("denied")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", fail_cache)
    plan = plan_uninstall(dist_info, [root])

    assert any(
        "Unable to scan bytecode directory" in blocker
        for blocker in plan.blockers
    )
    with pytest.raises(UninstallPlanError):
        apply_uninstall(plan)


def test_invalid_hash_algorithm_blocks_plan(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    record = dist_info / "RECORD"
    lines = record.read_text(encoding="utf-8").splitlines()
    lines[0] = "fancy/__init__.py,not-real=x,15"
    record.write_text("\n".join(lines) + "\n", encoding="utf-8")

    plan = plan_uninstall(dist_info, [root])

    assert any("invalid hash algorithm" in blocker for blocker in plan.blockers)
    with pytest.raises(UninstallPlanError):
        apply_uninstall(plan)


def test_unreadable_file_checksum_is_reported_as_retained(tmp_path, monkeypatch):
    root, dist_info, (source, _, _) = make_installation(tmp_path)

    def fail_open(self, *args, **kwargs):
        if self == source:
            raise PermissionError("denied")
        return open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_open)
    plan = plan_uninstall(dist_info, [root])
    planned = next(item for item in plan.files if item.path == source)

    assert planned.action == "retain"
    assert planned.reason == "unable-to-verify"


def test_directory_replaced_by_symlink_before_apply_is_stale(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    plan = plan_uninstall(dist_info, [root])
    Path.rename(root / "fancy", root / "fancy-real")
    (root / "fancy").symlink_to(root / "fancy-real", target_is_directory=True)

    with pytest.raises(UninstallPlanChanged):
        apply_uninstall(plan)


def test_staging_directory_cannot_be_inside_install_root(tmp_path):
    root, dist_info, _ = make_installation(tmp_path)
    plan = plan_uninstall(dist_info, [root])

    with pytest.raises(UninstallPlanError):
        apply_uninstall(plan, staging_directory=root / "staging")
