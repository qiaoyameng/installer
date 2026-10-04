import base64
import hashlib
import os
from pathlib import Path

import pytest

from installer.exceptions import UninstallError
from installer.uninstall import apply_uninstall, plan_uninstall

DIST_INFO = "fancy-1.0.0.dist-info"


def _hash(data):
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def install_layout(tmp_path, files, *, extra_rows=()):
    """Create an installed-distribution layout under tmp_path/"site-packages".

    ``files`` maps RECORD-relative paths to contents; RECORD is generated
    with correct hashes and sizes, plus a METADATA file and ``extra_rows``.
    """
    scheme = tmp_path / "site-packages"
    dist_info = scheme / DIST_INFO
    rows = []
    for relative, data in sorted(files.items()):
        path = scheme / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        rows.append(f"{relative},{_hash(data)},{len(data)}")
    dist_info.mkdir(parents=True, exist_ok=True)
    metadata = b"Name: fancy\nVersion: 1.0.0\n"
    (dist_info / "METADATA").write_bytes(metadata)
    rows.append(f"{DIST_INFO}/METADATA,{_hash(metadata)},{len(metadata)}")
    rows.extend(extra_rows)
    rows.append(f"{DIST_INFO}/RECORD,,")
    (dist_info / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")
    return scheme, dist_info


@pytest.fixture()
def installed(tmp_path):
    scheme, dist_info = install_layout(
        tmp_path,
        {
            "fancy/__init__.py": b"def main():\n    pass\n",
            "fancy/mod.py": b"X = 1\n",
        },
    )
    return scheme, dist_info


def kept_reasons(plan):
    return {entry.path.name: entry.reason for entry in plan.kept}


class TestPlan:
    def test_lists_files_and_empty_dirs(self, installed):
        scheme, dist_info = installed
        plan = plan_uninstall(dist_info, [scheme])

        assert {f.path.name for f in plan.files} == {
            "__init__.py",
            "mod.py",
            "METADATA",
            "RECORD",
        }
        assert scheme / "fancy" in plan.empty_dirs
        assert dist_info in plan.empty_dirs
        assert scheme not in plan.empty_dirs
        assert plan.kept == []

    def test_dist_info_outside_allowed_roots(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {})
        with pytest.raises(ValueError, match="not within any allowed root"):
            plan_uninstall(dist_info, [tmp_path / "elsewhere"])

    def test_requires_dist_info_directory(self, tmp_path):
        with pytest.raises(ValueError, match="not a .dist-info directory"):
            plan_uninstall(tmp_path, [tmp_path])

    def test_requires_record_file(self, tmp_path):
        dist_info = tmp_path / DIST_INFO
        dist_info.mkdir()
        with pytest.raises(FileNotFoundError, match="no RECORD file"):
            plan_uninstall(dist_info, [tmp_path])

    def test_rejects_parent_directory_escape(self, tmp_path):
        scheme, dist_info = install_layout(
            tmp_path, {}, extra_rows=["../../escape.txt,,"]
        )
        plan = plan_uninstall(dist_info, [scheme])
        assert kept_reasons(plan) == {"escape.txt": "outside allowed roots"}

    def test_rejects_absolute_path_outside_roots(self, tmp_path):
        scheme, dist_info = install_layout(
            tmp_path, {}, extra_rows=[f"{tmp_path / 'escape.txt'},,"]
        )
        plan = plan_uninstall(dist_info, [scheme])
        assert kept_reasons(plan) == {"escape.txt": "outside allowed roots"}

    def test_rejects_symlink_escape(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_bytes(b"secret")
        scheme, dist_info = install_layout(tmp_path, {})
        (scheme / "link").symlink_to(outside)
        secret = outside / "secret.txt"
        (dist_info / "RECORD").write_text(
            f"link/secret.txt,{_hash(b'secret')},6\n{DIST_INFO}/RECORD,,\n",
            encoding="utf-8",
        )

        plan = plan_uninstall(dist_info, [scheme])

        assert kept_reasons(plan) == {"secret.txt": "outside allowed roots"}
        result = apply_uninstall(plan)
        assert secret.read_bytes() == b"secret"
        assert "secret.txt" not in {p.name for p in result.removed_files}

    def test_keeps_modified_files_by_default(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {"fancy/mod.py": b"X = 1\n"})
        (scheme / "fancy" / "mod.py").write_bytes(b"X = 2\n")

        plan = plan_uninstall(dist_info, [scheme])
        assert kept_reasons(plan) == {"mod.py": "modified after installation"}

        plan = plan_uninstall(dist_info, [scheme], remove_modified=True)
        assert "mod.py" in {f.path.name for f in plan.files}

    def test_keeps_unverified_files_by_default(self, tmp_path):
        scheme, dist_info = install_layout(
            tmp_path, {}, extra_rows=["script.py,,"]
        )
        (scheme / "script.py").write_bytes(b"print('hi')\n")

        plan = plan_uninstall(dist_info, [scheme])
        assert kept_reasons(plan) == {"script.py": "no hash/size to verify against"}

        plan = plan_uninstall(dist_info, [scheme], remove_unverified=True)
        assert "script.py" in {f.path.name for f in plan.files}

    def test_dist_info_files_need_no_verification(self, tmp_path):
        # RECORD's own entry has no hash, but files inside the .dist-info
        # directory are provably owned by the distribution.
        scheme, dist_info = install_layout(tmp_path, {})
        plan = plan_uninstall(dist_info, [scheme])
        assert {f.path.name for f in plan.files} == {"METADATA", "RECORD"}
        assert plan.kept == []

    def test_keeps_files_shared_with_other_distributions(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {"shared.py": b"X = 1\n"})
        other = scheme / "other-2.0.dist-info"
        other.mkdir()
        (other / "RECORD").write_text("shared.py,,\n", encoding="utf-8")

        plan = plan_uninstall(dist_info, [scheme])

        assert kept_reasons(plan) == {"shared.py": "also owned by another distribution"}
        result = apply_uninstall(plan)
        assert (scheme / "shared.py").read_bytes() == b"X = 1\n"
        assert "shared.py" not in {p.name for p in result.removed_files}

    def test_removes_generated_bytecode(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {"fancy/mod.py": b"X = 1\n"})
        pycache = scheme / "fancy" / "__pycache__"
        pycache.mkdir()
        (pycache / "mod.cpython-312.pyc").write_bytes(b"pyc")
        (pycache / "mod.cpython-312.opt-1.pyc").write_bytes(b"pyc")

        plan = plan_uninstall(dist_info, [scheme])

        assert {f.path.name for f in plan.files} >= {
            "mod.cpython-312.pyc",
            "mod.cpython-312.opt-1.pyc",
        }
        assert pycache in plan.empty_dirs

    def test_ignores_unrelated_pyc_named_files(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {"fancy/mod.py": b"X = 1\n"})
        pycache = scheme / "fancy" / "__pycache__"
        pycache.mkdir()
        stray = pycache / "other.cpython-312.pyc"
        stray.write_bytes(b"pyc")

        plan = plan_uninstall(dist_info, [scheme])

        assert stray not in [f.path for f in plan.files]

    def test_missing_files_are_reported(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {"gone.py": b""})
        (scheme / "gone.py").unlink()
        plan = plan_uninstall(dist_info, [scheme])
        assert kept_reasons(plan) == {"gone.py": "already missing"}

    def test_accepts_relative_dist_info_path(self, tmp_path, monkeypatch):
        scheme, dist_info = install_layout(tmp_path, {"fancy/mod.py": b"X = 1\n"})
        monkeypatch.chdir(tmp_path)

        plan = plan_uninstall(
            Path("site-packages") / DIST_INFO, [Path("site-packages")]
        )

        assert plan.kept == []
        assert "mod.py" in {f.path.name for f in plan.files}


class TestApply:
    def test_removes_files_and_empty_dirs(self, installed):
        scheme, dist_info = installed
        pycache = scheme / "fancy" / "__pycache__"
        pycache.mkdir()
        (pycache / "mod.cpython-312.pyc").write_bytes(b"pyc")

        plan = plan_uninstall(dist_info, [scheme])
        result = apply_uninstall(plan)

        assert not (scheme / "fancy").exists()
        assert not dist_info.exists()
        assert scheme.exists()
        assert set(result.removed_dirs) == {scheme / "fancy", pycache, dist_info}
        assert result.kept == []

    def test_never_deletes_unowned_files(self, installed):
        scheme, dist_info = installed
        user_file = scheme / "fancy" / "user-notes.txt"
        user_file.write_bytes(b"mine")

        plan = plan_uninstall(dist_info, [scheme])
        result = apply_uninstall(plan)

        assert user_file.read_bytes() == b"mine"
        assert (scheme / "fancy").exists()
        assert scheme / "fancy" not in result.removed_dirs

    def test_detects_modification_after_plan(self, installed):
        scheme, dist_info = installed
        plan = plan_uninstall(dist_info, [scheme])
        target = scheme / "fancy" / "mod.py"
        target.write_bytes(b"replaced after planning\n")

        with pytest.raises(UninstallError, match="no longer matches") as exc_info:
            apply_uninstall(plan)

        # Partial progress is reported, not hidden.
        assert exc_info.value.removed
        assert target.read_bytes() == b"replaced after planning\n"

    def test_apply_accepts_files_planned_as_modified(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {"fancy/mod.py": b"X = 1\n"})
        (scheme / "fancy" / "mod.py").write_bytes(b"X = 2\n")

        plan = plan_uninstall(dist_info, [scheme], remove_modified=True)
        result = apply_uninstall(plan)

        assert not (scheme / "fancy" / "mod.py").exists()
        assert "mod.py" in {p.name for p in result.removed_files}

    def test_detects_symlink_swap_after_plan(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {"pkg/mod.py": b"X = 1\n"})
        outside = tmp_path / "outside"
        outside.mkdir()
        plan = plan_uninstall(dist_info, [scheme])
        (scheme / "pkg").rename(outside / "pkg")
        (scheme / "pkg").symlink_to(outside / "pkg")

        with pytest.raises(UninstallError, match="no longer resolves"):
            apply_uninstall(plan)

        assert (outside / "pkg" / "mod.py").read_bytes() == b"X = 1\n"

    def test_staging_restores_files_on_failure(self, tmp_path):
        scheme, dist_info = install_layout(
            tmp_path, {"pkg/a.py": b"A\n", "pkg/b.py": b"B\n"}
        )
        plan = plan_uninstall(dist_info, [scheme])
        (scheme / "pkg" / "b.py").write_bytes(b"tampered\n")

        with pytest.raises(UninstallError) as exc_info:
            apply_uninstall(plan, staging_dir=tmp_path / "staging")

        # The file removed before the failure was put back.
        assert (scheme / "pkg" / "a.py").read_bytes() == b"A\n"
        assert exc_info.value.restored
        assert (scheme / "pkg" / "b.py").read_bytes() == b"tampered\n"

    def test_staging_is_cleaned_up_on_success(self, tmp_path):
        scheme, dist_info = install_layout(tmp_path, {"pkg/a.py": b"A\n"})
        staging = tmp_path / "staging"
        plan = plan_uninstall(dist_info, [scheme])
        apply_uninstall(plan, staging_dir=staging)
        assert not staging.exists()
        assert not (scheme / "pkg").exists()
