"""Tests for the transactional destination.

These tests inject failures at the three critical boundaries -- staging file
writes, target replacements, and the final RECORD write -- and verify that the
target schemes are either fully installed or fully restored afterwards. Only
in-repo mock wheels are used; no third-party package is installed.
"""

import base64
import hashlib
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

from installer import install
from installer.exceptions import TransactionError
from installer.records import parse_record_file
from installer.sources import WheelFile
from installer.transactions import TransactionalSchemeDictionaryDestination
from installer.utils import SCHEME_NAMES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@pytest.fixture()
def mock_wheel_path(tmp_path):
    """Build a wheel whose scripts scheme file carries a rewritable shebang."""
    path = tmp_path / "fancy-1.0.0-py3-none-any.whl"
    files = {
        "fancy/__init__.py": b"def main():\n    print('fancy')\n",
        "fancy/module.py": b"# purelib module\n",
        "fancy-1.0.0.data/data/fancy/data.py": b"# data file\n",
        "fancy-1.0.0.data/scripts/fancy-script.py": b"#!python\nimport fancy\n",
        "fancy-1.0.0.dist-info/top_level.txt": b"fancy\n",
        "fancy-1.0.0.dist-info/entry_points.txt": (
            b"[console_scripts]\nfancy = fancy:main\n"
        ),
        "fancy-1.0.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "fancy-1.0.0.dist-info/METADATA": (
            b"Metadata-Version: 2.1\nName: fancy\nVersion: 1.0.0\n"
        ),
        "fancy-1.0.0.dist-info/RECORD": b"",
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


@pytest.fixture()
def layout(tmp_path):
    """Create empty per-scheme roots and a transaction directory."""
    target = tmp_path / "target"
    target.mkdir()
    scheme_dict = {}
    for scheme_name in SCHEME_NAMES:
        root = target / scheme_name
        root.mkdir()
        scheme_dict[scheme_name] = str(root)
    return {
        "target": target,
        "scheme_dict": scheme_dict,
        "transaction_dir": tmp_path / "transaction",
    }


def make_destination(layout, **overrides):
    options = {
        "scheme_dict": layout["scheme_dict"],
        "interpreter": sys.executable,
        "script_kind": "posix",
        "transaction_dir": layout["transaction_dir"],
    }
    options.update(overrides)
    return TransactionalSchemeDictionaryDestination(**options)


def run_install(wheel_path, destination):
    with WheelFile.open(wheel_path) as source:
        install(source, destination, {})


def real_files(target):
    """All files actually installed (hidden transaction workdirs excluded)."""
    return {
        p.relative_to(target).as_posix(): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file() and not any(part.startswith(".installer-txn-") for part in p.parts)
    }


def real_file_paths(target):
    return sorted(real_files(target))


def has_no_transaction_state(target, transaction_dir):
    workdirs = [p for p in target.rglob("*") if p.name.startswith(".installer-txn-")]
    return not workdirs and not transaction_dir.exists()


def parse_installed_record(target):
    record_path = target / "purelib" / "fancy-1.0.0.dist-info" / "RECORD"
    return {
        row[0]: (row[1], row[2])
        for row in parse_record_file(record_path.read_text().splitlines())
    }


EXPECTED_PATHS = {
    "purelib/fancy/__init__.py",
    "purelib/fancy/module.py",
    "purelib/fancy-1.0.0.dist-info/METADATA",
    "purelib/fancy-1.0.0.dist-info/WHEEL",
    "purelib/fancy-1.0.0.dist-info/top_level.txt",
    "purelib/fancy-1.0.0.dist-info/entry_points.txt",
    "purelib/fancy-1.0.0.dist-info/RECORD",
    "scripts/fancy",
    "scripts/fancy-script.py",
    "data/fancy/data.py",
}


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
class TestSuccessfulInstall:
    def test_installs_across_scheme_roots(self, mock_wheel_path, layout):
        run_install(mock_wheel_path, make_destination(layout))

        assert set(real_file_paths(layout["target"])) == EXPECTED_PATHS

    def test_no_journal_or_workdirs_left_behind(self, mock_wheel_path, layout):
        run_install(mock_wheel_path, make_destination(layout))

        assert has_no_transaction_state(layout["target"], layout["transaction_dir"])

    def test_record_hashes_match_installed_bytes(self, mock_wheel_path, layout):
        run_install(mock_wheel_path, make_destination(layout))

        rows = parse_installed_record(layout["target"])
        target = layout["target"]
        record_path = target / "purelib/fancy-1.0.0.dist-info/RECORD"
        record_lines = record_path.read_text().splitlines()
        assert len(record_lines) == len(EXPECTED_PATHS)

        for row in parse_record_file(record_lines):
            relative, hash_value, size = row
            if not hash_value:
                # The RECORD itself has no hash.
                assert relative == "fancy-1.0.0.dist-info/RECORD"
                continue
            if relative.startswith("../"):
                _, scheme, relpath = relative.split("/", 2)
            else:
                scheme, relpath = "purelib", relative
            on_disk = target / scheme / relpath
            data = on_disk.read_bytes()
            algorithm, digest = hash_value.split("=", 1)
            actual = (
                base64.urlsafe_b64encode(hashlib.new(algorithm, data).digest())
                .decode()
                .rstrip("=")
            )
            assert actual == digest
            assert int(size) == len(data)

    def test_hash_covers_rewritten_shebang(self, mock_wheel_path, layout):
        run_install(mock_wheel_path, make_destination(layout))

        script = layout["target"] / "scripts/fancy-script.py"
        installed = script.read_bytes()
        assert installed.startswith(f"#!{sys.executable}\n".encode())

        rows = parse_installed_record(layout["target"])
        prefix, size = rows["../scripts/fancy-script.py"]
        assert int(size) == len(installed)
        algorithm, digest = prefix.split("=", 1)
        expected = hashlib.new(algorithm, installed).digest()
        import base64

        assert base64.urlsafe_b64encode(expected).decode().rstrip("=") == digest

    def test_generated_bytecode_installed_but_not_in_record(
        self, mock_wheel_path, layout
    ):
        destination = make_destination(layout, bytecode_optimization_levels=(0,))
        run_install(mock_wheel_path, destination)

        pyc = layout["target"] / (
            "purelib/fancy/__pycache__/__init__.cpython-"
            f"{sys.version_info.major}{sys.version_info.minor}.pyc"
        )
        assert pyc.is_file()
        rows = parse_installed_record(layout["target"])
        assert not any("__pycache__" in path for path in rows)

    def test_default_transaction_dir_under_temp(self, mock_wheel_path, layout, tmp_path):
        destination = TransactionalSchemeDictionaryDestination(
            scheme_dict=layout["scheme_dict"],
            interpreter=sys.executable,
            script_kind="posix",
        )
        run_install(mock_wheel_path, destination)
        assert Path(destination.transaction_dir).parent == Path(
            tempfile.gettempdir()
        )
        assert not Path(destination.transaction_dir).exists()


# ---------------------------------------------------------------------------
# Failure injection: staging write
# ---------------------------------------------------------------------------
class TestStagingFailure:
    def test_failed_write_rolls_back(self, mock_wheel_path, layout):
        destination = make_destination(layout)
        original_write_to_fs = type(destination).write_to_fs
        attempts = {"count": 0}

        def failing_write(self, scheme, path, stream, is_executable):
            attempts["count"] += 1
            if attempts["count"] == 4:
                raise OSError("simulated disk full")
            return original_write_to_fs(self, scheme, path, stream, is_executable)

        type(destination).write_to_fs = failing_write
        try:
            with pytest.raises(OSError, match="disk full"):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination).write_to_fs = original_write_to_fs

        assert real_file_paths(layout["target"]) == []
        assert has_no_transaction_state(
            layout["target"], layout["transaction_dir"]
        )

    def test_keyboard_interrupt_leaves_journal_for_recovery(
        self, mock_wheel_path, layout
    ):
        destination = make_destination(layout)
        original_write_to_fs = type(destination).write_to_fs
        attempts = {"count": 0}

        def interrupted_write(self, scheme, path, stream, is_executable):
            attempts["count"] += 1
            if attempts["count"] == 4:
                raise KeyboardInterrupt
            return original_write_to_fs(self, scheme, path, stream, is_executable)

        type(destination).write_to_fs = interrupted_write
        try:
            with pytest.raises(KeyboardInterrupt):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination).write_to_fs = original_write_to_fs

        # Nothing was committed yet; a new process rolls the staging away.
        assert real_file_paths(layout["target"]) == []
        assert layout["transaction_dir"].exists()
        TransactionalSchemeDictionaryDestination.recover(
            layout["transaction_dir"], "rollback"
        )
        assert has_no_transaction_state(
            layout["target"], layout["transaction_dir"]
        )
        # The filesystem is clean enough to retry the whole installation.
        retry = make_destination(layout)
        run_install(mock_wheel_path, retry)
        assert set(real_file_paths(layout["target"])) == EXPECTED_PATHS


# ---------------------------------------------------------------------------
# Failure injection: target replacement during commit
# ---------------------------------------------------------------------------
def patch_replace_at(destination, failure_index, error_factory=OSError):
    """Make the N-th call to _replace_file raise."""
    original = type(destination)._replace_file
    counter = {"count": 0}

    def failing_replace(self, source, target_path):
        counter["count"] += 1
        if counter["count"] == failure_index:
            raise error_factory("simulated replacement failure")
        return original(self, source, target_path)

    type(destination)._replace_file = failing_replace
    return original


def seed_previous_install(target):
    """Place an older installation, including a file the wheel doesn't ship."""
    package = target / "purelib/fancy"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("OLD INIT\n")
    (package / "removed_module.py").write_text("# only in the old version\n")
    old_script_dir = target / "scripts"
    (old_script_dir / "fancy").write_text("#!/old\nold launcher\n")
    return {
        p.relative_to(target).as_posix(): p.read_bytes()
        for p in target.rglob("*")
        if p.is_file()
    }


class TestReplacementFailure:
    def test_exception_mid_commit_auto_rolls_back(
        self, mock_wheel_path, layout
    ):
        previous = seed_previous_install(layout["target"])
        destination = make_destination(layout, overwrite_existing=True)
        original = patch_replace_at(destination, failure_index=5)
        try:
            with pytest.raises(OSError, match="replacement failure"):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        assert real_files(layout["target"]) == previous
        assert (
            layout["target"] / "purelib/fancy/removed_module.py"
        ).read_text() == "# only in the old version\n"
        assert has_no_transaction_state(
            layout["target"], layout["transaction_dir"]
        )

    def test_kill_mid_commit_resumes_in_new_process(
        self, mock_wheel_path, layout
    ):
        seed_previous_install(layout["target"])
        destination = make_destination(layout, overwrite_existing=True)
        original = patch_replace_at(
            destination, failure_index=5, error_factory=SystemExit
        )
        try:
            with pytest.raises(SystemExit):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        assert layout["transaction_dir"].exists()

        TransactionalSchemeDictionaryDestination.recover(
            layout["transaction_dir"], "resume"
        )
        assert EXPECTED_PATHS <= set(real_file_paths(layout["target"]))
        # Files shipped by the new wheel are replaced; stale files not part of
        # the new RECORD are left alone (as with a regular, non-transactional
        # install).
        assert (
            layout["target"] / "purelib/fancy/removed_module.py"
        ).is_file()
        assert has_no_transaction_state(
            layout["target"], layout["transaction_dir"]
        )

    def test_kill_mid_commit_rolls_back_in_new_process(
        self, mock_wheel_path, layout
    ):
        previous = seed_previous_install(layout["target"])
        destination = make_destination(layout, overwrite_existing=True)
        original = patch_replace_at(
            destination, failure_index=5, error_factory=SystemExit
        )
        try:
            with pytest.raises(SystemExit):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        TransactionalSchemeDictionaryDestination.recover(
            layout["transaction_dir"], "rollback"
        )
        assert real_files(layout["target"]) == previous
        assert has_no_transaction_state(
            layout["target"], layout["transaction_dir"]
        )

    def test_resume_is_idempotent(self, mock_wheel_path, layout):
        destination = make_destination(layout)
        original = patch_replace_at(
            destination, failure_index=7, error_factory=KeyboardInterrupt
        )
        try:
            with pytest.raises(KeyboardInterrupt):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        TransactionalSchemeDictionaryDestination.recover(
            layout["transaction_dir"], "resume"
        )
        assert set(real_file_paths(layout["target"])) == EXPECTED_PATHS
        # A second recovery finds nothing to do and reports the missing journal
        # instead of touching the completed installation.
        with pytest.raises(TransactionError):
            TransactionalSchemeDictionaryDestination.recover(
                layout["transaction_dir"], "resume"
            )
        assert set(real_file_paths(layout["target"])) == EXPECTED_PATHS

    def test_rollback_is_idempotent(self, mock_wheel_path, layout):
        previous = seed_previous_install(layout["target"])
        destination = make_destination(layout, overwrite_existing=True)
        original = patch_replace_at(
            destination, failure_index=7, error_factory=KeyboardInterrupt
        )
        try:
            with pytest.raises(KeyboardInterrupt):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        TransactionalSchemeDictionaryDestination.recover(
            layout["transaction_dir"], "rollback"
        )
        # Journal is gone after the first rollback; nothing more to recover.
        with pytest.raises(TransactionError):
            TransactionalSchemeDictionaryDestination.recover(
                layout["transaction_dir"], "rollback"
            )
        assert real_files(layout["target"]) == previous


# ---------------------------------------------------------------------------
# Failure injection: final RECORD materialisation
# ---------------------------------------------------------------------------
class TestRecordFailure:
    def test_record_write_failure_rolls_back(self, mock_wheel_path, layout):
        destination = make_destination(layout)
        original = type(destination)._write_staged_bytes

        def failing_staged_write(self, scheme, path, contents):
            if path.endswith("RECORD"):
                raise OSError("no space left for RECORD")
            return original(self, scheme, path, contents)

        type(destination)._write_staged_bytes = failing_staged_write
        try:
            with pytest.raises(OSError, match="RECORD"):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._write_staged_bytes = original

        assert real_file_paths(layout["target"]) == []
        assert has_no_transaction_state(
            layout["target"], layout["transaction_dir"]
        )

    def test_record_commit_failure_after_kill_rolls_back(
        self, mock_wheel_path, layout
    ):
        # RECORD is the last plan item, so killing on its replacement leaves
        # every regular file already committed but the RECORD pending.
        destination = make_destination(layout)
        original = type(destination)._replace_file

        def only_record_replacement(self, source, target_path):
            if target_path.endswith("RECORD"):
                raise SystemExit
            return original(self, source, target_path)

        type(destination)._replace_file = only_record_replacement
        try:
            with pytest.raises(SystemExit):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        TransactionalSchemeDictionaryDestination.recover(
            layout["transaction_dir"], "rollback"
        )
        assert real_file_paths(layout["target"]) == []
        assert has_no_transaction_state(
            layout["target"], layout["transaction_dir"]
        )

    def test_record_commit_failure_after_kill_resumes(
        self, mock_wheel_path, layout
    ):
        destination = make_destination(layout)
        original = type(destination)._replace_file

        def only_record_replacement(self, source, target_path):
            if target_path.endswith("RECORD"):
                raise SystemExit
            return original(self, source, target_path)

        type(destination)._replace_file = only_record_replacement
        try:
            with pytest.raises(SystemExit):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        TransactionalSchemeDictionaryDestination.recover(
            layout["transaction_dir"], "resume"
        )
        assert set(real_file_paths(layout["target"])) == EXPECTED_PATHS
        rows = parse_installed_record(layout["target"])
        assert "fancy-1.0.0.dist-info/RECORD" in rows


# ---------------------------------------------------------------------------
# Journal/API semantics and directory ownership
# ---------------------------------------------------------------------------
class TestJournalSemantics:
    def test_existing_journal_blocks_fresh_destination(
        self, mock_wheel_path, layout
    ):
        destination = make_destination(layout)
        original = patch_replace_at(
            destination, failure_index=4, error_factory=KeyboardInterrupt
        )
        try:
            with pytest.raises(KeyboardInterrupt):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        with pytest.raises(TransactionError, match="recover"):
            make_destination(layout)

    def test_recover_unknown_directory_errors(self, layout):
        with pytest.raises(TransactionError):
            TransactionalSchemeDictionaryDestination.recover(
                layout["transaction_dir"], "resume"
            )

    def test_resume_during_staging_requires_rollback(
        self, mock_wheel_path, layout
    ):
        destination = make_destination(layout)
        original_write_to_fs = type(destination).write_to_fs
        attempts = {"count": 0}

        def interrupted_write(self, scheme, path, stream, is_executable):
            attempts["count"] += 1
            if attempts["count"] == 3:
                raise KeyboardInterrupt
            return original_write_to_fs(self, scheme, path, stream, is_executable)

        type(destination).write_to_fs = interrupted_write
        try:
            with pytest.raises(KeyboardInterrupt):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination).write_to_fs = original_write_to_fs

        with pytest.raises(TransactionError, match="rollback"):
            TransactionalSchemeDictionaryDestination.recover(
                layout["transaction_dir"], "resume"
            )

    def test_pre_existing_directories_are_not_removed(self, mock_wheel_path, tmp_path):
        # When scheme roots already exist (the common case) rollback must not
        # delete them, even when they end up empty.
        target = tmp_path / "target"
        target.mkdir()
        scheme_dict = {
            name: str(target / name) for name in SCHEME_NAMES
        }
        for root in scheme_dict.values():
            Path(root).mkdir()
        layout = {
            "target": target,
            "scheme_dict": scheme_dict,
            "transaction_dir": tmp_path / "transaction",
        }
        destination = make_destination(layout)
        original = patch_replace_at(
            destination, failure_index=3, error_factory=OSError
        )
        try:
            with pytest.raises(OSError):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        for root in scheme_dict.values():
            assert Path(root).is_dir()

    def test_created_nested_directories_removed_on_rollback(
        self, mock_wheel_path, tmp_path
    ):
        # Remove the per-scheme roots entirely; the destination creates them
        # (plus nested package dirs), and rollback must remove the empty ones
        # it created while leaving unrelated content alone.
        target = tmp_path / "target"
        target.mkdir()
        scheme_dict = {name: str(target / name) for name in SCHEME_NAMES}
        layout = {
            "target": target,
            "scheme_dict": scheme_dict,
            "transaction_dir": tmp_path / "transaction",
        }
        destination = make_destination(layout)
        original = patch_replace_at(
            destination, failure_index=3, error_factory=OSError
        )
        try:
            with pytest.raises(OSError):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        # All created directories that are empty disappear; a real file would
        # keep its parents.
        remaining_files = real_file_paths(target)
        assert remaining_files == []


class TestDestdir:
    def test_installs_under_destdir_and_cleans_state(
        self, mock_wheel_path, layout, tmp_path
    ):
        staging_prefix = tmp_path / "destdir"
        destination = TransactionalSchemeDictionaryDestination(
            scheme_dict=layout["scheme_dict"],
            interpreter=sys.executable,
            script_kind="posix",
            transaction_dir=layout["transaction_dir"],
            destdir=str(staging_prefix),
        )
        run_install(mock_wheel_path, destination)

        pure_root = Path(layout["scheme_dict"]["purelib"]).relative_to("/")
        installed = staging_prefix / pure_root / "fancy" / "__init__.py"
        assert installed.is_file()
        leftover = [
            p
            for p in staging_prefix.rglob("*")
            if p.name.startswith(".installer-txn-")
        ]
        assert not leftover
        assert not layout["transaction_dir"].exists()

    def test_rollback_under_destdir(self, mock_wheel_path, layout, tmp_path):
        staging_prefix = tmp_path / "destdir"
        destination = TransactionalSchemeDictionaryDestination(
            scheme_dict=layout["scheme_dict"],
            interpreter=sys.executable,
            script_kind="posix",
            transaction_dir=layout["transaction_dir"],
            destdir=str(staging_prefix),
        )
        original = type(destination)._replace_file
        counter = {"count": 0}

        def failing_replace(self, source, target_path):
            counter["count"] += 1
            if counter["count"] == 4:
                raise OSError("boom")
            return original(self, source, target_path)

        type(destination)._replace_file = failing_replace
        try:
            with pytest.raises(OSError, match="boom"):
                run_install(mock_wheel_path, destination)
        finally:
            type(destination)._replace_file = original

        installed_files = [
            p
            for p in staging_prefix.rglob("*")
            if p.is_file() and not any(
                part.startswith(".installer-txn-") for part in p.parts
            )
        ]
        assert installed_files == []
        assert not layout["transaction_dir"].exists()
