"""Tests for reproducible wheel installation."""

import marshal
import os
import stat
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from installer import install
from installer.destinations import SchemeDictionaryDestination
from installer.exceptions import (
    InvalidReproducibleConfiguration,
    InvalidSourceDateEpoch,
)
from installer.records import parse_record_file
from installer.sources import WheelFile
from installer.utils import SCHEME_NAMES

SOURCE_DATE_EPOCH = "1700000000"
EPOCH_NS = int(SOURCE_DATE_EPOCH) * 1_000_000_000
LOGICAL_PREFIX = "/opt/reproducible-env"


def _scheme_dict(logical_prefix: str) -> dict[str, str]:
    purelib = f"{logical_prefix}/lib/python3.12/site-packages"
    return {
        "purelib": purelib,
        "platlib": purelib,
        "headers": f"{logical_prefix}/include/python3.12/reproducible",
        "scripts": f"{logical_prefix}/bin",
        "data": logical_prefix,
    }


def _destination(destdir: Path, interpreter: str = "/usr/bin/python3"):
    return SchemeDictionaryDestination(
        scheme_dict=_scheme_dict(LOGICAL_PREFIX),
        interpreter=interpreter,
        script_kind="posix",
        bytecode_optimization_levels=[0, 1],
        destdir=str(destdir),
        reproducible=True,
    )


def _install_wheel(wheel: Path, destdir: Path, interpreter: str = "/usr/bin/python3"):
    with WheelFile.open(str(wheel)) as source:
        install(source, _destination(destdir, interpreter), {})


def _snapshot(root: Path) -> dict[str, tuple[bytes, int, int]]:
    """Map relative path -> (contents, mode bits, mtime ns) for all files."""
    result = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        st = path.stat()
        result[str(path.relative_to(root))] = (
            path.read_bytes(),
            stat.S_IMODE(st.st_mode),
            st.st_mtime_ns,
        )
    return result


@pytest.fixture(autouse=True)
def source_date_epoch(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)


def test_two_staging_roots_produce_identical_output(fancy_wheel, tmp_path):
    stage_a = tmp_path / "random-stage-aaaa"
    stage_b = tmp_path / "random-stage-bbbb"

    _install_wheel(fancy_wheel, stage_a)
    _install_wheel(fancy_wheel, stage_b)

    snapshot_a = _snapshot(stage_a)
    snapshot_b = _snapshot(stage_b)

    # Same set of relative files, regardless of the staging root.
    assert set(snapshot_a) == set(snapshot_b)

    mismatches = [
        relative
        for relative in snapshot_a
        if snapshot_a[relative] != snapshot_b[relative]
    ]
    assert mismatches == []


def test_files_have_fixed_mode_and_mtime(fancy_wheel, tmp_path):
    stage = tmp_path / "stage"
    _install_wheel(fancy_wheel, stage)

    for relative, (_content, mode, mtime_ns) in _snapshot(stage).items():
        assert mtime_ns == EPOCH_NS, relative
        if "/bin/" in f"/{relative}":
            assert mode == 0o755, relative
        else:
            assert mode == 0o644, relative

    for directory in stage.rglob("*"):
        if not directory.is_dir():
            continue
        st = directory.stat()
        assert stat.S_IMODE(st.st_mode) == 0o755, directory
        assert st.st_mtime_ns == EPOCH_NS, directory


def test_pyc_uses_hash_invalidation_and_logical_filename(fancy_wheel, tmp_path):
    stage = tmp_path / "stage"
    _install_wheel(fancy_wheel, stage)

    pyc_files = list(stage.rglob("*.pyc"))
    assert pyc_files

    for pyc_file in pyc_files:
        data = pyc_file.read_bytes()

        # PEP 552: field 1 holds the invalidation flags. Bit 0 set means the
        # pyc is hash-based; bits 1+ indicate checked hash.
        flags = struct.unpack("<I", data[4:8])[0]
        assert flags & 0b1, pyc_file

        code = marshal.loads(data[16:])
        assert code.co_filename.startswith(LOGICAL_PREFIX), (
            pyc_file,
            code.co_filename,
        )
        assert "stage" not in code.co_filename


def test_pyc_contents_independent_of_staging_path(fancy_wheel, tmp_path):
    stage_a = tmp_path / "stage-one"
    stage_b = tmp_path / "stage-two"
    _install_wheel(fancy_wheel, stage_a)
    _install_wheel(fancy_wheel, stage_b)

    pycs_a = {p.name: p for p in stage_a.rglob("*.pyc")}
    pycs_b = {p.name: p for p in stage_b.rglob("*.pyc")}
    assert set(pycs_a) == set(pycs_b)
    for name in pycs_a:
        assert pycs_a[name].read_bytes() == pycs_b[name].read_bytes()


def test_generated_scripts_point_at_specified_interpreter(fancy_wheel, tmp_path):
    stage = tmp_path / "stage"
    _install_wheel(fancy_wheel, stage, interpreter="/usr/bin/python3")

    scripts_dir = stage / "opt/reproducible-env/bin"
    scripts = [p for p in scripts_dir.iterdir() if p.is_file()]
    assert {p.name for p in scripts} == {"fancy", "fancy-gui"}

    for script in scripts:
        first_line = script.read_bytes().splitlines()[0]
        assert first_line == b"#!/usr/bin/python3"


def test_record_is_sorted_and_identical_across_roots(fancy_wheel, tmp_path):
    stage_a = tmp_path / "stage-aaaa"
    stage_b = tmp_path / "stage-bbbb"
    _install_wheel(fancy_wheel, stage_a)
    _install_wheel(fancy_wheel, stage_b)

    def record_rows(stage: Path):
        record_path = next(stage.rglob("RECORD"))
        text = record_path.read_text(encoding="utf-8")
        return list(parse_record_file(text.splitlines()))

    rows_a = record_rows(stage_a)
    rows_b = record_rows(stage_b)

    assert rows_a == rows_b
    # The RECORD ordering is deterministic: records are sorted by their
    # scheme-relative path, with cross-scheme entries carrying "../"
    # prefixes. Check the root-scheme entries (no prefix) are sorted.
    root_scheme_paths = [
        row[0] for row in rows_a if not row[0].startswith("../")
    ]
    assert root_scheme_paths == sorted(root_scheme_paths)
    # RECORD itself is always an unhashed entry.
    record_entry = next(row for row in rows_a if row[0].endswith("/RECORD"))
    assert record_entry[1:] == ("", "")
    # No staging path leaks into RECORD.
    assert all("stage" not in row[0] for row in rows_a)


@pytest.mark.parametrize("value", ["", "   ", "not-a-number", "-1", "1.5", "+5"])
def test_invalid_source_date_epoch_rejected(monkeypatch, value):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", value)

    with pytest.raises(InvalidSourceDateEpoch):
        SchemeDictionaryDestination(
            {name: "/x" for name in SCHEME_NAMES},
            "/usr/bin/python3",
            "posix",
            reproducible=True,
        )


def test_missing_source_date_epoch_rejected(monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    with pytest.raises(InvalidSourceDateEpoch):
        SchemeDictionaryDestination(
            {name: "/x" for name in SCHEME_NAMES},
            "/usr/bin/python3",
            "posix",
            reproducible=True,
        )


def test_unsupported_interpreter_capability_rejected(monkeypatch):
    monkeypatch.setattr(
        "installer.destinations._supports_hash_based_pyc", lambda: False
    )

    with pytest.raises(InvalidReproducibleConfiguration):
        SchemeDictionaryDestination(
            {name: "/x" for name in SCHEME_NAMES},
            "/usr/bin/python3",
            "posix",
            bytecode_optimization_levels=[0],
            reproducible=True,
        )


def test_unsupported_interpreter_ok_without_bytecode(monkeypatch):
    monkeypatch.setattr(
        "installer.destinations._supports_hash_based_pyc", lambda: False
    )

    destination = SchemeDictionaryDestination(
        {name: "/x" for name in SCHEME_NAMES},
        "/usr/bin/python3",
        "posix",
        bytecode_optimization_levels=(),
        reproducible=True,
    )
    assert destination.source_date_epoch == int(SOURCE_DATE_EPOCH)


def test_default_installation_does_not_require_source_date_epoch(
    monkeypatch, fancy_wheel, tmp_path
):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    stage = tmp_path / "stage"
    destination = SchemeDictionaryDestination(
        scheme_dict=_scheme_dict("/opt/default-env"),
        interpreter=sys.executable,
        script_kind="posix",
        bytecode_optimization_levels=[0, 1],
        destdir=str(stage),
    )
    with WheelFile.open(str(fancy_wheel)) as source:
        install(source, destination, {})

    # Default mode still produces bytecode.
    assert list(stage.rglob("*.pyc"))


def test_reproducible_install_independent_of_umask(fancy_wheel, tmp_path):
    def run(stage: Path, mask: int) -> None:
        code = (
            "import os\n"
            f"os.umask({mask})\n"
            "from installer.sources import WheelFile\n"
            "from installer.destinations import SchemeDictionaryDestination\n"
            "from installer import install\n"
            f"wheel = {str(fancy_wheel)!r}\n"
            f"destdir = {str(stage)!r}\n"
            "purelib = '/opt/reproducible-env/lib/python3.12/site-packages'\n"
            "scheme_dict = {'purelib': purelib, 'platlib': purelib, "
            "'headers': '/opt/reproducible-env/include/python3.12/x', "
            "'scripts': '/opt/reproducible-env/bin', "
            "'data': '/opt/reproducible-env'}\n"
            "destination = SchemeDictionaryDestination(\n"
            "    scheme_dict, interpreter='/usr/bin/python3',\n"
            "    script_kind='posix', bytecode_optimization_levels=[0, 1],\n"
            "    destdir=destdir, reproducible=True)\n"
            "with WheelFile.open(wheel) as source:\n"
            "    install(source, destination, {})\n"
        )
        env = {**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}
        subprocess.run([sys.executable, "-c", code], check=True, env=env)

    stage_a = tmp_path / "umask-022"
    stage_b = tmp_path / "umask-077"
    run(stage_a, 0o022)
    run(stage_b, 0o077)

    assert _snapshot(stage_a) == _snapshot(stage_b)
