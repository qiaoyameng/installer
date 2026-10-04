"""Tests for the reproducible installation mode."""

import hashlib
import marshal
import stat
import struct
import sys
from pathlib import Path

import pytest

from installer import install
from installer.destinations import SchemeDictionaryDestination
from installer.exceptions import ReproducibleInstallError
from installer.records import RecordEntry
from installer.sources import WheelFile
from installer.utils import SCHEME_NAMES


LOGICAL_PREFIX = "/opt/target"
EPOCH = 1_700_000_000


def _scheme_dict() -> dict[str, str]:
    return {
        "purelib": f"{LOGICAL_PREFIX}/lib/python/site-packages",
        "platlib": f"{LOGICAL_PREFIX}/lib/python/site-packages",
        "headers": f"{LOGICAL_PREFIX}/include",
        "scripts": f"{LOGICAL_PREFIX}/bin",
        "data": LOGICAL_PREFIX,
    }


def _destination(staging: Path) -> SchemeDictionaryDestination:
    return SchemeDictionaryDestination(
        scheme_dict=_scheme_dict(),
        interpreter=sys.executable,
        script_kind="posix",
        bytecode_optimization_levels=(0, 1),
        destdir=str(staging),
        reproducible=True,
        source_date_epoch=EPOCH,
    )


def _install_wheel(wheel: Path, staging: Path) -> None:
    with WheelFile.open(wheel) as source:
        install(source, _destination(staging), {})


def _snapshot(root: Path) -> dict[str, tuple[str, int, int, str | None]]:
    """Relative path -> (kind, permission bits, mtime in ns, content hash)."""
    snapshot = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        path_stat = path.stat()
        mode = stat.S_IMODE(path_stat.st_mode)
        mtime_ns = path_stat.st_mtime_ns
        if path.is_dir():
            snapshot[str(rel)] = ("d", mode, mtime_ns, None)
        else:
            content = path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            snapshot[str(rel)] = ("f", mode, mtime_ns, digest)
    return snapshot


def _iter_code_objects(code):
    yield code
    for const in code.co_consts:
        if hasattr(const, "co_filename"):
            yield from _iter_code_objects(const)


def test_same_wheel_two_staging_roots_identical(
    fancy_wheel, tmp_path: Path
) -> None:
    stage_one = tmp_path / "staging-one-with-a-random-suffix"
    stage_two = tmp_path / "staging-two-with-a-different-suffix"

    _install_wheel(fancy_wheel, stage_one)
    _install_wheel(fancy_wheel, stage_two)

    assert _snapshot(stage_one) == _snapshot(stage_two)


def test_relative_files_and_fixed_metadata(fancy_wheel, tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    _install_wheel(fancy_wheel, stage)

    snapshot = _snapshot(stage)
    # The normalized tree is keyed on relative paths, so neither staging
    # prefix nor absolute location leaks into the metadata.
    assert all(not path.startswith("/") for path in snapshot)

    for rel, (kind, mode, mtime_ns, _digest) in snapshot.items():
        assert mtime_ns == EPOCH * 1_000_000_000, rel
        if kind == "d":
            assert mode == 0o755, rel
        elif rel.startswith("opt/target/bin/"):
            assert mode == 0o755, rel
        else:
            assert mode == 0o644, rel


def test_scripts_point_to_configured_interpreter(
    fancy_wheel, tmp_path: Path
) -> None:
    stage = tmp_path / "stage"
    _install_wheel(fancy_wheel, stage)

    for script_name in ("fancy", "fancy-gui"):
        script = stage / "opt" / "target" / "bin" / script_name
        assert script.is_file()
        content = script.read_bytes()
        assert sys.executable.encode() in content
        assert str(stage).encode() not in content


def test_scripts_use_direct_shebang_for_short_interpreter(
    fancy_wheel, tmp_path: Path
) -> None:
    # A short interpreter path fits the shebang length limit, so the
    # generated launcher starts with a plain ``#!<interpreter>`` line.
    interpreter = "/usr/bin/python3"
    stage = tmp_path / "stage"
    destination = SchemeDictionaryDestination(
        scheme_dict=_scheme_dict(),
        interpreter=interpreter,
        script_kind="posix",
        bytecode_optimization_levels=(),
        destdir=str(stage),
        reproducible=True,
        source_date_epoch=EPOCH,
    )
    with WheelFile.open(fancy_wheel) as source:
        install(source, destination, {})

    script = stage / "opt" / "target" / "bin" / "fancy"
    assert script.read_bytes().startswith(f"#!{interpreter}\n".encode())


def test_record_is_sorted_and_relative(fancy_wheel, tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    _install_wheel(fancy_wheel, stage)

    record = next(stage.rglob("RECORD"))
    lines = record.read_text().splitlines()
    paths = [line.split(",", 1)[0] for line in lines]
    # Root-scheme entries carry no cross-scheme relative prefix and are
    # written in sorted order; overall determinism is also covered by the
    # two-staging-root snapshot comparison above.
    same_scheme_paths = [path for path in paths if "../" not in path]
    assert same_scheme_paths == sorted(same_scheme_paths)
    assert all(not path.startswith("/") for path in paths)
    assert all("staging" not in path for path in paths)

    other_stage = tmp_path / "stage-two"
    _install_wheel(fancy_wheel, other_stage)
    other_record = next(other_stage.rglob("RECORD")).read_bytes()
    assert record.read_bytes() == other_record


def test_pyc_is_hash_based_with_logical_filename(
    fancy_wheel, tmp_path: Path
) -> None:
    stage = tmp_path / "stage"
    _install_wheel(fancy_wheel, stage)

    pyc_files = list(stage.rglob("*.pyc"))
    assert pyc_files

    for pyc_path in pyc_files:
        data = pyc_path.read_bytes()

        # PEP 552: the 16-byte header is magic, flags, source hash, 0.
        flags = struct.unpack("<I", data[4:8])[0]
        assert flags == 3  # PycInvalidationMode.CHECKED_HASH
        # Bytes 8:16 hold the zero-padded source hash (no source mtime/size).
        assert data[8:16].strip(b"\0")  # the source hash is present

        code = marshal.loads(data[16:])
        for nested in _iter_code_objects(code):
            assert nested.co_filename.startswith(LOGICAL_PREFIX)
            assert "staging" not in nested.co_filename


def test_default_installation_is_not_reproducible(
    fancy_wheel, tmp_path: Path
) -> None:
    # Without reproducible=True, SOURCE_DATE_EPOCH is not consulted and the
    # default timestamp-based bytecode is generated.
    scheme_dict = {}
    for scheme_name in SCHEME_NAMES:
        directory = tmp_path / scheme_name
        directory.mkdir(exist_ok=True)
        scheme_dict[scheme_name] = str(directory)

    destination = SchemeDictionaryDestination(
        scheme_dict=scheme_dict,
        interpreter=sys.executable,
        script_kind="posix",
        bytecode_optimization_levels=(0,),
    )
    with WheelFile.open(fancy_wheel) as source:
        install(source, destination, {})

    pyc_path = next(tmp_path.rglob("*.pyc"))
    flags = struct.unpack("<I", pyc_path.read_bytes()[4:8])[0]
    assert flags == 0  # timestamp-based invalidation


def test_missing_source_date_epoch_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    with pytest.raises(ReproducibleInstallError, match="SOURCE_DATE_EPOCH"):
        SchemeDictionaryDestination(
            scheme_dict={"purelib": "/x"},
            interpreter=sys.executable,
            script_kind="posix",
            reproducible=True,
        )


@pytest.mark.parametrize(
    "value",
    ["", " 123", "123 ", "-5", "+5", "1.5", "abc", "0x10"],
)
def test_invalid_source_date_epoch_raises(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", value)
    with pytest.raises(ReproducibleInstallError, match="SOURCE_DATE_EPOCH"):
        SchemeDictionaryDestination(
            scheme_dict={"purelib": "/x"},
            interpreter=sys.executable,
            script_kind="posix",
            reproducible=True,
        )


@pytest.mark.parametrize("epoch", ["0", "1700000000"])
def test_valid_source_date_epoch_accepted(
    monkeypatch: pytest.MonkeyPatch, epoch: str
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", epoch)
    destination = SchemeDictionaryDestination(
        scheme_dict={"purelib": "/x"},
        interpreter=sys.executable,
        script_kind="posix",
        reproducible=True,
    )
    assert destination.source_date_epoch == int(epoch)


@pytest.mark.parametrize("epoch", [-1, 1.5, "1700000000", True])
def test_bad_explicit_source_date_epoch_raises(epoch: object) -> None:
    with pytest.raises(ReproducibleInstallError, match="source_date_epoch"):
        SchemeDictionaryDestination(
            scheme_dict={"purelib": "/x"},
            interpreter=sys.executable,
            script_kind="posix",
            reproducible=True,
            source_date_epoch=epoch,
        )


def test_insufficient_interpreter_raises_instead_of_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_interpreter = tmp_path / "old-python"
    fake_interpreter.write_text(
        "#!/bin/sh\necho '3.6.15'\necho '330d0d0a'\n"
    )
    fake_interpreter.chmod(0o755)

    destination = SchemeDictionaryDestination(
        scheme_dict={name: str(tmp_path / name) for name in SCHEME_NAMES},
        interpreter=str(fake_interpreter),
        script_kind="posix",
        bytecode_optimization_levels=(0,),
        reproducible=True,
        source_date_epoch=EPOCH,
    )
    with pytest.raises(ReproducibleInstallError, match="PEP 552"):
        destination._compile_reproducible_bytecode(
            "purelib", RecordEntry("pkg/module.py", None, None)
        )


def test_missing_interpreter_binary_raises(tmp_path: Path) -> None:
    destination = SchemeDictionaryDestination(
        scheme_dict={name: str(tmp_path / name) for name in SCHEME_NAMES},
        interpreter=str(tmp_path / "does-not-exist"),
        script_kind="posix",
        bytecode_optimization_levels=(0,),
        reproducible=True,
        source_date_epoch=EPOCH,
    )
    with pytest.raises(ReproducibleInstallError, match="could not run"):
        destination._compile_reproducible_bytecode(
            "purelib", RecordEntry("pkg/module.py", None, None)
        )


def test_no_bytecode_does_not_require_interpreter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    # A reproducible install without bytecode only needs a fixed epoch.
    SchemeDictionaryDestination(
        scheme_dict={"purelib": "/x"},
        interpreter="/no/such/interpreter",
        script_kind="posix",
        bytecode_optimization_levels=(),
        reproducible=True,
        source_date_epoch=EPOCH,
    )
