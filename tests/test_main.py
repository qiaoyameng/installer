import os

import pytest

from installer.__main__ import _get_scheme_dict as get_scheme_dict
from installer.__main__ import _main as main


def test_get_scheme_dict():
    d = get_scheme_dict(distribution_name="foo")
    assert set(d.keys()) >= {"purelib", "platlib", "headers", "scripts", "data"}


def test_get_scheme_dict_prefix():
    d = get_scheme_dict(distribution_name="foo", prefix="/foo")
    for key in ("purelib", "platlib", "headers", "scripts", "data"):
        assert d[key].startswith(f"{os.sep}foo"), (
            f"{key} does not start with /foo: {d[key]}"
        )


def test_main(fancy_wheel, tmp_path):
    destdir = tmp_path / "dest"

    main([str(fancy_wheel), "-d", str(destdir)], "python -m installer")

    installed_py_files = destdir.rglob("*.py")

    assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

    installed_pyc_files = destdir.rglob("*.pyc")
    assert {f.name.split(".")[0] for f in installed_pyc_files} == {
        "__init__",
        "__main__",
    }


def test_main_multiple_wheels(fancy_wheel, another_fancy_wheel, tmp_path):
    destdir = tmp_path / "dest"

    main(
        [str(fancy_wheel), str(another_fancy_wheel), "-d", str(destdir)],
        "python -m installer",
    )

    for wheel_name in ("fancy", "another_fancy"):
        installed_py_files = destdir.rglob(f"**/{wheel_name}/**/*.py")
        assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

        installed_pyc_files = destdir.rglob(f"**/{wheel_name}/**/*.pyc")
        assert {f.name.split(".")[0] for f in installed_pyc_files} == {
            "__init__",
            "__main__",
        }


def test_main_prefix(fancy_wheel, tmp_path):
    destdir = tmp_path / "dest"

    main([str(fancy_wheel), "-d", str(destdir), "-p", "/foo"], "python -m installer")

    installed_py_files = list(destdir.rglob("*.py"))

    for f in installed_py_files:
        assert str(f.parent).startswith(str(destdir / "foo")), (
            f"path does not respect destdir+prefix: {f}"
        )
    assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

    installed_pyc_files = destdir.rglob("*.pyc")
    assert {f.name.split(".")[0] for f in installed_pyc_files} == {
        "__init__",
        "__main__",
    }


def test_main_no_pyc(fancy_wheel, tmp_path):
    destdir = tmp_path / "dest"

    main(
        [str(fancy_wheel), "-d", str(destdir), "--no-compile-bytecode"],
        "python -m installer",
    )

    installed_py_files = destdir.rglob("*.py")

    assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

    installed_pyc_files = destdir.rglob("*.pyc")
    assert set(installed_pyc_files) == set()


def test_main_reproducible(fancy_wheel, tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    destdir = tmp_path / "dest"

    main(
        [str(fancy_wheel), "-d", str(destdir), "--reproducible"],
        "python -m installer",
    )

    pyc_files = list(destdir.rglob("*.pyc"))
    assert pyc_files
    for pyc in pyc_files:
        flags = int.from_bytes(pyc.read_bytes()[4:8], "little")
        assert flags == 3  # hash-based invalidation
        assert int(pyc.stat().st_mtime) == 1700000000


def test_main_reproducible_without_epoch_fails(fancy_wheel, tmp_path, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    destdir = tmp_path / "dest"

    with pytest.raises(Exception, match="SOURCE_DATE_EPOCH"):
        main(
            [str(fancy_wheel), "-d", str(destdir), "--reproducible"],
            "python -m installer",
        )


@pytest.mark.parametrize(
    "validation_part",
    ["all", "entries", "none"],
)
def test_main_validate_record_all_pass(fancy_wheel, tmp_path, validation_part):
    destdir = tmp_path / "dest"

    main(
        [str(fancy_wheel), "-d", str(destdir), "--validate-record", validation_part],
        "python -m installer",
    )

    installed_py_files = destdir.rglob("*.py")

    assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

    installed_pyc_files = destdir.rglob("*.pyc")
    assert {f.name.split(".")[0] for f in installed_pyc_files} == {
        "__init__",
        "__main__",
    }
