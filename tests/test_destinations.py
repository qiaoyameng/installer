import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import shutil
import zipfile

import pytest

from installer import install
from installer.destinations import (
    SchemeDictionaryDestination,
    TransactionalSchemeDictionaryDestination,
    WheelDestination,
)
from installer.records import RecordEntry
from installer.scripts import Script
from installer.sources import WheelFile
from installer.utils import SCHEME_NAMES


class TestWheelDestination:
    def test_takes_no_arguments(self):
        WheelDestination()

    def test_raises_not_implemented_error(self):
        destination = WheelDestination()

        with pytest.raises(NotImplementedError):
            destination.write_script(name=None, module=None, attr=None, section=None)

        with pytest.raises(NotImplementedError):
            destination.write_file(
                scheme=None, path=None, stream=None, is_executable=False
            )

        with pytest.raises(NotImplementedError):
            destination.finalize_installation(
                scheme=None,
                record_file_path=None,
                records=None,
            )


class TestSchemeDictionaryDestination:
    @pytest.fixture()
    def destination(self, tmp_path):
        scheme_dict = {}
        for scheme in SCHEME_NAMES:
            full_path = tmp_path / scheme
            if not full_path.exists():
                full_path.mkdir()
            scheme_dict[scheme] = str(full_path)
        return SchemeDictionaryDestination(scheme_dict, "/my/python", "posix")

    @pytest.fixture()
    def destination_overwrite_existing(self, tmp_path):
        scheme_dict = {}
        for scheme in SCHEME_NAMES:
            full_path = tmp_path / scheme
            if not full_path.exists():
                full_path.mkdir()
            scheme_dict[scheme] = str(full_path)
        return SchemeDictionaryDestination(
            scheme_dict, "/my/python", "posix", overwrite_existing=True
        )

    @pytest.mark.parametrize(
        ("scheme", "path", "data", "expected"),
        [
            pytest.param(
                "data", "my_data.bin", b"my data", b"my data", id="normal file"
            ),
            pytest.param(
                "data",
                "data_folder/my_data.bin",
                b"my data",
                b"my data",
                id="normal file in subfolder",
            ),
            pytest.param(
                "scripts",
                "my_script.py",
                b"#!python\nmy script",
                b"#!/my/python\nmy script",
                id="script file",
            ),
            pytest.param(
                "scripts",
                "script_folder/my_script.py",
                b"#!python\nmy script",
                b"#!/my/python\nmy script",
                id="script file in subfolder",
            ),
        ],
    )
    def test_write_file(self, destination, scheme, path, data, expected):
        record = destination.write_file(scheme, path, io.BytesIO(data), False)
        file_data = (Path(destination.scheme_dict[scheme]) / path).read_bytes()
        assert file_data == expected
        assert record.path == path

    def test_write_record_duplicate(self, destination):
        destination.write_file("data", "my_data.bin", io.BytesIO(b"my data"), False)
        with pytest.raises(FileExistsError):
            destination.write_file("data", "my_data.bin", io.BytesIO(b"my data"), False)

    def test_write_record_duplicate_with_overwrite_existing(
        self, destination_overwrite_existing
    ):
        destination_overwrite_existing.write_file(
            "data", "my_data.bin", io.BytesIO(b"my data"), False
        )
        destination_overwrite_existing.write_file(
            "data", "my_data.bin", io.BytesIO(b"my data"), False
        )

    def test_write_script(self, destination):
        script_args = ("my_entrypoint", "my_module", "my_function", "console")
        record = destination.write_script(*script_args)
        file_path = Path(destination.scheme_dict["scripts"]) / "my_entrypoint"

        assert file_path.is_file()

        file_data = file_path.read_bytes()
        _, expected_data = Script(*script_args).generate("/my/python", "posix")

        assert file_data == expected_data
        assert record.path == "my_entrypoint"

    def test_finalize_write_record(self, destination):
        records = [
            (
                "data",
                destination.write_file(
                    "data",
                    "my_data1.bin",
                    io.BytesIO(b"my data 1"),
                    is_executable=False,
                ),
            ),
            (
                "data",
                destination.write_file(
                    "data",
                    "my_data2.bin",
                    io.BytesIO(b"my data 2"),
                    is_executable=False,
                ),
            ),
            (
                "data",
                destination.write_file(
                    "data",
                    "my_data3,my_data4.bin",
                    io.BytesIO(b"my data 3"),
                    is_executable=False,
                ),
            ),
            (
                "scripts",
                destination.write_file(
                    "scripts",
                    "my_script",
                    io.BytesIO(b"my script"),
                    is_executable=True,
                ),
            ),
            (
                "scripts",
                destination.write_file(
                    "scripts",
                    "my_script2",
                    io.BytesIO(b"#!python\nmy script"),
                    is_executable=False,
                ),
            ),
            (
                "scripts",
                destination.write_script(
                    "my_entrypoint", "my_module", "my_function", "console"
                ),
            ),
            ("purelib", RecordEntry("RECORD", None, None)),
        ]

        destination.finalize_installation("purelib", "RECORD", records)
        file_path = Path(destination.scheme_dict["purelib"]) / "RECORD"

        data = file_path.read_bytes()
        expected_data = (
            b"RECORD,,\n"
            b"data/my_data1.bin,sha256=NV0A-M4OPuqTsHjeD6Wth_-UqrpAAAdyplcustFZ8s4,9\n"
            b"data/my_data2.bin,sha256=lP7V8oWLqgyXCbdASNiPdsUogzPUZhht_7F8T5bC3eQ,9\n"
            b'data/my_data3,my_data4.bin",sha256=18krruu1gr01x-WM_9ChSASoHv0mfRAV6-B2bd9sxpo,9\n'
            b"scripts/my_entrypoint,sha256=_p_9nwmeIeoMBfQ0akhr1KbKn3laDydg0J7cy0Fs6JI,216\n"
            b"scripts/my_script,sha256=M60fWvUSMJkPtw2apUvjWWwOcnRPcVy_zO4-4lpH08o,9\n"
            b"scripts/my_script2,sha256=k9_997kTbTYQm7EXFLclVZL1m2N98rU90QX46XeMvjY,22\n"
        )
        assert all(
            real.endswith(expected)
            for real, expected in zip(
                data.split(b"\n"), expected_data.split(b"\n"), strict=True
            )
        )

    def test_blocking_path_traversal(self, destination):
        with pytest.raises(ValueError):
            destination._path_with_destdir("purelib", "subdir/../../outside.txt")


def _make_wheel(path, *, name="demo", script=b"#!python\nprint('ok')\n"):
    files = {
        f"{name}/__init__.py": "value = 1\n",
        f"{name}-1.0.dist-info/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: test\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
        f"{name}-1.0.dist-info/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {name}\n"
            "Version: 1.0\n"
        ),
        f"{name}-1.0.dist-info/RECORD": "",
        f"{name}-1.0.data/scripts/{name}": script,
    }
    with zipfile.ZipFile(path, "w") as archive:
        for filename, contents in files.items():
            archive.writestr(filename, contents)


def _open_destination(tmp_path, **kwargs):
    scheme_dict = {}
    for scheme_name in SCHEME_NAMES:
        path = tmp_path / scheme_name
        path.mkdir(exist_ok=True)
        scheme_dict[scheme_name] = str(path)

    options = {
        "scheme_dict": scheme_dict,
        "interpreter": "/test/python",
        "script_kind": "posix",
        "transaction_dir": tmp_path / "transaction",
    }
    options.update(kwargs)
    return TransactionalSchemeDictionaryDestination(**options), scheme_dict


def _open_recovered(destination, scheme_dict):
    return TransactionalSchemeDictionaryDestination.from_transaction_dir(
        destination.transaction_path,
        scheme_dict=scheme_dict,
        interpreter=destination.interpreter,
        script_kind=destination.script_kind,
        bytecode_optimization_levels=destination.bytecode_optimization_levels,
        overwrite_existing=destination.overwrite_existing,
        remove_completed_transaction=destination.remove_completed_transaction,
    )


def _record_rows(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.reader(stream))


class TestTransactionalSchemeDictionaryDestination:
    def test_installs_prepared_bytes_and_commits_across_schemes(
        self, tmp_path, monkeypatch
    ):
        wheel_path = tmp_path / "demo-1.0-py3-none-any.whl"
        _make_wheel(wheel_path)
        destination, scheme_dict = _open_destination(tmp_path)
        copied = []
        original_copy = shutil.copyfileobj

        def tracked_copy(source, target, length=0):
            copied.append(target.name)
            return original_copy(source, target, length)

        monkeypatch.setattr("installer.destinations.shutil.copyfileobj", tracked_copy)

        with WheelFile.open(wheel_path) as source:
            install(source, destination, {"INSTALLER": b"test installer\n"})

        assert (Path(scheme_dict["purelib"]) / "demo" / "__init__.py").read_bytes() == (
            b"value = 1\n"
        )
        assert (Path(scheme_dict["scripts"]) / "demo").read_text().splitlines()[0] == (
            "#!/test/python"
        )
        # The implementation does not claim a cross-directory atomic rename.
        assert any("installer-tmp" in name for name in copied)
        assert destination.transaction_path.exists()
        manifest_path = destination.transaction_path / "transaction.json"
        assert '"state": "committed"' in manifest_path.read_text()

    def test_write_failure_leaves_destination_unchanged(self, tmp_path, monkeypatch):
        wheel_path = tmp_path / "demo-1.0-py3-none-any.whl"
        _make_wheel(wheel_path)
        destination, scheme_dict = _open_destination(
            tmp_path, remove_completed_transaction=True
        )

        def failing_copy(source, target, length=0):
            raise OSError("simulated staging write failure")

        monkeypatch.setattr(
            "installer.destinations.copyfileobj_with_hashing", failing_copy
        )

        with WheelFile.open(wheel_path) as source:
            with pytest.raises(OSError, match="staging write"):
                install(source, destination, {})

        recovered = _open_recovered(destination, scheme_dict)
        recovered.rollback()

        assert list(Path(scheme_dict["purelib"]).iterdir()) == []
        assert list(Path(scheme_dict["scripts"]).iterdir()) == []
        assert Path(scheme_dict["purelib"]).exists()
        assert Path(scheme_dict["scripts"]).exists()
        assert not destination.transaction_path.exists()

    def test_replacement_failure_can_complete_or_roll_back(
        self, tmp_path, monkeypatch
    ):
        wheel_path = tmp_path / "demo-1.0-py3-none-any.whl"
        _make_wheel(wheel_path)
        destination, scheme_dict = _open_destination(
            tmp_path,
            overwrite_existing=True,
            remove_completed_transaction=True,
        )
        old_file = Path(scheme_dict["purelib"]) / "demo" / "__init__.py"
        old_file.parent.mkdir(parents=True)
        old_file.write_bytes(b"old value\n")
        old_file.chmod(0o640)

        original_copy = destination._copy_staged_beside_target
        calls = 0

        def fail_first_copy(staged_path, target_path, item):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("simulated replacement preparation failure")
            return original_copy(staged_path, target_path, item)

        monkeypatch.setattr(
            destination, "_copy_staged_beside_target", fail_first_copy
        )

        with WheelFile.open(wheel_path) as source:
            with pytest.raises(OSError, match="replacement preparation"):
                install(source, destination, {})

        recovered = _open_recovered(destination, scheme_dict)
        recovered.rollback()

        assert old_file.read_bytes() == b"old value\n"
        assert stat_mode(old_file) & 0o777 == 0o640
        assert not (Path(scheme_dict["scripts"]) / "demo").exists()

    def test_partial_replace_is_resumed_without_losing_old_file(
        self, tmp_path, monkeypatch
    ):
        wheel_path = tmp_path / "demo-1.0-py3-none-any.whl"
        _make_wheel(wheel_path)
        destination, scheme_dict = _open_destination(
            tmp_path,
            overwrite_existing=True,
            remove_completed_transaction=True,
        )
        old_file = Path(scheme_dict["purelib"]) / "demo" / "__init__.py"
        old_file.parent.mkdir(parents=True)
        old_file.write_bytes(b"old value\n")

        original_replace = os.replace

        def replace_after_first(source, target):
            if str(target).endswith("demo/__init__.py"):
                original_replace(source, target)
                raise OSError("simulated crash after replacement")
            return original_replace(source, target)

        monkeypatch.setattr("installer.destinations.os.replace", replace_after_first)

        with WheelFile.open(wheel_path) as source:
            with pytest.raises(OSError, match="simulated crash"):
                install(source, destination, {})

        recovered = _open_recovered(destination, scheme_dict)
        recovered.resume()

        assert old_file.read_bytes() == b"value = 1\n"
        assert (Path(scheme_dict["scripts"]) / "demo").read_text().startswith(
            "#!/test/python\n"
        )
        assert not destination.transaction_path.exists()

    def test_partial_commit_rollback_removes_only_installed_empty_dirs(
        self, tmp_path, monkeypatch
    ):
        wheel_path = tmp_path / "demo-1.0-py3-none-any.whl"
        _make_wheel(wheel_path)
        destination, scheme_dict = _open_destination(
            tmp_path, remove_completed_transaction=True
        )
        original_replace = os.replace

        def replace_then_fail(source, target):
            result = original_replace(source, target)
            if str(target).endswith("demo/__init__.py"):
                raise OSError("simulated crash during partial commit")
            return result

        monkeypatch.setattr(
            "installer.destinations.os.replace", replace_then_fail
        )

        with WheelFile.open(wheel_path) as source:
            with pytest.raises(OSError, match="partial commit"):
                install(source, destination, {})

        recovered = _open_recovered(destination, scheme_dict)
        recovered.rollback()

        assert list(Path(scheme_dict["purelib"]).iterdir()) == []
        assert list(Path(scheme_dict["scripts"]).iterdir()) == []
        assert Path(scheme_dict["purelib"]).exists()
        assert Path(scheme_dict["scripts"]).exists()
        assert not destination.transaction_path.exists()

    def test_final_record_failure_can_roll_back(self, tmp_path, monkeypatch):
        wheel_path = tmp_path / "demo-1.0-py3-none-any.whl"
        _make_wheel(wheel_path)
        destination, scheme_dict = _open_destination(
            tmp_path,
            bytecode_optimization_levels=(0,),
            remove_completed_transaction=True,
        )
        old_file = Path(scheme_dict["purelib"]) / "demo" / "__init__.py"
        old_file.parent.mkdir(parents=True)
        old_file.write_bytes(b"old value\n")
        destination.overwrite_existing = True

        original_stage = destination._stage_stream

        def fail_record_stage(*args, **kwargs):
            result = original_stage(*args, **kwargs)
            if kwargs.get("path", args[2]) == "demo-1.0.dist-info/RECORD":
                raise OSError("simulated final record failure")
            return result

        monkeypatch.setattr(destination, "_stage_stream", fail_record_stage)

        with WheelFile.open(wheel_path) as source:
            with pytest.raises(OSError, match="final record"):
                install(source, destination, {})

        recovered = _open_recovered(destination, scheme_dict)
        recovered.recover()

        assert old_file.read_bytes() == b"old value\n"
        assert list(Path(scheme_dict["scripts"]).iterdir()) == []
        assert list((Path(scheme_dict["purelib"]) / "demo").glob("*.pyc")) == []
        assert not destination.transaction_path.exists()

    def test_record_hashes_match_installed_shebang_and_bytecode(self, tmp_path):
        wheel_path = tmp_path / "demo-1.0-py3-none-any.whl"
        _make_wheel(wheel_path)
        destination, scheme_dict = _open_destination(
            tmp_path, bytecode_optimization_levels=(0,)
        )

        with WheelFile.open(wheel_path) as source:
            install(source, destination, {})

        record_path = (
            Path(scheme_dict["purelib"]) / "demo-1.0.dist-info" / "RECORD"
        )
        rows = _record_rows(record_path)
        rows_by_path = {row[0]: row for row in rows}
        script_path = Path(scheme_dict["scripts"]) / "demo"
        script_hash = hashlib.sha256(script_path.read_bytes()).digest()
        expected_script_hash = (
            base64.urlsafe_b64encode(script_hash).decode().rstrip("=")
        )
        assert rows_by_path["../scripts/demo"][1] == f"sha256={expected_script_hash}"

        pyc_paths = list((Path(scheme_dict["purelib"]) / "demo").rglob("*.pyc"))
        assert len(pyc_paths) == 1
        pyc_hash = hashlib.sha256(pyc_paths[0].read_bytes()).digest()
        expected_pyc_hash = base64.urlsafe_b64encode(pyc_hash).decode().rstrip("=")
        pyc_record_path = f"demo/__pycache__/{pyc_paths[0].name}"
        assert rows_by_path[pyc_record_path][1] == f"sha256={expected_pyc_hash}"


def stat_mode(path):
    return Path(path).stat().st_mode
