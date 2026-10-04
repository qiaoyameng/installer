"""Handles all file writing and post-installation processing."""

import base64
import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Union,
    cast,
)

from installer.records import Hash, RecordEntry, parse_record_file
from installer.scripts import Script
from installer.utils import (
    _WINDOWS,
    Scheme,
    construct_record_file,
    copyfileobj_with_hashing,
    fix_shebang,
    make_file_executable,
)

if TYPE_CHECKING:
    from installer.scripts import LauncherKind, ScriptSection


_STATE_FINALIZING = "finalizing"
_STATE_PREPARING = "preparing"
_STATE_PREPARED = "prepared"
_STATE_COMMITTING = "committing"
_STATE_COMMITTED = "committed"
_STATE_ROLLED_BACK = "rolled_back"
_STATE_ROLLING_BACK = "rolling_back"


def _fsync_directory(path: Path) -> None:
    """Best-effort durable flush of a directory entry change."""
    if _WINDOWS:  # pragma: no cover
        return
    descriptor = os.open(path, os.O_RDONLY)  # noqa: PTH123
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class WheelDestination:
    """Handles writing the unpacked files, script generation and ``RECORD`` generation.

    Subclasses provide the concrete script generation logic, as well as the RECORD file
    (re)writing.
    """

    def write_script(
        self, name: str, module: str, attr: str, section: "ScriptSection"
    ) -> RecordEntry:
        """Write a script in the correct location to invoke given entry point.

        :param name: name of the script
        :param module: module path, to load the entry point from
        :param attr: final attribute access, for the entry point
        :param section: Denotes the "entry point section" where this was specified.
            Valid values are ``"gui"`` and ``"console"``.
        :type section: str

        Example usage/behaviour::

            >>> dest.write_script("pip", "pip._internal.cli", "main", "console")

        """
        raise NotImplementedError

    def write_file(
        self,
        scheme: Scheme,
        path: Union[str, "os.PathLike[str]"],
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write a file to correct ``path`` within the ``scheme``.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        The stream would be closed by the caller, after this call.

        Example usage/behaviour::

            >>> with open("__init__.py") as stream:
            ...     dest.write_file("purelib", "pkg/__init__.py", stream)

        """
        raise NotImplementedError

    def finalize_installation(
        self,
        scheme: Scheme,
        record_file_path: str,
        records: Iterable[tuple[Scheme, RecordEntry]],
    ) -> None:
        """Finalize installation, after all the files are written.

        Handles (re)writing of the ``RECORD`` file.

        :param scheme: scheme to write the ``RECORD`` file in
        :param record_file_path: path of the ``RECORD`` file with that scheme
        :param records: entries to write to the ``RECORD`` file

        Example usage/behaviour::

            >>> dest.finalize_installation("purelib")

        """
        raise NotImplementedError


@dataclass
class SchemeDictionaryDestination(WheelDestination):
    """Destination, based on a mapping of {scheme: file-system-path}."""

    scheme_dict: dict[str, str]
    """A mapping of {scheme: file-system-path}"""

    interpreter: str
    """The interpreter to use for generating scripts."""

    script_kind: "LauncherKind"
    """The "kind" of launcher script to use."""

    hash_algorithm: str = "sha256"
    """
    The hashing algorithm to use, which is a member of
    :any:`hashlib.algorithms_available` (ideally from
    :any:`hashlib.algorithms_guaranteed`).
    """

    bytecode_optimization_levels: Collection[int] = ()
    """
    Compile cached bytecode for installed .py files with these optimization
    levels. The bytecode is specific to the minor version of Python (e.g. 3.10)
    used to generate it.
    """

    destdir: str | None = None
    """
    A staging directory in which to write all files. This is expected to be the
    filesystem root at runtime, so embedded paths will be written as though
    this was the root.
    """

    overwrite_existing: bool = False
    """Silently overwrite existing files."""

    def _path_with_destdir(self, scheme: Scheme, path: str) -> Path:
        # See https://docs.python.org/3/library/zipfile.html#zipfile.Path:
        #  When handling untrusted archives,
        #  consider resolving filenames using os.path.abspath()
        #  and checking against the target directory with os.path.commonpath().
        #
        # Attention: Path.absolute() is not sufficient because it does not
        #  normalize, i.e. does not remove "..".
        #
        # We want to avoid Path.resolve() because it is significantly slower
        # than os.path.abspath()!
        target_dir = Path(os.path.abspath(self.scheme_dict[scheme]))  # noqa: PTH100
        file = Path(os.path.abspath(target_dir / path))  # noqa: PTH100

        if not file.is_relative_to(target_dir):
            raise ValueError(
                f"Attempting to write {path} outside of the target directory"
            )

        if self.destdir is not None:
            rel_path = file.relative_to(file.anchor)
            return Path(self.destdir) / rel_path
        return file

    def write_to_fs(
        self,
        scheme: Scheme,
        path: str,
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write contents of ``stream`` to the correct location on the filesystem.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        - Ensures that an existing file is not being overwritten.
        - Hashes the written content, to determine the entry in the ``RECORD`` file.
        """
        target_path = self._path_with_destdir(scheme, path)
        if not self.overwrite_existing and target_path.exists():
            message = f"File already exists: {target_path!s}"
            raise FileExistsError(message)

        parent_folder = target_path.parent
        if not parent_folder.exists():
            parent_folder.mkdir(parents=True)

        with target_path.open("wb") as f:
            hash_, size = copyfileobj_with_hashing(stream, f, self.hash_algorithm)

        if is_executable:
            make_file_executable(target_path)

        return RecordEntry(path, Hash(self.hash_algorithm, hash_), size)

    def write_file(
        self,
        scheme: Scheme,
        path: Union[str, "os.PathLike[str]"],
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write a file to correct ``path`` within the ``scheme``.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        - Changes the shebang for files in the "scripts" scheme.
        - Uses :py:meth:`SchemeDictionaryDestination.write_to_fs` for the
          filesystem interaction.
        """
        path_ = os.fspath(path)

        if scheme == "scripts":
            with fix_shebang(stream, self.interpreter) as stream_with_different_shebang:
                return self.write_to_fs(
                    scheme, path_, stream_with_different_shebang, is_executable
                )

        return self.write_to_fs(scheme, path_, stream, is_executable)

    def write_script(
        self, name: str, module: str, attr: str, section: "ScriptSection"
    ) -> RecordEntry:
        """Write a script to invoke an entrypoint.

        :param name: name of the script
        :param module: module path, to load the entry point from
        :param attr: final attribute access, for the entry point
        :param section: Denotes the "entry point section" where this was specified.
            Valid values are ``"gui"`` and ``"console"``.
        :type section: str

        - Generates a launcher using :any:`Script.generate`.
        - Writes to the "scripts" scheme.
        - Uses :py:meth:`SchemeDictionaryDestination.write_to_fs` for the
          filesystem interaction.
        """
        script = Script(name, module, attr, section)
        script_name, data = script.generate(self.interpreter, self.script_kind)

        with io.BytesIO(data) as stream:
            entry = self.write_to_fs(
                Scheme("scripts"), script_name, stream, is_executable=True
            )

            path = self._path_with_destdir(Scheme("scripts"), script_name)
            mode = path.stat().st_mode
            mode |= (mode & 0o444) >> 2
            path.chmod(mode)

            return entry

    def _compile_bytecode(self, scheme: Scheme, record: RecordEntry) -> None:
        """Compile bytecode for a single .py file."""
        if not self.bytecode_optimization_levels or scheme not in (
            "purelib",
            "platlib",
        ):
            return

        import compileall

        target_path = self._path_with_destdir(scheme, record.path)
        dir_path_to_embed = (Path(self.scheme_dict[scheme]) / record.path).parent

        for level in self.bytecode_optimization_levels:
            compileall.compile_file(
                target_path, optimize=level, quiet=1, ddir=dir_path_to_embed
            )

    def finalize_installation(
        self,
        scheme: Scheme,
        record_file_path: str,
        records: Iterable[tuple[Scheme, RecordEntry]],
    ) -> None:
        """Finalize installation, by writing the ``RECORD`` file & compiling bytecode.

        :param scheme: scheme to write the ``RECORD`` file in
        :param record_file_path: path of the ``RECORD`` file with that scheme
        :param records: entries to write to the ``RECORD`` file
        """

        def prefix_for_scheme(file_scheme: str) -> str | None:
            if file_scheme == scheme:
                return None
            if _WINDOWS:  # pragma: no cover
                path = os.path.abspath(self.scheme_dict[file_scheme])  # noqa: PTH100
            else:  # pragma: no cover
                path = os.path.relpath(
                    self.scheme_dict[file_scheme],
                    start=self.scheme_dict[scheme],
                )
            return path + "/"

        record_list = list(records)
        with construct_record_file(record_list, prefix_for_scheme) as record_stream:
            self.write_to_fs(
                scheme, record_file_path, record_stream, is_executable=False
            )

        for scheme_, record in record_list:
            self._compile_bytecode(scheme_, record)


@dataclass
class TransactionalSchemeDictionaryDestination(SchemeDictionaryDestination):
    """Prepare a wheel in a temporary area before replacing destination files.

    This destination does not provide a single cross-directory atomic rename.
    Individual regular files are replaced atomically when source and destination
    are on the same filesystem; otherwise a temporary file is copied beside the
    destination and atomically renamed into place. A JSON manifest durably
    records preparation, replacement and rollback state, so an interrupted
    process can either finish the installation or restore replaced files.

    Provide ``transaction_dir`` when the caller needs to recover after the
    installing process exits. The manifest state determines whether recovery
    completes a prepared/partly committed installation or rolls back an
    installation interrupted before commit.
    """

    transaction_dir: str | Path | None = None
    """Stable directory containing staged files and persistent transaction state."""

    remove_completed_transaction: bool = False
    """Remove the transaction directory after successful commit or rollback."""

    _initialized: bool = field(default=False, init=False, repr=False)
    _manifest: dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    _transaction_path: Path | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._initialize_transaction()

    @classmethod
    def from_transaction_dir(
        cls,
        path: str | Path,
        scheme_dict: dict[str, str],
        interpreter: str,
        script_kind: "LauncherKind",
        **kwargs: Any,
    ) -> "TransactionalSchemeDictionaryDestination":
        """Open a destination with a persisted transaction for recovery."""
        destination = cls(
            scheme_dict=scheme_dict,
            interpreter=interpreter,
            script_kind=script_kind,
            transaction_dir=path,
            **kwargs,
        )
        return cast("TransactionalSchemeDictionaryDestination", destination)

    @property
    def transaction_path(self) -> Path:
        """Path to the active transaction directory."""
        self._ensure_initialized()
        assert self._transaction_path is not None
        return self._transaction_path

    def _initialize_transaction(self) -> None:
        if self._initialized:
            return

        if self.transaction_dir is None:
            transaction_path = Path(
                tempfile.mkdtemp(prefix="installer-transaction-")
            )
        else:
            transaction_path = Path(self.transaction_dir)
            transaction_path.mkdir(parents=True, exist_ok=True)

        self._transaction_path = transaction_path
        (transaction_path / "files").mkdir(exist_ok=True)
        (transaction_path / "backups").mkdir(exist_ok=True)

        manifest_path = self._manifest_path()
        if manifest_path.exists():
            with manifest_path.open("rb") as stream:
                self._manifest = json.loads(stream.read().decode("utf-8"))
            self._validate_manifest(self._manifest)
        else:
            self._manifest = {
                "version": 1,
                "state": _STATE_PREPARING,
                "root_scheme": None,
                "record_file_path": None,
                "next_item_id": 0,
                "items": [],
                "directories": [],
            }
            self._write_manifest()

        self._initialized = True

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self._initialize_transaction()

    def _manifest_path(self) -> Path:
        assert self._transaction_path is not None
        return self._transaction_path / "transaction.json"

    def _write_manifest(self) -> None:
        assert self._transaction_path is not None
        manifest_path = self._manifest_path()
        temporary_path = manifest_path.with_name(".transaction.json.tmp")
        with temporary_path.open("w", encoding="utf-8") as stream:
            json.dump(self._manifest, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, manifest_path)
        _fsync_directory(manifest_path.parent)

    def _validate_manifest(self, manifest: dict[str, Any]) -> None:
        if manifest.get("version") != 1:
            message = f"Unsupported transaction manifest version: {manifest.get('version')}"
            raise ValueError(message)
        if not isinstance(manifest.get("items"), list):
            message = "Transaction manifest is missing its item list"
            raise ValueError(message)

    def _items_by_destination(self) -> dict[tuple[str, str], dict[str, Any]]:
        return {
            (str(item["scheme"]), str(item["path"])): item
            for item in self._manifest["items"]
        }

    def _staged_parts(self, scheme: Scheme, path: str) -> Path:
        parts = tuple(part for part in Path(path).parts if part != "..")
        if parts and Path(path).anchor:
            message = f"Attempting to write {path} outside of the staging directory"
            raise ValueError(message)
        return Path(str(scheme), *parts)

    def _staged_path(self, scheme: Scheme, path: str) -> Path:
        # Calling this also performs destination traversal validation.
        self._path_with_destdir(scheme, path)
        return self.transaction_path / "files" / self._staged_parts(scheme, path)

    def _hash_path(self, path: Path) -> tuple[str, int]:
        hasher = hashlib.new(self.hash_algorithm)
        size = 0
        with path.open("rb") as stream:
            while True:
                buf = stream.read(1024 * 1024)
                if not buf:
                    break
                hasher.update(buf)
                size += len(buf)
        return (
            base64.urlsafe_b64encode(hasher.digest()).decode("ascii").rstrip("="),
            size,
        )

    def _existing_target_info(self, target_path: Path) -> dict[str, Any] | None:
        if not target_path.is_symlink() and not target_path.exists():
            return None

        mode = target_path.lstat().st_mode
        if stat.S_ISLNK(mode):
            return {"kind": "link", "target": os.readlink(target_path)}
        if not stat.S_ISREG(mode):
            message = f"Existing path is not a regular file or symlink: {target_path}"
            raise IsADirectoryError(message)

        hash_value, size = self._hash_path(target_path)
        return {
            "kind": "file",
            "hash": {"name": self.hash_algorithm, "value": hash_value},
            "size": size,
            "mode": mode,
        }

    def _stage_stream(
        self,
        item_id: int | None,
        scheme: Scheme,
        path: str,
        stream: BinaryIO,
        is_executable: bool,
        *,
        generated: bool,
    ) -> tuple[RecordEntry, dict[str, Any]]:
        target_path = self._path_with_destdir(scheme, path)
        staged_path = self._staged_path(scheme, path)
        key = (str(scheme), path)
        existing_item = self._items_by_destination().get(key)

        if item_id is None and existing_item is not None:
            item_id = int(existing_item["id"])
        if item_id is None:
            item_id = int(self._manifest["next_item_id"])
            self._manifest["next_item_id"] = item_id + 1

        target_exists = target_path.is_symlink() or target_path.exists()
        if existing_item is None and target_exists:
            if not self.overwrite_existing:
                message = f"File already exists: {target_path!s}"
                raise FileExistsError(message)

        old_target = (
            existing_item.get("old_target")
            if existing_item is not None
            else self._existing_target_info(target_path)
        )

        staged_path.parent.mkdir(parents=True, exist_ok=True)
        if is_executable:
            staged_path.touch()
            make_file_executable(staged_path)

        with staged_path.open("wb") as staged_stream:
            hash_value, size = copyfileobj_with_hashing(
                stream, staged_stream, self.hash_algorithm
            )
            staged_stream.flush()
            os.fsync(staged_stream.fileno())
        _fsync_directory(staged_path.parent)

        item = {
            "id": item_id,
            "scheme": str(scheme),
            "path": path,
            "staged": str(
                staged_path.relative_to(self.transaction_path / "files")
            ),
            "hash": {"name": self.hash_algorithm, "value": hash_value},
            "size": size,
            "executable": is_executable,
            "generated": generated,
            "committed": False,
            "old_target": old_target,
        }

        if existing_item is None:
            self._manifest["items"].append(item)
        else:
            self._manifest["items"] = [
                item if candidate is existing_item else candidate
                for candidate in self._manifest["items"]
            ]

        self._write_manifest()
        return RecordEntry(path, Hash(self.hash_algorithm, hash_value), size), item

    def write_to_fs(
        self,
        scheme: Scheme,
        path: str,
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write a file to the staging area and record it in the manifest."""
        self._ensure_initialized()
        if self._manifest["state"] not in (_STATE_PREPARING, _STATE_FINALIZING):
            message = "Transaction is not accepting new files"
            raise RuntimeError(message)

        record, _ = self._stage_stream(
            None,
            scheme,
            path,
            stream,
            is_executable,
            generated=False,
        )
        return record

    def write_script(
        self, name: str, module: str, attr: str, section: "ScriptSection"
    ) -> RecordEntry:
        """Generate a launcher and stage it with its final executable mode."""
        script = Script(name, module, attr, section)
        script_name, data = script.generate(self.interpreter, self.script_kind)

        with io.BytesIO(data) as stream:
            entry = self.write_to_fs(
                Scheme("scripts"), script_name, stream, is_executable=True
            )
            staged_path = self._staged_path(Scheme("scripts"), script_name)
            mode = staged_path.stat().st_mode
            mode |= (mode & 0o444) >> 2
            staged_path.chmod(mode)
            return entry

    def _bytecode_records(self) -> list[tuple[Scheme, RecordEntry]]:
        if not self.bytecode_optimization_levels:
            return []

        import importlib.util
        import py_compile

        generated_records: list[tuple[Scheme, RecordEntry]] = []

        for source_item in list(self._manifest["items"]):
            source_scheme = Scheme(str(source_item["scheme"]))
            source_path = str(source_item["path"])
            if (
                source_scheme not in (Scheme("purelib"), Scheme("platlib"))
                or not source_path.endswith(".py")
                or "__pycache__" in source_path.split("/")
            ):
                continue

            source_staged_path = self._staged_path(source_scheme, source_path)
            source_target_path = Path(self.scheme_dict[source_scheme]) / source_path
            ddir = str(source_target_path.parent)

            for level in sorted(set(self.bytecode_optimization_levels)):
                optimization = "" if level == 0 else level
                target_pyc = Path(
                    importlib.util.cache_from_source(
                        source_target_path,
                        optimization=optimization,
                    )
                )
                pyc_relative = os.path.relpath(
                    target_pyc, Path(self.scheme_dict[source_scheme])
                )
                pyc_path = pyc_relative.replace(os.sep, "/")
                staged_pyc = self._staged_path(source_scheme, pyc_path)
                staged_pyc.parent.mkdir(parents=True, exist_ok=True)

                py_compile.compile(
                    str(source_staged_path),
                    cfile=str(staged_pyc),
                    dfile=str(Path(ddir) / Path(source_path).name),
                    doraise=True,
                    optimize=level,
                    quiet=1,
                )

                pyc_data = staged_pyc.read_bytes()
                with io.BytesIO(pyc_data) as stream:
                    record, _ = self._stage_stream(
                        None,
                        source_scheme,
                        pyc_path,
                        stream,
                        False,
                        generated=True,
                    )
                generated_records.append((source_scheme, record))

        self._write_manifest()
        return generated_records

    def _construct_record_rows(
        self,
        scheme: Scheme,
        records: list[tuple[Scheme, RecordEntry]],
    ) -> bytes:
        def prefix_for_scheme(file_scheme: str) -> str | None:
            if file_scheme == scheme:
                return None
            if _WINDOWS:  # pragma: no cover
                path = os.path.abspath(self.scheme_dict[file_scheme])  # noqa: PTH100
            else:  # pragma: no cover
                path = os.path.relpath(
                    self.scheme_dict[file_scheme],
                    start=self.scheme_dict[scheme],
                )
            return path + "/"

        with construct_record_file(records, prefix_for_scheme) as stream:
            return stream.read()

    def _validate_prepared(
        self,
        scheme: Scheme,
        record_file_path: str,
        records: list[tuple[Scheme, RecordEntry]],
        record_rows: bytes,
    ) -> None:
        manifest_destinations = {
            (str(item["scheme"]), str(item["path"]))
            for item in self._manifest["items"]
        }
        expected_destinations = {
            (str(file_scheme), record.path)
            for file_scheme, record in records
            if record.hash_ is not None
        }
        expected_destinations.add((str(scheme), record_file_path))

        if manifest_destinations != expected_destinations:
            message = "Prepared transaction does not match the installation plan"
            raise RuntimeError(message)

        for item in self._manifest["items"]:
            item_scheme = Scheme(str(item["scheme"]))
            item_path = str(item["path"])
            staged_path = self._staged_path(item_scheme, item_path)
            hash_value, size = self._hash_path(staged_path)
            if (
                size != int(item["size"])
                or hash_value != str(item["hash"]["value"])
            ):
                message = f"Prepared file failed validation: {item_scheme}/{item_path}"
                raise RuntimeError(message)

            old_target = item.get("old_target")
            if old_target is not None and old_target.get("kind") == "file":
                target_path = self._path_with_destdir(item_scheme, item_path)
                current_hash, current_size = self._hash_path(target_path)
                if (
                    current_size != int(old_target["size"])
                    or current_hash != str(old_target["hash"]["value"])
                ):
                    message = (
                        "Destination changed while preparing the transaction: "
                        f"{target_path}"
                    )
                    raise RuntimeError(message)

        parsed_rows = list(parse_record_file(record_rows.decode("utf-8").splitlines()))
        record_destinations: set[tuple[str, str]] = {(
            str(scheme), record_file_path
        )}
        for file_scheme, record in records:
            prefix = ""
            if file_scheme != scheme:
                if _WINDOWS:  # pragma: no cover
                    prefix = (
                        os.path.abspath(  # noqa: PTH100
                            self.scheme_dict[file_scheme]
                        )
                        + "/"
                    )
                else:  # pragma: no cover
                    prefix = (
                        os.path.relpath(
                            self.scheme_dict[file_scheme],
                            start=self.scheme_dict[scheme],
                        )
                        + "/"
                    )
            record_destinations.add((str(scheme), prefix + record.path))

        parsed_destinations = {(str(scheme), row[0]) for row in parsed_rows}
        if parsed_destinations != record_destinations:
            message = "Prepared RECORD does not match the installation plan"
            raise RuntimeError(message)

    def finalize_installation(
        self,
        scheme: Scheme,
        record_file_path: str,
        records: Iterable[tuple[Scheme, RecordEntry]],
    ) -> None:
        """Prepare and verify bytecode/RECORD, then commit the transaction."""
        self._ensure_initialized()
        record_list = list(records)
        record_record = RecordEntry(record_file_path, None, None)
        record_list = [
            item
            for item in record_list
            if not (
                str(item[0]) == str(scheme)
                and item[1].path == record_file_path
            )
        ]
        record_list.append((scheme, record_record))

        self._manifest["state"] = _STATE_FINALIZING
        self._manifest["root_scheme"] = str(scheme)
        self._manifest["record_file_path"] = record_file_path
        self._write_manifest()

        for generated_scheme, generated_record in self._bytecode_records():
            record_list.append((generated_scheme, generated_record))

        record_rows = self._construct_record_rows(scheme, record_list)
        with io.BytesIO(record_rows) as stream:
            self._stage_stream(
                None,
                scheme,
                record_file_path,
                stream,
                False,
                generated=True,
            )

        self._validate_prepared(scheme, record_file_path, record_list, record_rows)
        self._manifest["directories"] = self._planned_directories()
        self._manifest["state"] = _STATE_PREPARED
        self._write_manifest()
        self.commit()

    def _planned_directories(self) -> list[dict[str, Any]]:
        directories: dict[str, None] = {}
        for item in self._manifest["items"]:
            item_scheme = Scheme(str(item["scheme"]))
            item_path = str(item["path"])
            target_path = self._path_with_destdir(item_scheme, item_path)
            current = target_path.parent

            while True:
                directories[str(current)] = None
                if current.exists() or current.is_symlink():
                    break
                parent = current.parent
                if parent == current:
                    break
                current = parent

        ordered = sorted(directories, key=lambda value: (len(Path(value).parts), value))
        return [
            {
                "path": directory,
                "absent_at_preparation": not Path(directory).exists()
                and not Path(directory).is_symlink(),
                "created_by_us": False,
            }
            for directory in ordered
        ]

    def _create_planned_directories(self) -> None:
        for directory_info in self._manifest["directories"]:
            directory = Path(str(directory_info["path"]))
            if directory.is_symlink() or directory.exists():
                if directory_info.get("absent_at_preparation"):
                    directory_info["created_by_us"] = True
                continue
            self._write_manifest()
            directory.mkdir(parents=False, exist_ok=True)
            directory_info["created_by_us"] = True
            self._write_manifest()
            _fsync_directory(directory.parent)

    def _backup_path_for_item(self, item: dict[str, Any]) -> Path:
        return self.transaction_path / "backups" / str(item["id"])

    def _temporary_target_path_for_item(
        self, target_path: Path, item: dict[str, Any]
    ) -> Path:
        return target_path.with_name(
            f".{target_path.name}.installer-tmp-{item['id']}"
        )

    def _copy_staged_beside_target(
        self, staged_path: Path, target_path: Path, item: dict[str, Any]
    ) -> Path:
        temporary_path = self._temporary_target_path_for_item(target_path, item)
        if temporary_path.is_symlink() or temporary_path.exists():
            temporary_path.unlink()
        with staged_path.open("rb") as source_stream, temporary_path.open(
            "wb"
        ) as target_stream:
            shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
            target_stream.flush()
            os.fsync(target_stream.fileno())
        temporary_path.chmod(staged_path.stat().st_mode)
        _fsync_directory(temporary_path.parent)
        return temporary_path

    def _persist_existing_target(self, item: dict[str, Any], target_path: Path) -> None:
        old_target = item.get("old_target")
        backup_path = self._backup_path_for_item(item)

        if old_target is None:
            return
        if backup_path.exists() or backup_path.is_symlink():
            return

        if old_target.get("kind") == "link":
            os.symlink(str(old_target["target"]), backup_path)
        else:
            shutil.copy2(target_path, backup_path, follow_symlinks=False)
            backup_path.chmod(int(old_target["mode"]))
        _fsync_directory(backup_path.parent)

    def _target_matches_item(
        self, target_path: Path, item: dict[str, Any]
    ) -> bool:
        if target_path.is_symlink() or not target_path.exists():
            return False
        if not stat.S_ISREG(target_path.lstat().st_mode):
            return False
        hash_value, size = self._hash_path(target_path)
        return size == int(item["size"]) and hash_value == str(item["hash"]["value"])

    def _target_matches_old(self, target_path: Path, old_target: dict[str, Any]) -> bool:
        if old_target.get("kind") == "link":
            return target_path.is_symlink() and os.readlink(target_path) == str(
                old_target["target"]
            )
        if target_path.is_symlink() or not target_path.exists():
            return False
        if not stat.S_ISREG(target_path.lstat().st_mode):
            return False
        hash_value, size = self._hash_path(target_path)
        return size == int(old_target["size"]) and hash_value == str(
            old_target["hash"]["value"]
        )

    def _commit_item(self, item: dict[str, Any]) -> None:
        if item.get("committed"):
            return

        item_scheme = Scheme(str(item["scheme"]))
        item_path = str(item["path"])
        target_path = self._path_with_destdir(item_scheme, item_path)
        staged_path = self._staged_path(item_scheme, item_path)
        old_target = item.get("old_target")
        backup_path = self._backup_path_for_item(item)

        if old_target is not None:
            if target_path.is_symlink() or target_path.exists():
                if self._target_matches_item(target_path, item):
                    if not backup_path.exists() and not backup_path.is_symlink():
                        message = (
                            "Cannot resume commit without the backup required for "
                            f"rollback: {backup_path}"
                        )
                        raise RuntimeError(message)
                    item["committed"] = True
                    self._write_manifest()
                    return
                elif self._target_matches_old(target_path, old_target):
                    self._persist_existing_target(item, target_path)
                else:
                    message = (
                        "Destination changed before transaction commit: "
                        f"{target_path}"
                    )
                    raise RuntimeError(message)
            elif not backup_path.exists() and not backup_path.is_symlink():
                message = (
                    "Cannot resume commit without the backup required for rollback: "
                    f"{backup_path}"
                )
                raise RuntimeError(message)
        elif target_path.is_symlink() or target_path.exists():
            if not self._target_matches_item(target_path, item):
                message = (
                    "Destination changed before transaction commit: "
                    f"{target_path}"
                )
                raise RuntimeError(message)
            item["committed"] = True
            self._write_manifest()
            return

        temporary_path = self._copy_staged_beside_target(
            staged_path, target_path, item
        )
        os.replace(temporary_path, target_path)
        _fsync_directory(target_path.parent)

        hash_value, size = self._hash_path(target_path)
        if size != int(item["size"]) or hash_value != str(item["hash"]["value"]):
            message = f"Installed file does not match prepared content: {target_path}"
            raise RuntimeError(message)

        item["committed"] = True
        self._write_manifest()

    def commit(self) -> None:
        """Finish a prepared or partially committed transaction."""
        self._ensure_initialized()
        state = self._manifest["state"]
        if state == _STATE_COMMITTED:
            self._cleanup_transaction()
            return
        if state not in (_STATE_PREPARED, _STATE_COMMITTING):
            message = f"Cannot commit a transaction in state {state!r}"
            raise RuntimeError(message)

        self._manifest["state"] = _STATE_COMMITTING
        self._write_manifest()
        self._create_planned_directories()

        for item in self._manifest["items"]:
            self._commit_item(item)

        for item in self._manifest["items"]:
            backup_path = self._backup_path_for_item(item)
            if backup_path.is_symlink() or backup_path.exists():
                backup_path.unlink()
                _fsync_directory(backup_path.parent)

        self._manifest["state"] = _STATE_COMMITTED
        self._write_manifest()
        self._cleanup_transaction()

    def resume(self) -> None:
        """Continue an interrupted commit, or clean up a completed one."""
        self._ensure_initialized()
        state = self._manifest["state"]
        if state in (_STATE_PREPARED, _STATE_COMMITTING, _STATE_COMMITTED):
            self.commit()
            return
        message = (
            "Transaction was interrupted before preparation completed; "
            "use rollback() to restore the destination"
        )
        raise RuntimeError(message)

    def _rollback_new_file(self, item: dict[str, Any], target_path: Path) -> bool:
        if not target_path.is_symlink() and not target_path.exists():
            return True
        hash_value, size = self._hash_path(target_path)
        if size == int(item["size"]) and hash_value == str(item["hash"]["value"]):
            target_path.unlink()
            _fsync_directory(target_path.parent)
            return True
        return False

    def _restore_old_target(
        self, item: dict[str, Any], target_path: Path, backup_path: Path
    ) -> None:
        old_target = item.get("old_target")
        if old_target is None:
            if target_path.is_symlink() or target_path.exists():
                if not self._rollback_new_file(item, target_path):
                    message = f"Refusing to remove changed file during rollback: {target_path}"
                    raise RuntimeError(message)
            return

        if target_path.is_symlink() or target_path.exists():
            if old_target.get("kind") == "file":
                current_hash, current_size = self._hash_path(target_path)
                is_new_content = (
                    current_size == int(item["size"])
                    and current_hash == str(item["hash"]["value"])
                )
                is_old_content = (
                    current_size == int(old_target["size"])
                    and current_hash == str(old_target["hash"]["value"])
                )
                if is_new_content:
                    target_path.unlink()
                elif is_old_content:
                    target_path.chmod(int(old_target["mode"]))
                    return
                else:
                    message = f"Refusing to replace changed file during rollback: {target_path}"
                    raise RuntimeError(message)
            elif target_path.is_symlink():
                if os.readlink(target_path) == str(old_target["target"]):
                    return
                target_path.unlink()
            else:
                if not self._target_matches_item(target_path, item):
                    message = f"Expected a symlink at {target_path} during rollback"
                    raise RuntimeError(message)
                target_path.unlink()

        temporary_path = backup_path.with_name(
            f".{backup_path.name}.installer-restore-{os.getpid()}"
        )
        if backup_path.is_symlink():
            os.symlink(os.readlink(backup_path), temporary_path)
        else:
            shutil.copy2(backup_path, temporary_path, follow_symlinks=False)
        os.replace(temporary_path, target_path)
        if old_target.get("kind") == "file":
            target_path.chmod(int(old_target["mode"]))
        _fsync_directory(target_path.parent)

    def _rollback_item(self, item: dict[str, Any]) -> None:
        item_scheme = Scheme(str(item["scheme"]))
        item_path = str(item["path"])
        target_path = self._path_with_destdir(item_scheme, item_path)
        backup_path = self._backup_path_for_item(item)
        old_target = item.get("old_target")
        temporary_path = self._temporary_target_path_for_item(target_path, item)

        if old_target is None:
            if target_path.is_symlink() or target_path.exists():
                if not self._rollback_new_file(item, target_path):
                    message = f"Refusing to remove changed file during rollback: {target_path}"
                    raise RuntimeError(message)
        elif backup_path.exists() or backup_path.is_symlink():
            self._restore_old_target(item, target_path, backup_path)
        elif item.get("committed"):
            message = f"Backup required to restore {target_path} is missing"
            raise RuntimeError(message)

        if temporary_path.is_symlink() or temporary_path.exists():
            temporary_path.unlink()
            _fsync_directory(temporary_path.parent)

    def _remove_created_directories(self) -> None:
        for directory_info in reversed(self._manifest["directories"]):
            directory = Path(str(directory_info["path"]))
            if not (
                directory_info.get("created_by_us")
                or directory_info.get("absent_at_preparation")
            ):
                continue
            try:
                directory.rmdir()
            except FileNotFoundError:
                continue
            except OSError:
                continue
            _fsync_directory(directory.parent)

    def rollback(self) -> None:
        """Restore replaced files and remove this transaction's empty directories."""
        self._ensure_initialized()
        state = self._manifest["state"]
        if state == _STATE_ROLLED_BACK:
            self._cleanup_transaction()
            return
        if state == _STATE_COMMITTED:
            message = "Cannot roll back a committed transaction"
            raise RuntimeError(message)

        self._manifest["state"] = _STATE_ROLLING_BACK
        self._write_manifest()

        for item in reversed(self._manifest["items"]):
            self._rollback_item(item)
        self._remove_created_directories()

        self._manifest["state"] = _STATE_ROLLED_BACK
        self._write_manifest()
        self._cleanup_transaction()

    def recover(self) -> None:
        """Complete a prepared transaction or roll back an interrupted one."""
        self._ensure_initialized()
        state = self._manifest["state"]
        if state in (_STATE_PREPARED, _STATE_COMMITTING, _STATE_COMMITTED):
            self.commit()
        else:
            self.rollback()

    def _cleanup_transaction(self) -> None:
        if not self.remove_completed_transaction:
            return
        shutil.rmtree(self.transaction_path)
        self._initialized = False
        self._transaction_path = None
