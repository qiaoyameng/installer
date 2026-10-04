"""Handles all file writing and post-installation processing."""

import io
import os
import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    ClassVar,
    Union,
)

from installer.exceptions import (
    InvalidReproducibleConfiguration,
    InvalidSourceDateEpoch,
)
from installer.records import Hash, RecordEntry
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

# Fixed permission bits used for reproducible installations.
_REPRODUCIBLE_FILE_MODE = 0o644
_REPRODUCIBLE_EXECUTABLE_MODE = 0o755
_REPRODUCIBLE_DIR_MODE = 0o755

# Maximum Unix timestamp accepted from SOURCE_DATE_EPOCH (signed 64-bit).
_MAX_SOURCE_DATE_EPOCH = 2**63 - 1

# SOURCE_DATE_EPOCH must be an unsigned integer consisting of ASCII digits:
# https://reproducible-builds.org/docs/source-date-epoch/
_SOURCE_DATE_EPOCH_REGEX = re.compile(r"[0-9]+")


def _read_source_date_epoch() -> int:
    """Read and validate ``SOURCE_DATE_EPOCH`` from the environment.

    :raises InvalidSourceDateEpoch: if the variable is unset, empty or not a
        valid non-negative integer Unix timestamp.
    """
    raw_value = os.environ.get("SOURCE_DATE_EPOCH")
    if raw_value is None:
        msg = (
            "Reproducible installation requires the SOURCE_DATE_EPOCH "
            "environment variable to be set to a non-negative integer Unix "
            "timestamp (see https://reproducible-builds.org/docs/source-date-epoch/)."
        )
        raise InvalidSourceDateEpoch(msg)

    value = raw_value.strip()
    if not _SOURCE_DATE_EPOCH_REGEX.fullmatch(value):
        msg = (
            f"Invalid SOURCE_DATE_EPOCH value {raw_value!r}: expected a "
            "non-negative integer Unix timestamp."
        )
        raise InvalidSourceDateEpoch(msg)

    epoch = int(value)
    if epoch > _MAX_SOURCE_DATE_EPOCH:
        msg = (
            f"Invalid SOURCE_DATE_EPOCH value {raw_value!r}: timestamp must "
            f"be at most {_MAX_SOURCE_DATE_EPOCH}."
        )
        raise InvalidSourceDateEpoch(msg)

    return epoch


def _supports_hash_based_pyc() -> bool:
    """Whether the running interpreter supports hash-based pyc invalidation."""
    import py_compile

    return hasattr(py_compile, "PycInvalidationMode") and hasattr(
        py_compile.PycInvalidationMode, "CHECKED_HASH"
    )


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

    reproducible: bool = False
    """Perform a reproducible installation.

    When enabled, all aspects of the installation are made independent of
    the current time, the process umask and the (possibly random) staging
    directory:

    - File and directory permission bits are fixed (``0644`` for regular
      files, ``0755`` for executables and directories), ignoring the umask.
    - File and directory modification times are taken from the
      ``SOURCE_DATE_EPOCH`` environment variable, which must be set.
    - Bytecode (when requested) is compiled using explicit hash-based
      invalidation (:pep:`552`; ``CHECKED_HASH``), so the generated ``.pyc``
      files never embed timestamps. The code object's filename is the
      logical installation path (built from ``scheme_dict``), never the
      physical staging path (``destdir``).

    Installations made with this option, from the same wheel, with the same
    ``SOURCE_DATE_EPOCH`` value and scheme dictionary, produce byte-for-byte
    identical contents regardless of the staging directory. Byte-identical
    outputs across different Python versions are not guaranteed (bytecode
    is version-specific).

    :raises installer.exceptions.InvalidSourceDateEpoch: if
        ``SOURCE_DATE_EPOCH`` is unset or not a valid non-negative integer.
    :raises installer.exceptions.InvalidReproducibleConfiguration: if
        bytecode compilation is requested but the interpreter cannot produce
        hash-based ``.pyc`` files.
    """

    source_date_epoch: ClassVar[int]
    """Unix timestamp used for all file times in reproducible mode."""

    _created_dirs: ClassVar[set[Path]]
    """Directories created during this installation, for metadata fixing."""

    def __post_init__(self) -> None:
        self._created_dirs: set[Path] = set()

        if not self.reproducible:
            return

        self.source_date_epoch: int = _read_source_date_epoch()

        if self.bytecode_optimization_levels and not _supports_hash_based_pyc():
            msg = (
                "Reproducible installation requires an interpreter that "
                "supports hash-based pyc invalidation (PEP 552), but "
                "py_compile.PycInvalidationMode.CHECKED_HASH is not "
                "available in this Python interpreter. Disable bytecode "
                "compilation (bytecode_optimization_levels=()) or use a "
                "capable interpreter; timestamp-based pyc files are not "
                "emitted in reproducible mode."
            )
            raise InvalidReproducibleConfiguration(msg)

    def _normalize_dir_metadata(self, path: Path) -> None:
        """Apply fixed mode and mtime to a directory in reproducible mode."""
        if self.reproducible:
            path.chmod(_REPRODUCIBLE_DIR_MODE)
            os.utime(path, ns=(self.source_date_epoch * 1_000_000_000,) * 2)

    def _normalize_file_metadata(
        self, path: Path, is_executable: bool
    ) -> None:
        """Apply fixed mode and mtime to a regular file in reproducible mode."""
        if self.reproducible:
            mode = (
                _REPRODUCIBLE_EXECUTABLE_MODE
                if is_executable
                else _REPRODUCIBLE_FILE_MODE
            )
            path.chmod(mode)
            os.utime(path, ns=(self.source_date_epoch * 1_000_000_000,) * 2)

    def _ensure_parent_dir(self, target_path: Path) -> None:
        """Create a file's parent directory, tracking newly created dirs."""
        parent_folder = target_path.parent
        if parent_folder.exists():
            return

        if self.reproducible:
            # Create the full chain ourselves, so every directory, including
            # the intermediate ones, gets fixed mode and mtime.
            for directory in reversed(parent_folder.parents):
                if directory.exists() or directory == parent_folder.anchor:
                    continue
                directory.mkdir(parents=False, exist_ok=True)
                self._created_dirs.add(directory)
                self._normalize_dir_metadata(directory)
            parent_folder.mkdir(parents=False, exist_ok=True)
            self._created_dirs.add(parent_folder)
            self._normalize_dir_metadata(parent_folder)
        else:
            parent_folder.mkdir(parents=True)

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

        self._ensure_parent_dir(target_path)

        with target_path.open("wb") as f:
            hash_, size = copyfileobj_with_hashing(stream, f, self.hash_algorithm)

        if is_executable:
            if self.reproducible:
                target_path.chmod(_REPRODUCIBLE_EXECUTABLE_MODE)
            else:
                make_file_executable(target_path)

        self._normalize_file_metadata(target_path, is_executable)

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

            if not self.reproducible:
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

        if not self.reproducible:
            import compileall

            target_path = self._path_with_destdir(scheme, record.path)
            dir_path_to_embed = (
                Path(self.scheme_dict[scheme]) / record.path
            ).parent

            for level in self.bytecode_optimization_levels:
                compileall.compile_file(
                    target_path, optimize=level, quiet=1, ddir=dir_path_to_embed
                )
            return

        import importlib.util
        import py_compile

        # Physical location of the staged source file.
        target_path = self._path_with_destdir(scheme, record.path)
        if target_path.suffix != ".py" or not target_path.exists():
            return

        # Logical, final location of the source file. Unlike the staging
        # path, this does not embed a random temporary directory.
        logical_path = Path(self.scheme_dict[scheme]) / record.path

        for level in self.bytecode_optimization_levels:
            optimization = level if level >= 1 else ""
            pyc_path = Path(
                importlib.util.cache_from_source(
                    os.fspath(target_path), optimization=optimization
                )
            )
            py_compile.compile(
                file=os.fspath(target_path),
                cfile=os.fspath(pyc_path),
                dfile=os.fspath(logical_path),
                doraise=True,
                optimize=level,
                # Explicit hash-based invalidation: the resulting .pyc embeds
                # neither the source mtime nor the source size, so it does not
                # depend on SOURCE_DATE_EPOCH clamping or wall-clock time.
                invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
                quiet=2,
            )

            # py_compile creates __pycache__ and the .pyc with default
            # permissions and current mtime; normalize both.
            self._created_dirs.add(pyc_path.parent)
            self._normalize_dir_metadata(pyc_path.parent)
            self._normalize_file_metadata(pyc_path, is_executable=False)

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

        if self.reproducible:
            # Compilation and RECORD writes may have updated the mtime of
            # directories created earlier; normalize everything once more.
            for directory in self._created_dirs:
                if directory.is_dir():
                    self._normalize_dir_metadata(directory)
