"""Two-phase uninstallation support for installed wheel distributions."""

import csv
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from importlib.util import MAGIC_NUMBER
from pathlib import Path, PurePosixPath
from typing import Literal, TypeAlias

from installer.exceptions import UninstallPlanChanged, UninstallPlanError
from installer.records import InvalidRecordEntry, RecordEntry, parse_record_file

__all__ = [
    "FileFingerprint",
    "PlannedDirectory",
    "PlannedFile",
    "UninstallPlan",
    "UninstallResult",
    "apply_uninstall",
    "plan_uninstall",
]

StrPath: TypeAlias = str | os.PathLike[str]
UnverifiedPolicy: TypeAlias = Literal["record", "all"]
_FILE_HASH_CHUNK_SIZE = 1024 * 1024
_VALID_BYTECODE_LEVELS = (0, 1, 2)


@dataclass(frozen=True)
class FileFingerprint:
    """Filesystem and content metadata used to detect changes after planning."""

    mode: int
    size: int
    mtime_ns: int
    inode: int
    device: int
    sha256: str


@dataclass(frozen=True)
class PlannedFile:
    """A path considered while constructing an uninstall plan."""

    path: Path
    action: Literal["delete", "retain"]
    reason: str
    fingerprint: FileFingerprint | None
    owners: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlannedDirectory:
    """An empty or provably owned directory considered while planning."""

    path: Path
    action: Literal["remove", "retain"]
    reason: str


@dataclass(frozen=True)
class UninstallPlan:
    """A read-only description of what an uninstall apply would do."""

    dist_info: Path
    record_file: Path
    install_roots: tuple[Path, ...]
    files: tuple[PlannedFile, ...]
    directories: tuple[PlannedDirectory, ...]
    blockers: tuple[str, ...]
    unverified_policy: UnverifiedPolicy = "record"
    bytecode_optimization_levels: tuple[int, ...] = ()
    bytecode_cache_tag: str | None = None

    @property
    def files_to_delete(self) -> tuple[PlannedFile, ...]:
        """Files that apply would delete if the plan remains valid."""
        return tuple(file for file in self.files if file.action == "delete")

    @property
    def blocked(self) -> bool:
        """Whether a global problem prevents apply from running."""
        return bool(self.blockers)

    def signature(self) -> tuple[object, ...]:
        """Return a comparable representation of the planned filesystem state."""
        return (
            tuple(
                (
                    str(file.path),
                    file.action,
                    file.reason,
                    file.fingerprint,
                    file.owners,
                )
                for file in self.files
            ),
            tuple(
                (str(directory.path), directory.action)
                for directory in self.directories
            ),
            self.blockers,
        )


@dataclass(frozen=True)
class UninstallResult:
    """The outcome of applying an uninstall plan."""

    removed_files: tuple[Path, ...]
    removed_directories: tuple[Path, ...]
    failures: tuple[tuple[Path, str], ...]
    staged_directory: Path | None = None
    rolled_back: bool = False


def _canonical_root(path: StrPath) -> Path:
    root = Path(path).expanduser().resolve(strict=False)
    if not root.exists():
        raise UninstallPlanError(f"Install root does not exist: {root}")
    if not root.is_dir() or root.is_symlink():
        raise UninstallPlanError(f"Install root is not a real directory: {root}")
    return root


def _canonical_roots(paths: Collection[StrPath]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for path in paths:
        root = _canonical_root(path)
        if root not in roots:
            roots.append(root)
    if not roots:
        raise UninstallPlanError("At least one allowed install root is required")
    return tuple(roots)


def _lexical_path(base: Path, relative_path: str) -> Path | None:
    if "\x00" in relative_path:
        return None

    posix_path = PurePosixPath(relative_path)
    if posix_path.is_absolute() or not posix_path.parts:
        return None

    path = Path(base).joinpath(*posix_path.parts)
    if not path.is_absolute():
        return None
    return Path(os.path.abspath(path))  # noqa: PTH100


def _root_for_path(path: Path, roots: Sequence[Path]) -> int | None:
    for index, root in enumerate(roots):
        if path == root or path.is_relative_to(root):
            return index
    return None


def _has_symlink_below_root(path: Path, root: Path) -> bool:
    if path.is_symlink():
        return True
    parent = path.parent
    while parent != root:
        if parent.is_symlink():
            return True
        parent = parent.parent
    return False


def _fingerprint(path: Path) -> FileFingerprint:
    stat_result = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(_FILE_HASH_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return FileFingerprint(
        mode=stat.S_IFMT(stat_result.st_mode),
        size=stat_result.st_size,
        mtime_ns=stat_result.st_mtime_ns,
        inode=stat_result.st_ino,
        device=stat_result.st_dev,
        sha256=digest.hexdigest(),
    )


def _record_entries(path: Path) -> tuple[tuple[RecordEntry, ...], str | None]:
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            rows = list(parse_record_file(stream))
        entries = tuple(RecordEntry.from_elements(*row) for row in rows)
    except (OSError, UnicodeError, csv.Error, InvalidRecordEntry) as exc:
        return (), f"Unable to read RECORD {path}: {exc}"

    seen: set[str] = set()
    duplicates: set[str] = set()
    for entry in entries:
        normalized = entry.path.replace("\\", "/")
        if normalized in seen:
            duplicates.add(normalized)
        seen.add(normalized)

    if duplicates:
        joined = ", ".join(sorted(duplicates))
        return entries, f"RECORD {path} contains duplicate paths: {joined}"
    return entries, None


def _safe_record_path(
    dist_info: Path,
    relative_path: str,
    roots: Sequence[Path],
) -> tuple[Path | None, int | None, str | None]:
    path = _lexical_path(dist_info.parent, relative_path)
    if path is None:
        return None, None, f"invalid relative RECORD path: {relative_path!r}"

    root_index = _root_for_path(path, roots)
    if root_index is None:
        return path, None, "path is outside of the allowed install roots"
    return path, root_index, None


def _read_ownership(
    roots: Sequence[Path],
) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...]]:
    record_files: dict[Path, Path] = {}
    blockers: list[str] = []

    for root in roots:
        try:
            children = list(root.iterdir())
        except OSError as exc:
            blockers.append(f"Unable to scan install root {root}: {exc}")
            continue

        for child in children:
            if not child.name.endswith(".dist-info"):
                continue
            if child.is_symlink():
                blockers.append(
                    f"Symlinked dist-info cannot establish ownership: {child}"
                )
                continue
            try:
                is_directory = child.is_dir()
            except OSError as exc:
                blockers.append(f"Unable to inspect {child}: {exc}")
                continue
            if not is_directory:
                continue
            record_files[child.resolve(strict=False) / "RECORD"] = child.resolve(
                strict=False
            )

    owners: dict[str, list[str]] = defaultdict(list)
    for record_file, dist_info in sorted(record_files.items()):
        entries, error = _record_entries(record_file)
        if error is not None:
            blockers.append(error)
            continue

        for entry in entries:
            path, _, path_error = _safe_record_path(dist_info, entry.path, roots)
            if path is None or path_error is not None:
                blockers.append(f"{dist_info.name}: {path_error}: {entry.path!r}")
                continue
            owners[os.path.normcase(str(path))].append(dist_info.name)

    deduped = {
        key: tuple(sorted(set(names))) for key, names in owners.items()
    }
    return deduped, tuple(dict.fromkeys(blockers))


def _entry_matches(entry: RecordEntry, path: Path) -> tuple[bool, str | None]:
    try:
        with path.open("rb") as stream:
            matches = entry.validate_stream(stream)
    except OSError as exc:
        return False, str(exc)
    return matches, None


def _plan_record_file(
    entry: RecordEntry,
    path: Path,
    root_index: int,
    roots: Sequence[Path],
    record_file: Path,
    owners: Mapping[str, tuple[str, ...]],
    unverified_policy: UnverifiedPolicy,
) -> PlannedFile:
    entry_owners = owners.get(os.path.normcase(str(path)), ())
    if len(entry_owners) > 1:
        return PlannedFile(
            path,
            "retain",
            "shared-by-other-distribution",
            None,
            entry_owners,
        )

    try:
        if _has_symlink_below_root(path, roots[root_index]):
            return PlannedFile(path, "retain", "symlink", None, entry_owners)
        if not path.exists():
            return PlannedFile(path, "retain", "missing", None, entry_owners)
        if not path.is_file():
            return PlannedFile(path, "retain", "not-a-regular-file", None, entry_owners)
    except OSError as exc:
        return PlannedFile(
            path,
            "retain",
            f"unable-to-inspect: {exc}",
            None,
            entry_owners,
        )

    if entry.hash_ is None and entry.size is None:
        try:
            fingerprint = _fingerprint(path)
        except OSError as exc:
            return PlannedFile(
                path,
                "retain",
                f"unable-to-fingerprint: {exc}",
                None,
                entry_owners,
            )
        if path != record_file and unverified_policy == "record":
            return PlannedFile(
                path,
                "retain",
                "record-entry-without-hash-or-size",
                fingerprint,
                entry_owners,
            )
        reason = (
            "record-manifest"
            if path == record_file
            else "record-unverified-allowed"
        )
        return PlannedFile(path, "delete", reason, fingerprint, entry_owners)

    matches, validation_error = _entry_matches(entry, path)
    if validation_error is not None:
        return PlannedFile(path, "retain", "unable-to-verify", None, entry_owners)
    if not matches:
        fingerprint = _fingerprint(path)
        return PlannedFile(path, "retain", "modified", fingerprint, entry_owners)

    return PlannedFile(
        path,
        "delete",
        "record-verified",
        _fingerprint(path),
        entry_owners,
    )


def _bytecode_candidates(
    files: Sequence[PlannedFile],
    owners: Mapping[str, tuple[str, ...]],
    roots: Sequence[Path],
    levels: Collection[int],
    cache_tag_filter: str | None,
) -> tuple[list[PlannedFile], tuple[str, ...]]:
    deleted_sources = {file.path for file in files if file.action == "delete"}
    candidates: list[PlannedFile] = []
    blockers: list[str] = []
    seen: set[Path] = set()

    for source in sorted(deleted_sources):
        if source.suffix != ".py":
            continue
        root_index = _root_for_path(source, roots)
        if root_index is None:
            continue

        cache_directory = source.parent / "__pycache__"
        if cache_directory.is_symlink() or not cache_directory.is_dir():
            continue

        pattern = re.compile(
            rf"^{re.escape(source.stem)}\.(?P<tag>[^.]+)"
            rf"(?:\.opt-(?P<level>[012]))?\.pyc$"
        )
        try:
            children = list(cache_directory.iterdir())
        except OSError as exc:
            blockers.append(
                f"Unable to scan bytecode directory {cache_directory}: {exc}"
            )
            continue

        for path in sorted(children):
            match = pattern.match(path.name)
            if match is None or path in seen:
                continue
            seen.add(path)

            level_text = match.group("level")
            level = int(level_text) if level_text is not None else 0
            if level not in levels:
                continue
            if path in deleted_sources or not path.exists():
                continue
            try:
                unsafe_bytecode = _has_symlink_below_root(path, roots[root_index])
                is_bytecode_file = path.is_file()
            except OSError as exc:
                blockers.append(f"Unable to inspect bytecode {path}: {exc}")
                continue
            if unsafe_bytecode or not is_bytecode_file:
                continue

            entry_owners = owners.get(os.path.normcase(str(path)), ())
            if cache_tag_filter is not None and match.group("tag") != cache_tag_filter:
                candidates.append(
                    PlannedFile(
                        path,
                        "retain",
                        "bytecode-abi-mismatch",
                        None,
                        entry_owners,
                    )
                )
                continue
            if len(entry_owners) > 1:
                candidates.append(
                    PlannedFile(
                        path,
                        "retain",
                        "shared-by-other-distribution",
                        None,
                        entry_owners,
                    )
                )
                continue
            if not _bytecode_matches_source(path, source):
                candidates.append(
                    PlannedFile(
                        path,
                        "retain",
                        "bytecode-source-mismatch",
                        None,
                        entry_owners,
                    )
                )
                continue
            candidates.append(
                PlannedFile(
                    path,
                    "delete",
                    f"generated-bytecode-opt-{level}",
                    _fingerprint(path),
                    entry_owners,
                )
            )
    return candidates, tuple(dict.fromkeys(blockers))


def _bytecode_matches_source(path: Path, source: Path) -> bool:
    try:
        with path.open("rb") as stream:
            header = stream.read(16)
        source_stat = source.stat()
        if len(header) != 16:
            return False
        if not header.startswith(MAGIC_NUMBER):
            return False
        flags = int.from_bytes(header[4:8], "little")
        if flags:
            return False
        bytecode_mtime = int.from_bytes(header[8:12], "little")
        bytecode_source_size = int.from_bytes(header[12:16], "little")
        return (
            bytecode_mtime == int(source_stat.st_mtime)
            and bytecode_source_size == source_stat.st_size
        )
    except OSError:
        return False


def _plan_directories(
    files: Sequence[PlannedFile],
    roots: Sequence[Path],
) -> tuple[PlannedDirectory, ...]:
    deleted = {file.path for file in files if file.action == "delete"}
    retained = {file.path for file in files if file.action == "retain"}
    candidates: dict[Path, int] = {}
    for path in set(deleted) | retained:
        root_index = _root_for_path(path, roots)
        if root_index is None:
            continue
        parent = path.parent
        while parent != roots[root_index]:
            candidates[parent] = root_index
            parent = parent.parent

    expanded_candidates = dict(candidates)
    unreadable_directories: dict[Path, str] = {}
    for directory, root_index in candidates.items():
        if _has_symlink_below_root(
            directory, roots[root_index]
        ) or not directory.is_dir():
            continue
        try:
            descendants = list(directory.rglob("*"))
        except OSError as exc:
            unreadable_directories[directory] = f"unable-to-scan: {exc}"
            continue
        for child in descendants:
            child_root_index = _root_for_path(child, roots)
            if child_root_index is None:
                continue
            try:
                is_directory = not child.is_symlink() and child.is_dir()
                safe_directory = is_directory and not _has_symlink_below_root(
                    child, roots[child_root_index]
                )
            except OSError:
                continue
            if safe_directory:
                expanded_candidates[child] = child_root_index

    plans_by_path: dict[Path, PlannedDirectory] = {}
    for directory, reason in unreadable_directories.items():
        planned_directory = PlannedDirectory(directory, "retain", reason)
        plans_by_path[directory] = planned_directory

    for directory in sorted(expanded_candidates, key=lambda item: len(item.parts)):
        plans_by_path[directory] = PlannedDirectory(
            directory, "remove", "empty-directory"
        )

    plans: list[PlannedDirectory] = []
    for directory, root_index in sorted(
        expanded_candidates.items(),
        key=lambda item: len(item[0].parts),
        reverse=True,
    ):
        if _has_symlink_below_root(directory, roots[root_index]):
            plans.append(PlannedDirectory(directory, "retain", "symlink"))
            continue
        if not directory.exists():
            plans.append(PlannedDirectory(directory, "retain", "missing"))
            continue
        if not directory.is_dir():
            plans.append(PlannedDirectory(directory, "retain", "not-a-directory"))
            continue

        removable = True
        reason = "empty-directory"
        if directory in unreadable_directories:
            planned_directory = PlannedDirectory(
                directory, "retain", unreadable_directories[directory]
            )
            plans_by_path[directory] = planned_directory
            plans.append(planned_directory)
            continue

        try:
            children = list(directory.rglob("*"))
        except OSError as exc:
            planned_directory = PlannedDirectory(
                directory, "retain", f"unable-to-scan: {exc}"
            )
            plans_by_path[directory] = planned_directory
            plans.append(planned_directory)
            continue
        if children:
            reason = "owned-files-removed"
        for child in children:
            child_root_index = _root_for_path(child, roots)
            if child_root_index is None:
                removable = False
                reason = "contains-path-outside-roots"
                break
            if _has_symlink_below_root(child, roots[child_root_index]):
                removable = False
                reason = "contains-symlink"
                break
            if not child.is_symlink() and child.is_dir():
                child_plan = plans_by_path.get(child)
                if child_plan is not None and child_plan.action == "retain":
                    removable = False
                    reason = child_plan.reason
                    break
            elif child in retained:
                removable = False
                reason = "contains-retained-file"
                break
            elif child not in deleted:
                removable = False
                reason = "contains-unowned-file"
                break

        planned_directory = PlannedDirectory(
            directory,
            "remove" if removable else "retain",
            reason,
        )
        plans_by_path[directory] = planned_directory
        plans.append(planned_directory)
    return tuple(sorted(plans, key=lambda directory: len(directory.path.parts)))


def plan_uninstall(
    dist_info: StrPath,
    allowed_install_roots: Collection[StrPath],
    *,
    unverified_policy: UnverifiedPolicy = "record",
    bytecode_optimization_levels: Collection[int] = (0, 1),
    bytecode_cache_tag: str | None = None,
) -> UninstallPlan:
    """Create a conservative uninstall plan without deleting anything.

    :param dist_info: Installed ``.dist-info`` directory containing ``RECORD``.
    :param allowed_install_roots: Roots which RECORD-relative paths are allowed in.
    :param unverified_policy: ``record`` only deletes unsigned RECORD itself; ``all``
        also deletes entries with neither hash nor size after explicit opt-in.
    :param bytecode_optimization_levels: Optimization tags for proven ``.pyc`` files.
    :param bytecode_cache_tag: Bytecode ABI tag; defaults to this interpreter's tag.
    """
    if unverified_policy not in ("record", "all"):
        raise UninstallPlanError(
            "unverified_policy must be either 'record' or 'all'"
        )
    invalid_levels = sorted(
        set(bytecode_optimization_levels) - set(_VALID_BYTECODE_LEVELS)
    )
    if invalid_levels:
        raise UninstallPlanError(
            f"Invalid bytecode optimization levels: {invalid_levels}"
        )
    levels = tuple(dict.fromkeys(bytecode_optimization_levels))
    cache_tag = bytecode_cache_tag or sys.implementation.cache_tag

    roots = _canonical_roots(allowed_install_roots)
    canonical_dist_info = (
        Path(dist_info).expanduser().resolve(strict=False)
    )
    dist_info_name = canonical_dist_info.name
    if (
        not dist_info_name.endswith(".dist-info")
        or len(dist_info_name) <= len(".dist-info")
        or "-" not in dist_info_name[: -len(".dist-info")]
    ):
        raise UninstallPlanError(
            f"Not a valid .dist-info directory: {canonical_dist_info}"
        )
    if (
        not canonical_dist_info.exists()
        or not canonical_dist_info.is_dir()
    ):
        raise UninstallPlanError(
            f"Missing dist-info directory: {canonical_dist_info}"
        )
    if canonical_dist_info.is_symlink() or _root_for_path(
        canonical_dist_info, roots
    ) is None:
        raise UninstallPlanError(
            f"dist-info is not a real directory inside an allowed install root: "
            f"{canonical_dist_info}"
        )

    record_file = canonical_dist_info / "RECORD"
    if (
        not record_file.exists()
        or not record_file.is_file()
        or record_file.is_symlink()
    ):
        raise UninstallPlanError(f"Missing real RECORD file: {record_file}")

    blockers: list[str] = []
    current_entries, current_error = _record_entries(record_file)
    if current_error is not None:
        blockers.append(current_error)

    owners, owner_blockers = _read_ownership(roots)
    blockers.extend(owner_blockers)
    blockers = list(dict.fromkeys(blockers))

    file_plans: list[PlannedFile] = []
    seen_paths: set[Path] = set()
    for entry in current_entries:
        path, root_index, path_error = _safe_record_path(
            canonical_dist_info, entry.path, roots
        )
        if path is None or root_index is None or path_error is not None:
            blockers.append(
                f"{canonical_dist_info.name}: {path_error}: {entry.path!r}"
            )
            continue
        if path in seen_paths:
            blockers.append(
                f"{canonical_dist_info.name}: duplicate RECORD path: {entry.path!r}"
            )
            continue
        seen_paths.add(path)
        file_plans.append(
            _plan_record_file(
                entry=entry,
                path=path,
                root_index=root_index,
                roots=roots,
                record_file=record_file,
                owners=owners,
                unverified_policy=unverified_policy,
            )
        )

    if levels and not current_error:
        bytecode_plans, bytecode_blockers = _bytecode_candidates(
            file_plans, owners, roots, levels, cache_tag
        )
        file_plans.extend(bytecode_plans)
        blockers.extend(bytecode_blockers)

    directories = _plan_directories(file_plans, roots)
    return UninstallPlan(
        dist_info=canonical_dist_info,
        record_file=record_file,
        install_roots=roots,
        files=tuple(sorted(file_plans, key=lambda file: str(file.path))),
        directories=directories,
        blockers=tuple(dict.fromkeys(blockers)),
        unverified_policy=unverified_policy,
        bytecode_optimization_levels=levels,
        bytecode_cache_tag=cache_tag,
    )


def _fresh_plan(plan: UninstallPlan) -> UninstallPlan:
    return plan_uninstall(
        plan.dist_info,
        plan.install_roots,
        unverified_policy=plan.unverified_policy,
        bytecode_optimization_levels=plan.bytecode_optimization_levels,
        bytecode_cache_tag=plan.bytecode_cache_tag,
    )


def _stage_path(staging_root: Path, path: Path, roots: Sequence[Path]) -> Path:
    root_index = _root_for_path(path, roots)
    assert root_index is not None
    relative = path.relative_to(roots[root_index])
    return staging_root / f"root-{root_index}" / relative


def _remove_directories(
    plan: UninstallPlan,
) -> tuple[tuple[Path, ...], tuple[tuple[Path, str], ...]]:
    removed: list[Path] = []
    failures: list[tuple[Path, str]] = []
    for directory in sorted(
        (item.path for item in plan.directories if item.action == "remove"),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        if directory.is_symlink() or not directory.is_dir():
            failures.append((directory, "directory was replaced after planning"))
            continue
        try:
            directory.rmdir()
        except OSError as exc:
            failures.append((directory, str(exc)))
        else:
            removed.append(directory)
    return tuple(removed), tuple(failures)


def _rollback_staging(
    moved: Sequence[tuple[Path, Path]], roots: Sequence[Path]
) -> tuple[tuple[tuple[Path, str], ...], tuple[Path, ...]]:
    failures: list[tuple[Path, str]] = []
    restored: list[Path] = []
    for original, staged in reversed(moved):
        try:
            original.parent.mkdir(parents=True, exist_ok=True)
            os.rename(staged, original)
            restored.append(original)
        except OSError as exc:
            failures.append((original, f"rollback failed: {exc}"))
    return tuple(failures), tuple(restored)


def _move_to_stage(path: Path, staged: Path) -> None:
    """Move one regular file into staging without following links."""
    staged.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.rename(path, staged)
    except OSError as exc:
        if getattr(exc, "errno", None) != 18:  # EXDEV: cross-device link.
            raise
        shutil.copy2(path, staged, follow_symlinks=False)
        os.unlink(path)


def _apply_staged(
    plan: UninstallPlan,
    staging_parent: StrPath | None,
) -> UninstallResult:
    parent = (
        Path(staging_parent or tempfile.gettempdir())
        .expanduser()
        .resolve(strict=False)
    )
    for root in plan.install_roots:
        if parent == root or parent.is_relative_to(root):
            raise UninstallPlanError(
                f"Staging directory must not be inside an install root: {parent}"
            )
    parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f"installer-uninstall-{plan.dist_info.name}-",
            dir=parent,
        )
    )

    moved: list[tuple[Path, Path]] = []
    for planned_file in sorted(
        plan.files_to_delete, key=lambda file: len(file.path.parts), reverse=True
    ):
        path = planned_file.path
        root_index = _root_for_path(path, plan.install_roots)
        assert root_index is not None
        if _has_symlink_below_root(path, plan.install_roots[root_index]):
            failures, _ = _rollback_staging(moved, plan.install_roots)
            return UninstallResult(
                (),
                (),
                ((path, "symlink introduced after planning"), *failures),
                staging_root,
                True,
            )
        staged = _stage_path(staging_root, path, plan.install_roots)
        try:
            _move_to_stage(path, staged)
        except OSError as exc:
            failures, _ = _rollback_staging(moved, plan.install_roots)
            return UninstallResult(
                (),
                (),
                ((path, str(exc)), *failures),
                staging_root,
                True,
            )
        moved.append((path, staged))

    removed_directories, directory_failures = _remove_directories(plan)
    if directory_failures:
        rollback_failures, _ = _rollback_staging(moved, plan.install_roots)
        return UninstallResult(
            (),
            (),
            (*directory_failures, *rollback_failures),
            staging_root,
            True,
        )

    try:
        shutil.rmtree(staging_root)
    except OSError as exc:
        return UninstallResult(
            tuple(path for path, _ in moved),
            removed_directories,
            ((staging_root, f"unable to remove staging directory: {exc}"),),
            staging_root,
        )
    return UninstallResult(tuple(path for path, _ in moved), removed_directories, ())


def apply_uninstall(
    plan: UninstallPlan,
    *,
    staging_directory: StrPath | None = None,
) -> UninstallResult:
    """Recheck and apply an uninstall plan.

    This is not an all-or-nothing operation without staging. With staging, file
    deletion is rolled back if a later removal fails; a crashed process leaves
    files in the returned staging directory for manual recovery.
    """
    if plan.blocked:
        raise UninstallPlanError("Refusing to apply a blocked uninstall plan")

    current = _fresh_plan(plan)
    if current.blocked:
        raise UninstallPlanChanged("Filesystem now contains a blocking condition")
    if (
        current.dist_info != plan.dist_info
        or current.record_file != plan.record_file
        or current.install_roots != plan.install_roots
        or current.signature() != plan.signature()
    ):
        raise UninstallPlanChanged("Uninstall plan is stale; create a new plan")

    if staging_directory is not None:
        return _apply_staged(plan, staging_directory)

    removed_files: list[Path] = []
    failures: list[tuple[Path, str]] = []
    for planned_file in sorted(
        plan.files_to_delete, key=lambda file: len(file.path.parts), reverse=True
    ):
        try:
            planned_file.path.unlink()
        except OSError as exc:
            failures.append((planned_file.path, str(exc)))
        else:
            removed_files.append(planned_file.path)

    removed_directories, directory_failures = _remove_directories(plan)
    return UninstallResult(
        tuple(removed_files),
        removed_directories,
        tuple(failures) + directory_failures,
    )
