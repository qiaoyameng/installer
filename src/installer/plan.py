"""Pure planning helpers for wheel installations.

The functions in this module calculate the files that an installation would
write, without modifying the destination, importing installed code, processing
``.pth`` files, or contacting an index.
"""

from __future__ import annotations

import base64
import hashlib
import os
import posixpath
import warnings
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Literal

from installer._core import _determine_scheme, _process_WHEEL_file
from installer.records import Hash, RecordEntry
from installer.scripts import Script
from installer.utils import (
    construct_record_file,
    fix_shebang,
    parse_entrypoints,
)

if TYPE_CHECKING:
    from installer.destinations import SchemeDictionaryDestination
    from installer.sources import WheelSource

__all__ = [
    "Conflict",
    "EntryPointSpec",
    "ExistingTargetEntry",
    "InstallationPlan",
    "PlannedFile",
    "PlannedOverride",
    "WheelDigest",
    "WheelInstallationRequest",
    "identical_installed_content",
    "plan_installation",
    "source_digest_matches",
    "target_conditions_are_current",
]

SourceKind = Literal["wheel-file", "additional-metadata", "entry-point", "record"]


@dataclass(frozen=True)
class WheelDigest:
    """A digest of a selected wheel file."""

    algorithm: str
    digest: str


@dataclass(frozen=True)
class EntryPointSpec:
    """The information in an ``entry_points.txt`` script declaration."""

    name: str
    module: str
    attr: str
    section: Literal["console", "gui"]


@dataclass(frozen=True)
class ExistingTargetEntry:
    """A filesystem entry already present at a planned path."""

    target: Path
    is_directory: bool


@dataclass(frozen=True)
class PlannedFile:
    """One file that installation would write.

    ``target`` is the absolute path after destination directory, scheme,
    shebang and entry-point rules have been applied. ``effective_digest`` is
    the digest of the bytes that would actually be written, so a script with
    a rewritten shebang does not merely reuse its source archive digest.
    """

    distribution: str
    source_path: str
    source_kind: SourceKind
    scheme: str
    target: Path
    physical_target: Path
    effective_digest: WheelDigest
    size: int
    is_executable: bool
    source_digest: WheelDigest | None = None
    shebang_rewritten: bool = False
    entry_point: EntryPointSpec | None = None
    replaces_existing: bool = False

    def shares_content_with(self, other: PlannedFile) -> bool:
        """Whether two plans write exactly interchangeable output."""
        return (
            self.effective_digest == other.effective_digest
            and self.size == other.size
            and self.is_executable == other.is_executable
            and self.shebang_rewritten == other.shebang_rewritten
            and self.source_kind == other.source_kind
            and self.entry_point == other.entry_point
        )


@dataclass(frozen=True)
class PlannedOverride:
    """A source member that additional installation metadata replaces."""

    distribution: str
    source_path: str
    replacement_source_path: str


@dataclass(frozen=True)
class Conflict:
    """A target path collision.

    A single prefix collision can involve both planned files and planned
    directories. Planned directories are represented by the file whose path
    would occupy the directory location.
    """

    target: Path
    planned_files: tuple[PlannedFile, ...]
    existing: ExistingTargetEntry | None = None

    @property
    def distributions(self) -> tuple[str, ...]:
        """Distributions involved in the collision."""
        return tuple(
            sorted(
                {
                    item.distribution
                    for item in self.planned_files
                }
            )
        )

    @property
    def source_paths(self) -> tuple[tuple[str, str], ...]:
        """Distribution and source path for every planned source member."""
        return tuple(
            sorted(
                (item.distribution, item.source_path)
                for item in self.planned_files
            )
        )


SharingPolicy = Callable[[PlannedFile, PlannedFile], bool]


@dataclass(frozen=True)
class WheelInstallationRequest:
    """A wheel selected for one deployment and its generated metadata."""

    source: WheelSource
    additional_metadata: dict[str, bytes] = field(default_factory=dict)
    wheel_digest: WheelDigest | None = None


@dataclass(frozen=True)
class InstallationPlan:
    """The complete file plan for one deployment."""

    files: tuple[PlannedFile, ...]
    conflicts: tuple[Conflict, ...]
    overrides: tuple[PlannedOverride, ...]
    wheel_digests: tuple[tuple[str, WheelDigest], ...]

    @property
    def has_conflicts(self) -> bool:
        """Whether applying the plan is unsafe without resolving a collision."""
        return bool(self.conflicts)


def identical_installed_content(left: PlannedFile, right: PlannedFile) -> bool:
    """Allow sharing only when installation output and provenance match.

    Equal transformed bytes alone are insufficient: executable bits, shebang
    rewriting, generated entry points, and generated metadata describe
    different installations even if their bytes happen to be identical.
    """
    return left.shares_content_with(right)


def source_digest_matches(path: os.PathLike[str], expected: WheelDigest) -> bool:
    """Check a selected wheel file against its planned source digest.

    This is intentionally separate from planning so callers can re-read the
    wheel immediately before applying the plan.
    """
    hasher = hashlib.new(expected.algorithm)
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    actual = base64.urlsafe_b64encode(hasher.digest()).decode("ascii").rstrip("=")
    return actual == expected.digest


def target_conditions_are_current(plan: InstallationPlan) -> bool:
    """Check that planned target preconditions still hold.

    This only reads filesystem metadata. A planned file may still overwrite an
    existing file when the destination used for planning allowed that.
    Existing directories and existing files occupying a parent path always
    remain incompatible.
    """
    checked_parents: set[Path] = set()
    for item in plan.files:
        target = item.physical_target
        if target.is_dir():
            return False
        if target.exists() or target.is_symlink():
            if not item.replaces_existing:
                return False

        for parent in target.parents:
            if parent in checked_parents:
                continue
            checked_parents.add(parent)
            if parent.is_file() or (parent.is_symlink() and not parent.is_dir()):
                return False
    return True


def _digest_bytes(
    data: bytes | BinaryIO, algorithm: str = "sha256"
) -> tuple[WheelDigest, int]:
    hasher = hashlib.new(algorithm)
    if isinstance(data, bytes):
        size = len(data)
        hasher.update(data)
    else:
        stream = data
        stream.seek(0)
        size = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)

    digest = base64.urlsafe_b64encode(hasher.digest()).decode("ascii").rstrip("=")
    return WheelDigest(algorithm, digest), size


def _logical_target(
    destination: SchemeDictionaryDestination, scheme: str, path: str
) -> Path:
    try:
        return destination._path_with_destdir(scheme, path)
    except KeyError:
        raise ValueError(f"Unknown installation scheme: {scheme}") from None


def _target_key(path: Path, case_sensitive: bool) -> tuple[str, ...]:
    text = os.path.normcase(os.fspath(path)) if not case_sensitive else os.fspath(path)
    return tuple(
        part.casefold() if not case_sensitive else part
        for part in Path(text).parts
    )


def _physical_path(path: Path) -> Path:
    """Resolve symlinks even when the planned file itself does not exist."""
    resolved_parent = Path(os.path.realpath(path.parent))
    return resolved_parent / path.name


def _existing_entries_for(
    target: Path, overwrite_existing: bool
) -> ExistingTargetEntry | None:
    if not target.exists() and not target.is_symlink():
        return None

    is_directory = target.is_dir()
    if is_directory:
        return ExistingTargetEntry(target, True)

    if not overwrite_existing:
        return ExistingTargetEntry(target, False)
    return None


class _PathTrie:
    def __init__(self) -> None:
        self._children: dict[str, _PathTrie] = {}
        self.files: list[PlannedFile] = []
        self.existing: ExistingTargetEntry | None = None

    def insert(
        self,
        key: Sequence[str],
        item: PlannedFile | ExistingTargetEntry,
    ) -> None:
        node = self
        for part in key:
            node = node._children.setdefault(part, _PathTrie())

        if isinstance(item, PlannedFile):
            node.files.append(item)
        else:
            node.existing = item

    def conflicts(self) -> Iterable[Conflict]:
        yield from self._conflicts()

    def _conflicts(self) -> Iterable[Conflict]:
        descendants = self._descendant_files()
        has_file_location = bool(self.files) or (
            self.existing is not None and not self.existing.is_directory
        )

        if has_file_location and descendants:
            files = tuple(dict.fromkeys((*self.files, *descendants)))
            existing = self.existing if self.existing is not None else None
            if self.files:
                target = self.files[0].physical_target
            elif self.existing is not None:
                target = self.existing.target
            else:  # pragma: no cover
                target = self._conflict_target(files, existing)
            yield Conflict(target, files, existing)
            return
        if self._exact_conflict():
            yield Conflict(
                self._conflict_target(tuple(self.files), self.existing),
                tuple(self.files),
                self.existing,
            )
            return
        if len(self.files) > 1:
            yield Conflict(
                self.files[0].physical_target,
                tuple(self.files),
                self._directory_existing(),
            )

        for child in self._children.values():
            yield from child._conflicts()

    def _exact_conflict(self) -> bool:
        if self.existing is None:
            return False
        if self.existing.is_directory:
            return bool(self.files)
        return any(not item.replaces_existing for item in self.files)

    def _directory_existing(self) -> ExistingTargetEntry | None:
        if self.existing is not None and self.existing.is_directory:
            return self.existing
        return None

    def _conflict_target(
        self,
        files: tuple[PlannedFile, ...],
        existing: ExistingTargetEntry | None,
    ) -> Path:
        if files:
            return files[0].physical_target
        if existing is not None:
            return existing.target
        return Path()

    def _descendant_files(self) -> tuple[PlannedFile, ...]:
        files: list[PlannedFile] = []
        for child in self._children.values():
            files.extend(child.files)
            files.extend(child._descendant_files())
        return tuple(dict.fromkeys(files))


def _filter_shareable_conflicts(
    conflicts: Iterable[Conflict], sharing_policy: SharingPolicy
) -> tuple[Conflict, ...]:
    result: list[Conflict] = []
    for conflict in conflicts:
        is_prefix = (
            len({item.physical_target for item in conflict.planned_files}) > 1
        )
        if is_prefix or conflict.existing is not None:
            result.append(conflict)
            continue

        files = conflict.planned_files
        shareable = (
            all(sharing_policy(left, right) for left, right in combinations(files, 2))
            if len(files) > 1
            else False
        )
        if not shareable:
            result.append(conflict)
    return tuple(
        sorted(result, key=lambda item: (os.fspath(item.target), len(item.target.parts)))
    )


def _nearest_existing_parent_file(path: Path) -> ExistingTargetEntry | None:
    for parent in path.parents:
        if parent.is_file() or (parent.is_symlink() and not parent.is_dir()):
            return ExistingTargetEntry(parent, False)
    return None


def _planned_file(
    *,
    distribution: str,
    source_path: str,
    source_kind: SourceKind,
    scheme: str,
    path: str,
    data: bytes,
    is_executable: bool,
    destination: SchemeDictionaryDestination,
    source_digest: WheelDigest | None = None,
    shebang_rewritten: bool = False,
    entry_point: EntryPointSpec | None = None,
    check_existing: bool,
) -> PlannedFile:
    target = _logical_target(destination, scheme, path)
    physical_target = _physical_path(target)
    digest, size = _digest_bytes(data, destination.hash_algorithm)
    replaces_existing = False

    if check_existing:
        if physical_target.exists() or physical_target.is_symlink():
            replaces_existing = (
                not physical_target.is_dir() and destination.overwrite_existing
            )

    return PlannedFile(
        distribution=distribution,
        source_path=source_path,
        source_kind=source_kind,
        scheme=scheme,
        target=target,
        physical_target=physical_target,
        effective_digest=digest,
        size=size,
        is_executable=is_executable,
        source_digest=source_digest,
        shebang_rewritten=shebang_rewritten,
        entry_point=entry_point,
        replaces_existing=replaces_existing,
    )


def _plan_entry_points(
    source: WheelSource,
    destination: SchemeDictionaryDestination,
    *,
    check_existing: bool,
) -> list[PlannedFile]:
    if "entry_points.txt" not in source.dist_info_filenames:
        return []

    planned = []
    text = source.read_dist_info("entry_points.txt")
    for name, module, attr, section in parse_entrypoints(text):
        spec = EntryPointSpec(name, module, attr, section)
        script = Script(name, module, attr, section)
        script_name, data = script.generate(
            destination.interpreter, destination.script_kind
        )
        source_path = (
            f"{source.dist_info_dir}/entry_points.txt:{section}_scripts:{name}"
        )
        planned.append(
            _planned_file(
                distribution=source.distribution,
                source_path=source_path,
                source_kind="entry-point",
                scheme="scripts",
                path=script_name,
                data=data,
                is_executable=True,
                destination=destination,
                entry_point=spec,
                check_existing=check_existing,
            )
        )
    return planned


def _record_for_item(
    item: PlannedFile, destination: SchemeDictionaryDestination
) -> RecordEntry:
    scheme_root = _logical_target(destination, item.scheme, "")
    relative_path = item.target.relative_to(scheme_root).as_posix()
    return RecordEntry(
        relative_path,
        Hash(item.effective_digest.algorithm, item.effective_digest.digest),
        item.size,
    )


def _plan_request(
    request: WheelInstallationRequest,
    destination: SchemeDictionaryDestination,
    *,
    check_existing: bool,
) -> tuple[tuple[PlannedFile, ...], tuple[PlannedOverride, ...]]:
    source = request.source
    root_scheme = _process_WHEEL_file(source)
    record_file_path = posixpath.join(source.dist_info_dir, "RECORD")
    planned: list[PlannedFile] = []
    overrides: list[PlannedOverride] = []
    additional_names = set(request.additional_metadata)

    planned.extend(
        _plan_entry_points(source, destination, check_existing=check_existing)
    )

    for record_elements, stream, is_executable in source.get_contents():
        source_record = RecordEntry.from_elements(*record_elements)
        source_path = source_record.path

        if source_path == record_file_path:
            overrides.append(
                PlannedOverride(source.distribution, source_path, "<generated RECORD>")
            )
            continue

        if "__pycache__" in source_path.split("/")[:-1]:
            warnings.warn(
                (
                    f"Skip installing {source_path} from {source.distribution}."
                    " Installing files in a __pycache__ directory poses a security risk."
                    " __pycache__ directories should not be included in wheels."
                    f" This is probably an issue in the build process of '{source.distribution}'."
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        original_data = stream.read()
        source_digest, _ = _digest_bytes(original_data)
        effective_data = original_data
        shebang_rewritten = False
        scheme, destination_path = _determine_scheme(
            path=source_path,
            source=source,
            root_scheme=root_scheme,
        )
        parent, filename = posixpath.split(destination_path)
        if (
            scheme == root_scheme
            and parent == source.dist_info_dir
            and filename in additional_names
        ):
            overrides.append(
                PlannedOverride(
                    source.distribution,
                    source_path,
                    f"<additional-metadata>/{filename}",
                )
            )
            continue

        if scheme == "scripts":
            stream.seek(0)
            with fix_shebang(stream, destination.interpreter) as transformed:
                effective_data = transformed.read()
            shebang_rewritten = effective_data != original_data

        planned.append(
            _planned_file(
                distribution=source.distribution,
                source_path=source_path,
                source_kind="wheel-file",
                scheme=scheme,
                path=destination_path,
                data=effective_data,
                is_executable=is_executable,
                source_digest=source_digest,
                destination=destination,
                shebang_rewritten=shebang_rewritten,
                check_existing=check_existing,
            )
        )

    for filename, contents in request.additional_metadata.items():
        if filename == "RECORD":
            overrides.append(
                PlannedOverride(
                    source.distribution,
                    posixpath.join(source.dist_info_dir, filename),
                    "<generated RECORD>",
                )
            )
            continue

        destination_path = posixpath.join(source.dist_info_dir, filename)
        planned.append(
            _planned_file(
                distribution=source.distribution,
                source_path=f"<additional-metadata>/{filename}",
                source_kind="additional-metadata",
                scheme=root_scheme,
                path=destination_path,
                data=contents,
                is_executable=False,
                destination=destination,
                check_existing=check_existing,
            )
        )

    records = [
        (item.scheme, _record_for_item(item, destination)) for item in planned
    ]
    with construct_record_file(
        records,
        lambda scheme: destination.record_prefix_for_scheme(scheme, root_scheme),
    ) as record_stream:
        record_data = record_stream.read()

    planned.append(
        _planned_file(
            distribution=source.distribution,
            source_path="<generated RECORD>",
            source_kind="record",
            scheme=root_scheme,
            path=record_file_path,
            data=record_data,
            is_executable=False,
            destination=destination,
            check_existing=check_existing,
        )
    )

    return tuple(planned), tuple(overrides)


def plan_installation(
    requests: Sequence[WheelInstallationRequest],
    destination: SchemeDictionaryDestination,
    *,
    sharing_policy: SharingPolicy | None = None,
    case_sensitive: bool | None = None,
    check_existing: bool = True,
) -> InstallationPlan:
    """Compute a deployment's file writes and target path conflicts.

    :param requests: selected wheels and per-wheel additional metadata.
    :param destination: scheme directories and platform script settings.
    :param sharing_policy: predicate allowing two exact target writes to be
        served from one physical output; default treats every duplicate as a
        conflict.
    :param case_sensitive: whether the target filesystem distinguishes path
        case. Defaults to case-insensitive behavior for Windows launchers.
    :param check_existing: inspect the current filesystem for files,
        directories, symlinks and parent-file conflicts.
    """
    if case_sensitive is None:
        case_sensitive = destination.script_kind == "posix"

    files: list[PlannedFile] = []
    overrides: list[PlannedOverride] = []
    wheel_digests: list[tuple[str, WheelDigest]] = []
    trie = _PathTrie()
    policy = sharing_policy or (lambda left, right: False)

    for request in requests:
        planned, request_overrides = _plan_request(
            request,
            destination,
            check_existing=check_existing,
        )
        files.extend(planned)
        overrides.extend(request_overrides)
        if request.wheel_digest is not None:
            wheel_digests.append((request.source.distribution, request.wheel_digest))

        for item in planned:
            physical_target = _physical_path(item.target)
            key = _target_key(physical_target, case_sensitive)
            trie.insert(key, item)

            if check_existing:
                exact = _existing_entries_for(
                    physical_target, destination.overwrite_existing
                )
                if exact is not None:
                    trie.insert(key, exact)

                parent_file = _nearest_existing_parent_file(physical_target)
                if parent_file is not None:
                    parent_key = _target_key(parent_file.target, case_sensitive)
                    trie.insert(parent_key, parent_file)

    conflicts = _filter_shareable_conflicts(trie.conflicts(), policy)
    return InstallationPlan(
        files=tuple(files),
        conflicts=conflicts,
        overrides=tuple(overrides),
        wheel_digests=tuple(wheel_digests),
    )
