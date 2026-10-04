"""Purely calculate the file layout that wheel installation would produce."""

from __future__ import annotations

import base64
import hashlib
import os
import posixpath
import warnings
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from installer._core import _determine_scheme, _process_WHEEL_file
from installer.records import Hash, RecordEntry
from installer.scripts import Script
from installer.sources import WheelSource
from installer.utils import Scheme, fix_shebang, parse_entrypoints

if TYPE_CHECKING:
    from installer.scripts import LauncherKind

__all__ = [
    "DuplicatePolicy",
    "InstallationPlan",
    "PlannedDistribution",
    "PlannedFile",
    "PlannedFileKind",
    "PlanConflict",
    "PlanConflictReason",
    "TargetCondition",
    "WheelPlanRequest",
    "allow_identical_files",
    "plan_installation",
]

_COPY_BUFSIZE = 1024 * 1024
_EXISTING_SOURCE_PATH = "<existing target>"


@dataclass(frozen=True)
class TargetCondition:
    """Caller-known condition of a path in the destination."""

    path: str | os.PathLike[str]
    """Absolute path already present in the destination."""

    is_directory: bool = False
    """Whether the known path is a directory rather than a file."""

    content_hash: Hash | None = None
    """Expected effective file hash, if the caller recorded one."""


class PlannedFileKind(str, Enum):
    """Describe how a planned target file is produced."""

    wheel = "wheel"
    entry_point = "entry-point"
    additional_metadata = "additional-metadata"
    record = "record"
    existing_target = "existing-target"


class PlanConflictReason(str, Enum):
    """Describe why planned files cannot occupy the target filesystem."""

    duplicate = "duplicate"
    file_directory = "file-directory"


@dataclass(frozen=True)
class WheelPlanRequest:
    """A wheel to plan and metadata selected for its installation."""

    source: WheelSource
    """The wheel members to plan."""

    additional_metadata: Mapping[str, bytes] = field(default_factory=dict)
    """Metadata files to write into this wheel's ``.dist-info`` directory."""

    wheel_hash: Hash | None = None
    """Expected hash of the source wheel, for verification before application."""


@dataclass(frozen=True)
class PlannedDistribution:
    """Information about a wheel in an installation plan."""

    index: int
    distribution: str
    version: str
    wheel_hash: Hash | None


@dataclass(frozen=True)
class PlannedFile:
    """A filesystem path produced from a wheel member or entry-point spec."""

    source_index: int
    """Index of the source wheel in the batch, or ``-1`` for an existing target."""

    distribution: str
    """Distribution producing this file."""

    version: str
    """Version of the distribution producing this file."""

    scheme: Scheme
    """Wheel installation scheme containing the file."""

    source_path: str
    """Path in the wheel, or a descriptive path for a generated file."""

    target_path: Path
    """Absolute path under the destination's scheme directory."""

    kind: PlannedFileKind
    """Whether the file is copied, generated, or supplied as metadata."""

    executable: bool
    """Whether installation would set an executable bit."""

    content_hash: Hash | None
    """Hash of effective file contents, after shebang rewriting/generation."""

    shebang_rewritten: bool = False
    """Whether a wheel script had its source shebang replaced."""

    source_detail: str | None = None
    """Extra location information, such as an entry-point section."""

    superseded: bool = False
    """Whether another file in the plan replaces this one before application."""


@dataclass(frozen=True)
class PlanConflict:
    """A set of planned files that cannot occupy the same target location."""

    reason: PlanConflictReason
    """Whether paths are exact duplicates or form a file/directory collision."""

    target_path: Path
    """Shortest filesystem path involved in the conflict."""

    files: tuple[PlannedFile, ...]
    """All distributions and source paths involved in the conflict."""

    def __str__(self) -> str:
        lines = [f"{self.reason.value} conflict at {self.target_path}:"]
        for planned_file in self.files:
            detail = ""
            if planned_file.source_detail is not None:
                detail = f" ({planned_file.source_detail})"
            if planned_file.kind is PlannedFileKind.existing_target:
                lines.append(
                    f"- {planned_file.source_detail or 'existing target'}: "
                    f"{planned_file.target_path}"
                )
                continue
            lines.append(
                "- "
                f"#{planned_file.source_index} "
                f"{planned_file.distribution}-{planned_file.version}: "
                f"{planned_file.source_path}{detail}"
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class InstallationPlan:
    """The complete result of planning one batch of wheels."""

    distributions: tuple[PlannedDistribution, ...]
    """Selected source wheels in batch order."""

    files: tuple[PlannedFile, ...]
    """All effective and superseded filesystem operations, in planning order."""

    conflicts: tuple[PlanConflict, ...]
    """Conflicts detected across the batch and caller-supplied target snapshot."""

    @property
    def is_valid(self) -> bool:
        """Whether the plan found no filesystem conflicts."""
        return not self.conflicts


DuplicatePolicy = Callable[[tuple[PlannedFile, ...]], bool]


def allow_identical_files(files: tuple[PlannedFile, ...]) -> bool:
    """Allow duplicate targets when installation would produce identical files.

    The comparison uses content after shebang rewriting or entry-point
    generation. It also requires the executable bit and production method to be
    the same; original archive bytes are not enough to establish equivalence.
    """
    if len(files) < 2:
        return False

    first = files[0]
    if first.kind == PlannedFileKind.record or first.content_hash is None:
        return False

    return all(
        planned_file.kind == first.kind
        and planned_file.source_detail == first.source_detail
        and planned_file.shebang_rewritten == first.shebang_rewritten
        and planned_file.content_hash == first.content_hash
        and planned_file.executable == first.executable
        for planned_file in files[1:]
    )


def _reject_duplicates(_files: tuple[PlannedFile, ...]) -> bool:
    return False


def _hash_bytes(data: bytes, algorithm: str) -> Hash:
    digest = hashlib.new(algorithm, data).digest()
    return Hash(
        algorithm,
        base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
    )


def _hash_stream(stream: BinaryIO, algorithm: str) -> Hash:
    hasher = hashlib.new(algorithm)
    while True:
        data = stream.read(_COPY_BUFSIZE)
        if not data:
            break
        hasher.update(data)

    return Hash(
        algorithm,
        base64.urlsafe_b64encode(hasher.digest()).decode("ascii").rstrip("="),
    )


def _target_path(
    scheme_dict: Mapping[str, str | os.PathLike[str]],
    scheme: Scheme,
    path: str,
) -> Path:
    root = Path(os.path.abspath(os.fspath(scheme_dict[scheme])))
    target_path = Path(os.path.abspath(root / path))
    if not target_path.is_relative_to(root):
        message = f"Attempting to write {path} outside of the target directory"
        raise ValueError(message)
    return target_path


def _validate_additional_metadata_name(filename: str) -> None:
    if (
        not filename
        or filename in {"RECORD", ".", ".."}
        or posixpath.basename(filename) != filename
    ):
        message = f"Invalid additional metadata filename: {filename!r}"
        raise ValueError(message)


def _path_parts(path: Path, case_sensitive: bool) -> tuple[str, ...]:
    if case_sensitive:
        return path.parts
    return tuple(part.casefold() for part in path.parts)


def _find_conflicts(
    files: Iterable[PlannedFile],
    *,
    case_sensitive: bool,
    policy: DuplicatePolicy,
    existing_targets: Iterable[
        str | os.PathLike[str] | TargetCondition
    ] = (),
) -> tuple[PlanConflict, ...]:
    def existing_target_info(
        target: str | os.PathLike[str] | TargetCondition,
    ) -> tuple[Path, str, Hash | None]:
        if isinstance(target, TargetCondition):
            path = Path(os.path.abspath(os.fspath(target.path)))
            detail = (
                "existing directory"
                if target.is_directory
                else "existing file"
            )
            return path, detail, target.content_hash
        path = Path(os.path.abspath(os.fspath(target)))
        return path, "existing target", None

    planned_files = tuple(
        planned_file for planned_file in files if not planned_file.superseded
    )
    existing_files = tuple(
        PlannedFile(
            source_index=-1,
            distribution="",
            version="",
            scheme=Scheme("data"),
            source_path=_EXISTING_SOURCE_PATH,
            target_path=existing_path,
            kind=PlannedFileKind.existing_target,
            executable=False,
            content_hash=existing_hash,
            source_detail=existing_detail,
        )
        for existing_path, existing_detail, existing_hash in (
            existing_target_info(target) for target in existing_targets
        )
    )
    nodes = planned_files + existing_files
    node_count = len(nodes)
    paths_to_indices: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for index, planned_file in enumerate(nodes):
        paths_to_indices[
            _path_parts(planned_file.target_path, case_sensitive)
        ].append(index)

    parents = list(range(node_count))
    ranks = [0] * node_count
    has_structural_edge = [False] * node_count
    duplicate_disputed = [False] * node_count
    is_existing = [index >= len(planned_files) for index in range(node_count)]
    is_existing_directory = [
        is_existing[index]
        and nodes[index].source_detail == "existing directory"
        for index in range(node_count)
    ]

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int, *, edge_is_structural: bool = False) -> int:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            if edge_is_structural:
                has_structural_edge[left_root] = True
            return left_root

        if ranks[left_root] < ranks[right_root]:
            left_root, right_root = right_root, left_root
        parents[right_root] = left_root
        if ranks[left_root] == ranks[right_root]:
            ranks[left_root] += 1
        has_structural_edge[left_root] = (
            edge_is_structural
            or has_structural_edge[left_root]
            or has_structural_edge[right_root]
        )
        duplicate_disputed[left_root] = (
            duplicate_disputed[left_root] or duplicate_disputed[right_root]
        )
        return left_root

    for parts, indices in paths_to_indices.items():
        for index in indices[1:]:
            union(
                indices[0],
                index,
                edge_is_structural=any(
                    is_existing_directory[index] for index in indices
                ),
            )
        if len(indices) > 1:
            planned_indices = [
                index for index in indices if not is_existing[index]
            ]
            duplicate_files = tuple(nodes[index] for index in planned_indices)
            if len(planned_indices) != len(indices) or not policy(
                duplicate_files
            ):
                duplicate_disputed[find(indices[0])] = True

        for length in range(1, len(parts)):
            parent_indices = paths_to_indices.get(parts[:length])
            if parent_indices is None:
                continue
            for child_index in indices:
                for parent_index in parent_indices:
                    union(child_index, parent_index, edge_is_structural=True)

    members: dict[int, list[int]] = defaultdict(list)
    for index in range(node_count):
        members[find(index)].append(index)

    conflicts = []
    for root_index, member_indices in members.items():
        if not any(not is_existing[index] for index in member_indices):
            continue
        if not has_structural_edge[root_index] and not duplicate_disputed[
            root_index
        ]:
            continue

        conflict_files = tuple(nodes[index] for index in sorted(member_indices))
        reason = (
            PlanConflictReason.file_directory
            if has_structural_edge[root_index]
            else PlanConflictReason.duplicate
        )
        target_path = min(
            (planned_file.target_path for planned_file in conflict_files),
            key=lambda path: _path_parts(path, case_sensitive),
        )
        conflicts.append(
            PlanConflict(
                reason=reason,
                target_path=target_path,
                files=conflict_files,
            )
        )

    conflicts.sort(
        key=lambda conflict: _path_parts(conflict.target_path, case_sensitive)
    )
    return tuple(conflicts)


def plan_installation(
    wheels: Iterable[WheelSource | WheelPlanRequest],
    scheme_dict: Mapping[str, str | os.PathLike[str]],
    *,
    interpreter: str,
    script_kind: "LauncherKind" = "posix",
    case_sensitive: bool | None = None,
    hash_algorithm: str = "sha256",
    duplicate_policy: DuplicatePolicy = _reject_duplicates,
    existing_targets: Iterable[
        str | os.PathLike[str] | TargetCondition
    ] = (),
) -> InstallationPlan:
    """Calculate installation targets without writing files or executing code.

    Members from ``{name}-{version}.data`` are remapped to their requested
    schemes. Scripts receive the selected interpreter shebang, and entry points
    are represented by the generated launcher name (including ``.exe`` for
    Windows launchers). ``.pth`` files are treated as regular data files; they
    are not evaluated, packages are not imported, and no package index is used.

    ``existing_targets`` is a caller-produced snapshot of files and directories
    already present in the destination. The planner does not walk, stat, or
    read the destination; callers can refresh that snapshot and compare hashes
    again immediately before applying this plan. ``wheel_hash`` is retained on
    each distribution for the same source-wheel verification step.

    Paths from schemes that resolve to the same absolute directory collide in
    the same namespace. ``case_sensitive`` selects the destination's filename
    rules; it defaults to the current platform's rule. Pass ``True`` or
    ``False`` explicitly when planning for a platform other than the current
    one.

    ``duplicate_policy`` decides when two generated files may safely share an
    exact target path. It receives only wheel-produced duplicates. The default
    rejects every duplicate. Policies should compare
    :attr:`PlannedFile.content_hash` (effective generated bytes),
    :attr:`PlannedFile.kind`, :attr:`PlannedFile.shebang_rewritten`, and
    :attr:`PlannedFile.executable`; raw compressed bytes and archive metadata
    are insufficient because shebang rewriting, entry-point generation, and
    permission mode can change the installed result.

    :param wheels: wheel sources or wheel plan requests, in deployment order.
    :param scheme_dict: mapping of wheel schemes to destination directories.
    :param interpreter: interpreter used by scripts and entry-point launchers.
    :param script_kind: launcher kind, matching the destination platform.
    :param case_sensitive: destination filename case rules.
    :param hash_algorithm: name of the hash algorithm for effective contents.
    :param duplicate_policy: callback that permits compatible exact duplicates.
    :param existing_targets: paths or :class:`TargetCondition` values known to
        already exist on disk when the caller produced the snapshot.
    """
    if case_sensitive is None:
        case_sensitive = os.name != "nt"

    distributions = []
    files: list[PlannedFile] = []

    def add_file(
        *,
        source_index: int,
        source: WheelSource,
        scheme: Scheme,
        source_path: str,
        destination_path: str,
        kind: PlannedFileKind,
        executable: bool,
        content_hash: Hash | None,
        shebang_rewritten: bool = False,
        source_detail: str | None = None,
        superseded: bool = False,
    ) -> PlannedFile:
        planned_file = PlannedFile(
            source_index=source_index,
            distribution=source.distribution,
            version=source.version,
            scheme=scheme,
            source_path=source_path,
            target_path=_target_path(scheme_dict, scheme, destination_path),
            kind=kind,
            executable=executable,
            shebang_rewritten=shebang_rewritten,
            content_hash=content_hash,
            source_detail=source_detail,
            superseded=superseded,
        )
        files.append(planned_file)
        return planned_file

    for source_index, wheel in enumerate(wheels):
        if isinstance(wheel, WheelSource):
            request = WheelPlanRequest(source=wheel)
        else:
            request = wheel
        source = request.source

        for filename in request.additional_metadata:
            _validate_additional_metadata_name(filename)

        root_scheme = _process_WHEEL_file(source)
        distributions.append(
            PlannedDistribution(
                index=source_index,
                distribution=source.distribution,
                version=source.version,
                wheel_hash=request.wheel_hash,
            )
        )

        if "entry_points.txt" in source.dist_info_filenames:
            entrypoints_text = source.read_dist_info("entry_points.txt")
            for name, module, attr, section in parse_entrypoints(entrypoints_text):
                script = Script(name, module, attr, section)
                script_name, data = script.generate(interpreter, script_kind)
                add_file(
                    source_index=source_index,
                    source=source,
                    scheme=Scheme("scripts"),
                    source_path=posixpath.join(
                        source.dist_info_dir, "entry_points.txt"
                    ),
                    destination_path=script_name,
                    kind=PlannedFileKind.entry_point,
                    executable=True,
                    content_hash=_hash_bytes(data, hash_algorithm),
                    source_detail=f"[{section}_scripts] {name}",
                )

        record_file_path = posixpath.join(source.dist_info_dir, "RECORD")
        additional_paths = {
            posixpath.join(source.dist_info_dir, filename)
            for filename in request.additional_metadata
        }

        for record_elements, stream, is_executable in source.get_contents():
            source_record = RecordEntry.from_elements(*record_elements)
            source_path = source_record.path
            if source_path == record_file_path:
                add_file(
                    source_index=source_index,
                    source=source,
                    scheme=root_scheme,
                    source_path=source_path,
                    destination_path=source_path,
                    kind=PlannedFileKind.record,
                    executable=False,
                    content_hash=None,
                    source_detail="source RECORD",
                    superseded=True,
                )
                continue

            if "__pycache__" in source_path.split("/")[:-1]:
                warnings.warn(
                    (
                        f"Skip installing {source_path} from {source.distribution}."
                        " Installing files in a __pycache__ directory poses a "
                        "security risk. __pycache__ directories should not be "
                        "included in wheels."
                    ),
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue

            scheme, destination_path = _determine_scheme(
                path=source_path,
                source=source,
                root_scheme=root_scheme,
            )
            if scheme == "scripts":
                stream.seek(0)
                shebang_rewritten = stream.read(8) == b"#!python"
                stream.seek(0)
                with fix_shebang(stream, interpreter) as rewritten:
                    content_hash = _hash_stream(rewritten, hash_algorithm)
            else:
                content_hash = _hash_stream(stream, hash_algorithm)
                shebang_rewritten = False

            add_file(
                source_index=source_index,
                source=source,
                scheme=scheme,
                source_path=source_path,
                destination_path=destination_path,
                kind=PlannedFileKind.wheel,
                executable=is_executable,
                shebang_rewritten=shebang_rewritten,
                content_hash=content_hash,
                superseded=source_path in additional_paths,
            )

        for filename, contents in request.additional_metadata.items():
            destination_path = posixpath.join(source.dist_info_dir, filename)
            add_file(
                source_index=source_index,
                source=source,
                scheme=root_scheme,
                source_path=destination_path,
                destination_path=destination_path,
                kind=PlannedFileKind.additional_metadata,
                executable=False,
                content_hash=_hash_bytes(contents, hash_algorithm),
                source_detail="additional metadata",
            )

        add_file(
            source_index=source_index,
            source=source,
            scheme=root_scheme,
            source_path=record_file_path,
            destination_path=record_file_path,
            kind=PlannedFileKind.record,
            executable=False,
            content_hash=None,
            source_detail="generated RECORD",
        )

    conflicts = _find_conflicts(
        files,
        case_sensitive=case_sensitive,
        policy=duplicate_policy,
        existing_targets=existing_targets,
    )
    return InstallationPlan(
        distributions=tuple(distributions),
        files=tuple(files),
        conflicts=conflicts,
    )
