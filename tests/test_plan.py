import base64
import hashlib
import stat
import zipfile
from pathlib import Path

import pytest

from installer.plan import (
    PlannedFile,
    PlannedFileKind,
    PlanConflictReason,
    TargetCondition,
    WheelPlanRequest,
    allow_identical_files,
    plan_installation,
)
from installer.records import Hash
from installer.sources import WheelFile
from installer.utils import Scheme

pytestmark = pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")


def record_hash(data):
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def write_member(archive, name, data, executable=False):
    info = zipfile.ZipInfo(name)
    if executable:
        info.external_attr = (stat.S_IFREG | 0o755) << 16
    archive.writestr(info, data)


def make_wheel(
    path,
    distribution,
    *,
    root_is_purelib=True,
    files=None,
    entry_points=None,
    duplicates=(),
):
    path.mkdir(parents=True, exist_ok=True)
    files = dict(files or {})
    version = "1.0"
    dist_info = f"{distribution}-{version}.dist-info"
    files[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        "Root-Is-Purelib: {value}\n"
        "Tag: py3-none-any\n"
    ).format(value="true" if root_is_purelib else "false").encode()
    files[f"{dist_info}/METADATA"] = (
        f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n"
    ).encode()
    if entry_points is not None:
        files[f"{dist_info}/entry_points.txt"] = entry_points

    record_lines = [
        f"{name},{record_hash(data)},{len(data)}" for name, data in files.items()
    ]
    record_lines.append(f"{dist_info}/RECORD,,")
    files[f"{dist_info}/RECORD"] = "\n".join(record_lines).encode()

    wheel_path = path / f"{distribution}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for name, data in files.items():
            write_member(archive, name, data)
        for name, data, executable in duplicates:
            write_member(archive, name, data, executable=executable)
    return wheel_path


def make_three_wheels(path):
    shared_script = b"#!python\nimport sys\n"
    alpha = make_wheel(
        path,
        "alpha",
        files={
            "alpha/__init__.py": b"ALPHA = True\n",
            "alpha-1.0.data/platlib/shared/module.py": (
                b"from alpha import object\n"
            ),
            "alpha-1.0.dist-info/INSTALLER": b"old-installer\n",
        },
        entry_points=(
            "[console_scripts]\n"
            "shared-tool = alpha:main\n"
        ).encode(),
    )
    beta = make_wheel(
        path,
        "beta",
        root_is_purelib=False,
        files={
            "beta/__init__.py": b"BETA = True\n",
            "beta-1.0.data/purelib/shared/module.py": (
                b"from beta import object\n"
            ),
        },
        entry_points=(
            "[console_scripts]\n"
            "beta-tool = beta:main\n"
        ).encode(),
    )
    gamma = make_wheel(
        path,
        "gamma",
        files={"gamma/__init__.py": b"GAMMA = True\n"},
        duplicates=(
            (
                "gamma-1.0.data/scripts/shared-tool",
                shared_script,
                False,
            ),
            (
                "gamma-1.0.data/scripts/shared-tool",
                shared_script,
                False,
            ),
        ),
    )
    return alpha, beta, gamma


def scheme_dict(root):
    return {
        "purelib": str(root),
        "platlib": str(root),
        "headers": str(root / "include"),
        "scripts": str(root / "bin"),
        "data": str(root / "share"),
    }


def open_wheels(paths):
    return [WheelFile(zipfile.ZipFile(wheel_path)) for wheel_path in paths]


def test_plans_scheme_mapping_entry_points_and_three_wheel_conflicts(tmp_path):
    wheel_paths = make_three_wheels(tmp_path)
    sources = open_wheels(wheel_paths)

    try:
        requests = [
            WheelPlanRequest(
                source=sources[0],
                additional_metadata={"INSTALLER": b"new-installer\n"},
                wheel_hash=Hash("sha256", "alpha-digest"),
            ),
            sources[1],
            sources[2],
        ]
        plan = plan_installation(
            requests,
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
        )
    finally:
        for source in sources:
            source._zipfile.close()

    assert not plan.is_valid
    assert [distribution.distribution for distribution in plan.distributions] == [
        "alpha",
        "beta",
        "gamma",
    ]
    assert plan.distributions[0].wheel_hash == Hash("sha256", "alpha-digest")

    script_conflict, module_conflict = plan.conflicts
    assert module_conflict.reason is PlanConflictReason.duplicate
    assert module_conflict.target_path == tmp_path / "prefix" / "shared" / "module.py"
    assert [
        (planned_file.distribution, planned_file.source_path)
        for planned_file in module_conflict.files
    ] == [
        (
            "alpha",
            "alpha-1.0.data/platlib/shared/module.py",
        ),
        (
            "beta",
            "beta-1.0.data/purelib/shared/module.py",
        ),
    ]

    assert script_conflict.target_path == tmp_path / "prefix" / "bin" / "shared-tool"
    assert {
        (planned_file.distribution, planned_file.kind)
        for planned_file in script_conflict.files
    } == {
        ("alpha", PlannedFileKind.entry_point),
        ("gamma", PlannedFileKind.wheel),
    }
    assert [
        planned_file.source_path for planned_file in script_conflict.files
    ] == [
        "alpha-1.0.dist-info/entry_points.txt",
        "gamma-1.0.data/scripts/shared-tool",
        "gamma-1.0.data/scripts/shared-tool",
    ]


def test_additional_metadata_supersedes_existing_wheel_member(tmp_path):
    wheel_paths = make_three_wheels(tmp_path)
    sources = open_wheels(wheel_paths)

    try:
        plan = plan_installation(
            [
                WheelPlanRequest(
                    source=sources[0],
                    additional_metadata={"INSTALLER": b"new-installer\n"},
                ),
                *sources[1:],
            ],
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
        )
    finally:
        for source in sources:
            source._zipfile.close()

    installer_files = [
        planned_file
        for planned_file in plan.files
        if planned_file.source_path == "alpha-1.0.dist-info/INSTALLER"
    ]
    assert len(installer_files) == 2
    assert installer_files[0].kind is PlannedFileKind.wheel
    assert installer_files[0].superseded
    assert installer_files[1].kind is PlannedFileKind.additional_metadata
    assert not installer_files[1].superseded


def test_additional_metadata_supersedes_duplicate_wheel_members(tmp_path):
    wheel_path = make_wheel(
        tmp_path / "wheels",
        "dupmetadata",
        files={"pkg/__init__.py": b"pkg = True\n"},
        duplicates=(
            (
                "dupmetadata-1.0.dist-info/INSTALLER",
                b"first-installer\n",
                False,
            ),
            (
                "dupmetadata-1.0.dist-info/INSTALLER",
                b"second-installer\n",
                False,
            ),
        ),
    )
    sources = open_wheels((wheel_path,))

    try:
        plan = plan_installation(
            [
                WheelPlanRequest(
                    source=sources[0],
                    additional_metadata={"INSTALLER": b"final-installer\n"},
                )
            ],
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
        )
    finally:
        for source in sources:
            source._zipfile.close()

    assert plan.is_valid
    installer_files = [
        planned_file
        for planned_file in plan.files
        if planned_file.source_path
        == "dupmetadata-1.0.dist-info/INSTALLER"
    ]
    assert len(installer_files) == 3
    assert [planned_file.superseded for planned_file in installer_files] == [
        True,
        True,
        False,
    ]


def test_shebang_is_accounted_for_in_planned_content_hash(tmp_path):
    wheel_paths = make_three_wheels(tmp_path)
    sources = open_wheels(wheel_paths)

    try:
        plan = plan_installation(
            sources,
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
        )
    finally:
        for source in sources:
            source._zipfile.close()

    rewritten_script = b"#!/usr/bin/python3\nimport sys\n"
    expected_hash = Hash(
        "sha256",
        base64.urlsafe_b64encode(hashlib.sha256(rewritten_script).digest())
        .decode("ascii")
        .rstrip("="),
    )
    gamma_scripts = [
        planned_file
        for planned_file in plan.files
        if planned_file.distribution == "gamma"
        and planned_file.source_path == "gamma-1.0.data/scripts/shared-tool"
    ]
    assert len(gamma_scripts) == 2
    assert [
        (
            planned_file.content_hash.name,
            planned_file.content_hash.value,
            planned_file.shebang_rewritten,
        )
        for planned_file in gamma_scripts
    ] == [
        (expected_hash.name, expected_hash.value, True),
        (expected_hash.name, expected_hash.value, True),
    ]


def test_case_insensitive_targets_detect_case_only_differences(tmp_path):
    tmp_path.joinpath("wheels").mkdir(exist_ok=True)
    wheel_paths = (
        make_wheel(
            tmp_path / "wheels",
            "lower",
            files={"module.py": b"lowercase\n"},
        ),
        make_wheel(
            tmp_path / "wheels",
            "upper",
            files={"MODULE.py": b"uppercase\n"},
        ),
    )
    sources = open_wheels(wheel_paths)

    try:
        insensitive = plan_installation(
            sources,
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
            case_sensitive=False,
        )
        sensitive = plan_installation(
            sources,
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
            case_sensitive=True,
        )
    finally:
        for source in sources:
            source._zipfile.close()

    assert len(insensitive.conflicts) == 1
    assert insensitive.conflicts[0].target_path == tmp_path / "prefix" / "module.py"
    assert sensitive.is_valid


def test_file_and_directory_conflicts_are_reported(tmp_path):
    wheel_paths = (
        make_wheel(
            tmp_path,
            "filewheel",
            files={"shared": b"file\n"},
        ),
        make_wheel(
            tmp_path,
            "directorywheel",
            files={"shared/module.py": b"directory\n"},
        ),
    )
    sources = open_wheels(wheel_paths)

    try:
        plan = plan_installation(
            sources,
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
        )
    finally:
        for source in sources:
            source._zipfile.close()

    assert len(plan.conflicts) == 1
    assert plan.conflicts[0].reason is PlanConflictReason.file_directory
    assert plan.conflicts[0].target_path == tmp_path / "prefix" / "shared"


def test_windows_entry_points_use_exe_suffix(tmp_path):
    wheel_path = make_wheel(
        tmp_path,
        "windowstools",
        entry_points=b"[console_scripts]\ntool = windowstools:main\n",
    )
    with WheelFile.open(wheel_path) as source:
        plan = plan_installation(
            [source],
            scheme_dict(tmp_path / "prefix"),
            interpreter=r"C:\Python\python.exe",
            script_kind="win-amd64",
        )

    entry_point = next(
        planned_file
        for planned_file in plan.files
        if planned_file.kind is PlannedFileKind.entry_point
    )
    assert entry_point.target_path == tmp_path / "prefix" / "bin" / "tool.exe"


def planned_file(
    *,
    executable=False,
    kind=PlannedFileKind.wheel,
    digest="same",
    shebang_rewritten=False,
    source_detail=None,
):
    return PlannedFile(
        source_index=0,
        distribution="example",
        version="1.0",
        scheme=Scheme("purelib"),
        source_path="example.txt",
        target_path=Path("/prefix/example.txt"),
        kind=kind,
        executable=executable,
        shebang_rewritten=shebang_rewritten,
        content_hash=Hash("sha256", digest),
        source_detail=source_detail,
    )


def test_identical_content_policy_checks_generation_and_executable_bit():
    assert allow_identical_files((planned_file(), planned_file()))
    assert not allow_identical_files(
        (planned_file(), planned_file(executable=True))
    )
    assert not allow_identical_files(
        (
            planned_file(
                kind=PlannedFileKind.entry_point,
                source_detail="[console_scripts] tool",
            ),
            planned_file(
                kind=PlannedFileKind.entry_point,
                source_detail="[gui_scripts] tool",
            ),
        )
    )
    assert not allow_identical_files(
        (
            planned_file(),
            planned_file(kind=PlannedFileKind.entry_point, digest="same"),
        )
    )
    assert not allow_identical_files((planned_file(), planned_file(digest="other")))
    assert not allow_identical_files(
        (
            planned_file(),
            planned_file(shebang_rewritten=True),
        )
    )


def test_identical_content_policy_allows_transformed_duplicates(tmp_path):
    data = b"same transformed content\n"
    tmp_path.joinpath("one").mkdir()
    tmp_path.joinpath("two").mkdir()
    wheel_paths = (
        make_wheel(tmp_path / "one", "one", files={"shared.txt": data}),
        make_wheel(tmp_path / "two", "two", files={"shared.txt": data}),
    )
    sources = open_wheels(wheel_paths)

    try:
        plan = plan_installation(
            sources,
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
            duplicate_policy=allow_identical_files,
        )
    finally:
        for source in sources:
            source._zipfile.close()

    assert plan.is_valid


def test_existing_file_condition_is_reported_even_when_content_policy_allows(
    tmp_path,
):
    data = b"same transformed content\n"
    wheel_path = make_wheel(
        tmp_path / "wheels",
        "one",
        files={"shared.txt": data},
    )
    sources = open_wheels((wheel_path,))

    try:
        plan = plan_installation(
            sources,
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
            duplicate_policy=allow_identical_files,
            existing_targets=[
                TargetCondition(
                    tmp_path / "prefix" / "shared.txt",
                    content_hash=Hash("sha256", "old-content"),
                )
            ],
        )
    finally:
        for source in sources:
            source._zipfile.close()

    assert len(plan.conflicts) == 1
    conflict = plan.conflicts[0]
    assert conflict.reason is PlanConflictReason.duplicate
    assert conflict.target_path == tmp_path / "prefix" / "shared.txt"
    assert [planned_file.kind for planned_file in conflict.files] == [
        PlannedFileKind.wheel,
        PlannedFileKind.existing_target,
    ]
    existing = conflict.files[1]
    assert existing.source_detail == "existing file"
    assert existing.content_hash == Hash("sha256", "old-content")


def test_existing_directory_condition_creates_file_directory_conflict(tmp_path):
    wheel_path = make_wheel(
        tmp_path / "wheels",
        "one",
        files={"shared/module.py": b"module\n"},
    )
    sources = open_wheels((wheel_path,))

    try:
        plan = plan_installation(
            sources,
            scheme_dict(tmp_path / "prefix"),
            interpreter="/usr/bin/python3",
            existing_targets=[
                TargetCondition(
                    tmp_path / "prefix" / "shared",
                    is_directory=True,
                )
            ],
        )
    finally:
        for source in sources:
            source._zipfile.close()

    assert len(plan.conflicts) == 1
    conflict = plan.conflicts[0]
    assert conflict.reason is PlanConflictReason.file_directory
    assert conflict.target_path == tmp_path / "prefix" / "shared"
    assert [planned_file.kind for planned_file in conflict.files] == [
        PlannedFileKind.wheel,
        PlannedFileKind.existing_target,
    ]
