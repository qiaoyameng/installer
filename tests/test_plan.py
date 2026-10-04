import base64
import hashlib
import textwrap
import zipfile
from pathlib import Path

from installer.destinations import SchemeDictionaryDestination
from installer.plan import (
    WheelDigest,
    WheelInstallationRequest,
    identical_installed_content,
    plan_installation,
    source_digest_matches,
    target_conditions_are_current,
)
from installer.scripts import Script
from installer.sources import WheelFile


def _record_row(path, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    return f"{path},sha256={digest},{len(data)}"


def make_wheel(
    path,
    name,
    *,
    root_is_purelib=True,
    files=None,
    entry_points=None,
    tag="py3-none-any",
    duplicate_files=(),
    executable_files=(),
):
    files = dict(files or {})
    dist_info = f"{name}-1.0.0.dist-info"
    metadata = textwrap.dedent(
        f"""\
        Metadata-Version: 2.1
        Name: {name}
        Version: 1.0.0
        """
    ).encode()
    wheel = textwrap.dedent(
        f"""\
        Wheel-Version: 1.0
        Root-Is-Purelib: {'true' if root_is_purelib else 'false'}
        Tag: {tag}
        """
    ).encode()
    files[f"{dist_info}/METADATA"] = metadata
    files[f"{dist_info}/WHEEL"] = wheel
    if entry_points is not None:
        files[f"{dist_info}/entry_points.txt"] = textwrap.dedent(entry_points).encode()

    rows = [_record_row(filename, data) for filename, data in sorted(files.items())]
    for filename, data in duplicate_files:
        rows.append(_record_row(filename, data))
    files[f"{dist_info}/RECORD"] = ("\n".join(rows) + "\n").encode()

    wheel_path = path / f"{name}-1.0.0-{tag}.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for filename, data in files.items():
            info = zipfile.ZipInfo(filename)
            if filename in executable_files:
                info.external_attr = 0o100755 << 16
            archive.writestr(info, data)
        for filename, data in duplicate_files:
            archive.writestr(filename, data)
    return wheel_path


def destination_for(tmp_path):
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir(exist_ok=True)
    scripts = tmp_path / "scripts"
    scripts.mkdir(exist_ok=True)
    headers = tmp_path / "headers"
    headers.mkdir(exist_ok=True)
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return SchemeDictionaryDestination(
        {
            "purelib": str(site_packages),
            "platlib": str(site_packages),
            "scripts": str(scripts),
            "headers": str(headers),
            "data": str(data),
        },
        interpreter="/usr/bin/python",
        script_kind="posix",
    )


def open_requests(*paths, additional_metadata=None):
    requests = []
    for path in paths:
        archive = zipfile.ZipFile(path)
        source = WheelFile(archive)
        requests.append(
            (
                WheelInstallationRequest(
                    source=source,
                    additional_metadata=(additional_metadata or {}).get(path.name, {}),
                ),
                archive,
            )
        )
    return requests


def test_three_tiny_wheels_report_two_different_source_mappings(tmp_path):
    alpha = make_wheel(
        tmp_path,
        "alpha",
        files={
            "shared/__init__.py": b"shared package\n",
            "alpha-1.0.0.data/scripts/shared-script": b"#!python\nprint('source script')\n",
        },
    )
    beta = make_wheel(
        tmp_path,
        "beta",
        root_is_purelib=False,
        tag="cp310-cp310-any",
        files={"beta-1.0.0.data/platlib/shared/__init__.py": b"shared package\n"},
    )
    gamma = make_wheel(
        tmp_path,
        "gamma",
        files={"gamma/__init__.py": b""},
        entry_points="""
        [console_scripts]
        shared-script = gamma:main
        """,
    )

    opened = open_requests(alpha, beta, gamma)
    try:
        plan = plan_installation(
            [request for request, _ in opened], destination_for(tmp_path)
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert plan.has_conflicts
    assert len(plan.conflicts) == 2

    package_conflict = next(
        conflict
        for conflict in plan.conflicts
        if conflict.target.name == "__init__.py"
    )
    assert package_conflict.distributions == ("alpha", "beta")
    assert package_conflict.source_paths == (
        ("alpha", "shared/__init__.py"),
        ("beta", "beta-1.0.0.data/platlib/shared/__init__.py"),
    )

    script_conflict = next(
        conflict
        for conflict in plan.conflicts
        if conflict.target.name == "shared-script"
    )
    assert script_conflict.distributions == ("alpha", "gamma")
    assert script_conflict.source_paths == (
        ("alpha", "alpha-1.0.0.data/scripts/shared-script"),
        (
            "gamma",
            "gamma-1.0.0.dist-info/entry_points.txt:console_scripts:shared-script",
        ),
    )


def test_file_directory_conflict_reports_prefix(tmp_path):
    first = make_wheel(tmp_path, "first", files={"shared": b"file"})
    second = make_wheel(
        tmp_path, "second", files={"shared/child.txt": b"child"}
    )
    opened = open_requests(first, second)
    try:
        plan = plan_installation(
            [request for request, _ in opened], destination_for(tmp_path)
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert [
        (conflict.target.name, len(conflict.planned_files))
        for conflict in plan.conflicts
    ] == [("shared", 2)]


def test_same_wheel_duplicate_member_is_conflict(tmp_path):
    path = tmp_path / "dupe-1.0.0-py3-none-any.whl"
    dist_info = "dupe-1.0.0.dist-info"
    files = {
        "dupe/__init__.py": b"first\n",
        f"{dist_info}/METADATA": b"Metadata-Version: 2.1\nName: dupe\nVersion: 1.0.0\n",
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    duplicate = ("dupe/__init__.py", b"second\n")
    rows = [_record_row(name, data) for name, data in sorted(files.items())]
    rows.append(_record_row(*duplicate))
    files[f"{dist_info}/RECORD"] = ("\n".join(rows) + "\n").encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr(*duplicate)

    with WheelFile.open(path) as source:
        plan = plan_installation(
            [WheelInstallationRequest(source=source)],
            destination_for(tmp_path),
        )

    assert len(plan.conflicts) == 1
    assert plan.conflicts[0].source_paths == (
        ("dupe", "dupe/__init__.py"),
        ("dupe", "dupe/__init__.py"),
    )


def test_additional_metadata_overrides_wheel_member(tmp_path):
    wheel = make_wheel(tmp_path, "meta")
    destination = destination_for(tmp_path)
    with WheelFile.open(wheel) as source:
        plan = plan_installation(
            [
                WheelInstallationRequest(
                    source=source,
                    additional_metadata={"METADATA": b"replacement\n"},
                )
            ],
            destination,
        )

    metadata_files = [
        item
        for item in plan.files
        if item.source_path.endswith("METADATA")
    ]
    assert len(metadata_files) == 1
    assert metadata_files[0].source_path == "<additional-metadata>/METADATA"
    assert plan.overrides[0].source_path == "meta-1.0.0.dist-info/METADATA"


def test_identical_policy_uses_installation_output_not_archive_identity(tmp_path):
    first = make_wheel(tmp_path, "one", files={"pkg/__init__.py": b"same\n"})
    second = make_wheel(tmp_path, "two", files={"pkg/__init__.py": b"same\n"})
    opened = open_requests(first, second)
    try:
        strict_plan = plan_installation(
            [request for request, _ in opened], destination_for(tmp_path)
        )
        shared_plan = plan_installation(
            [request for request, _ in opened],
            destination_for(tmp_path),
            sharing_policy=identical_installed_content,
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert len(strict_plan.conflicts) == 1
    assert shared_plan.conflicts == ()


def test_generated_and_regular_script_with_same_bytes_are_not_shareable(tmp_path):
    _, generated = Script(
        "cli", "pkg", "main", "console"
    ).generate("/usr/bin/python", "posix")
    first = make_wheel(
        tmp_path,
        "scriptpkg",
        files={"scriptpkg-1.0.0.data/scripts/cli": generated},
    )
    second = make_wheel(
        tmp_path,
        "entrypkg",
        files={"entrypkg/__init__.py": b""},
        entry_points="""
        [console_scripts]
        cli = pkg:main
        """,
    )
    opened = open_requests(first, second)
    try:
        plan = plan_installation(
            [request for request, _ in opened],
            destination_for(tmp_path),
            sharing_policy=identical_installed_content,
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert len(plan.conflicts) == 1


def test_case_insensitive_target_collision(tmp_path):
    base = tmp_path
    first_wheel = make_wheel(base, "casea", files={"Module.py": b"a"})
    second_wheel = make_wheel(base, "caseb", files={"module.py": b"b"})
    opened = open_requests(first_wheel, second_wheel)
    try:
        plan = plan_installation(
            [request for request, _ in opened],
            destination_for(base),
            case_sensitive=False,
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert len(plan.conflicts) == 1


def test_existing_target_conditions_are_checked(tmp_path):
    destination = destination_for(tmp_path)
    existing = destination.scheme_dict["purelib"] + "/existing.txt"
    with open(existing, "wb"):
        pass
    wheel = make_wheel(tmp_path, "exists", files={"existing.txt": b"new"})

    with WheelFile.open(wheel) as source:
        plan = plan_installation(
            [WheelInstallationRequest(source=source)], destination
        )
    assert len(plan.conflicts) == 1

    destination.overwrite_existing = True
    with WheelFile.open(wheel) as source:
        plan = plan_installation(
            [WheelInstallationRequest(source=source)], destination
        )
    assert plan.conflicts == ()
    overwritten = next(item for item in plan.files if item.target.name == "existing.txt")
    assert overwritten.replaces_existing


def test_shebang_difference_is_not_shareable(tmp_path):
    first = make_wheel(
        tmp_path,
        "shebanga",
        files={"shebanga-1.0.0.data/scripts/tool": b"#!python\ncode\n"},
    )
    second_wheel = make_wheel(
        tmp_path,
        "shebangb",
        files={"shebangb-1.0.0.data/scripts/tool": b"#!/other/python\ncode\n"},
    )
    destination = destination_for(tmp_path)
    opened = open_requests(first, second_wheel)
    try:
        plan = plan_installation(
            [request for request, _ in opened],
            destination,
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert len(plan.conflicts) == 1


def test_scheme_paths_reached_through_symlink_collide(tmp_path):
    site_packages = tmp_path / "real-site"
    site_packages.mkdir()
    pure_alias = tmp_path / "pure-link"
    pure_alias.symlink_to(site_packages)
    plat_alias = tmp_path / "plat-link"
    plat_alias.symlink_to(site_packages)
    destination = SchemeDictionaryDestination(
        {
            "purelib": str(pure_alias),
            "platlib": str(plat_alias),
            "scripts": str(tmp_path / "scripts"),
            "headers": str(tmp_path / "headers"),
            "data": str(tmp_path / "data"),
        },
        interpreter="/usr/bin/python",
        script_kind="posix",
    )
    for path in ("scripts", "headers", "data"):
        (tmp_path / path).mkdir()

    first = make_wheel(tmp_path, "symlinka", files={"same.py": b"same\n"})
    second_wheel = make_wheel(
        tmp_path,
        "symlinkb",
        root_is_purelib=False,
        tag="cp310-cp310-any",
        files={"symlinkb-1.0.0.data/platlib/same.py": b"same\n"},
    )
    opened = open_requests(first, second_wheel)
    try:
        plan = plan_installation(
            [request for request, _ in opened],
            destination,
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert len(plan.conflicts) == 1
    assert plan.conflicts[0].target == site_packages.resolve() / "same.py"


def test_existing_parent_file_is_directory_conflict(tmp_path):
    destination = destination_for(tmp_path)
    parent = Path(destination.scheme_dict["purelib"]) / "blocker"
    parent.write_bytes(b"")
    wheel = make_wheel(
        tmp_path, "blocked", files={"blocker/child.py": b"child\n"}
    )

    with WheelFile.open(wheel) as source:
        plan = plan_installation(
            [WheelInstallationRequest(source=source)], destination
        )

    assert len(plan.conflicts) == 1
    assert plan.conflicts[0].target == parent
    assert plan.conflicts[0].existing.target == parent


def test_executable_bit_prevents_identical_content_sharing(tmp_path):
    first = make_wheel(
        tmp_path,
        "execa",
        files={"execa-1.0.0.data/scripts/tool": b"#!/bin/sh\n"},
        executable_files={"execa-1.0.0.data/scripts/tool"},
    )
    second_wheel = make_wheel(
        tmp_path,
        "execb",
        files={"execb-1.0.0.data/scripts/tool": b"#!/bin/sh\n"},
    )
    opened = open_requests(first, second_wheel)
    try:
        plan = plan_installation(
            [request for request, _ in opened],
            destination_for(tmp_path),
            sharing_policy=identical_installed_content,
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert len(plan.conflicts) == 1


def test_source_digest_can_be_rechecked(tmp_path):
    wheel = make_wheel(tmp_path, "digestwheel")
    raw = wheel.read_bytes()
    digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")

    assert source_digest_matches(wheel, WheelDigest("sha256", digest))
    assert not source_digest_matches(wheel, WheelDigest("sha256", "mismatch"))


def test_target_conditions_can_be_rechecked(tmp_path):
    destination = destination_for(tmp_path)
    wheel = make_wheel(tmp_path, "fresh", files={"fresh.txt": b"fresh"})

    with WheelFile.open(wheel) as source:
        plan = plan_installation(
            [WheelInstallationRequest(source=source)],
            destination,
            check_existing=False,
        )

    assert target_conditions_are_current(plan)

    target = Path(destination.scheme_dict["purelib"]) / "fresh.txt"
    target.write_bytes(b"")
    assert not target_conditions_are_current(plan)


def test_windows_entry_point_uses_exe_name(tmp_path):
    destination = destination_for(tmp_path)
    destination.script_kind = "win-amd64"
    first = make_wheel(
        tmp_path,
        "winexe",
        files={"winexe-1.0.0.data/scripts/cli.exe": b"launcher"},
    )
    second_wheel = make_wheel(
        tmp_path,
        "winentry",
        files={"winentry/__init__.py": b""},
        entry_points="""
        [console_scripts]
        cli = winentry:main
        """,
    )
    opened = open_requests(first, second_wheel)
    try:
        plan = plan_installation(
            [request for request, _ in opened],
            destination,
            case_sensitive=False,
        )
    finally:
        for _, archive in opened:
            archive.close()

    assert len(plan.conflicts) == 1
    assert plan.conflicts[0].target.name == "cli.exe"
