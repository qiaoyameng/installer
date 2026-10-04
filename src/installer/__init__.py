"""A library for installing Python wheels."""

__version__ = "1.0.1"
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
    "install",
    "plan_installation",
    "source_digest_matches",
    "target_conditions_are_current",
]

from installer._core import install
from installer.plan import (
    Conflict,
    EntryPointSpec,
    ExistingTargetEntry,
    InstallationPlan,
    PlannedFile,
    PlannedOverride,
    WheelDigest,
    WheelInstallationRequest,
    identical_installed_content,
    plan_installation,
    source_digest_matches,
    target_conditions_are_current,
)
