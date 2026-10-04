"""Errors raised from this package."""


class InstallerError(Exception):
    """All exceptions raised from this package's code."""


class InvalidWheelSource(InstallerError):
    """When a wheel source violates a contract, or is not supported."""


class UninstallError(InstallerError):
    """Base class for errors encountered while planning or applying uninstallation."""


class UninstallPlanError(UninstallError):
    """Raised when uninstallation is requested with invalid parameters or state."""


class UninstallPlanChanged(UninstallError):
    """Raised when an uninstall plan no longer matches the filesystem."""
