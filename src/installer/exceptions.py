"""Errors raised from this package."""


class InstallerError(Exception):
    """All exceptions raised from this package's code."""


class InvalidWheelSource(InstallerError):
    """When a wheel source violates a contract, or is not supported."""


class UninstallError(InstallerError):
    """When an uninstallation cannot be completed safely.

    Uninstallation is not atomic: this error carries the partial progress made
    before the failure, so that callers can report or recover from it.
    """

    def __init__(self, message, *, removed=(), restored=()):
        super().__init__(message)
        self.removed = list(removed)
        """Files that were already removed before the failure."""
        self.restored = list(restored)
        """Staged files that were moved back to their original location."""
