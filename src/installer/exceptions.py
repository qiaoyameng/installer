"""Errors raised from this package."""


class InstallerError(Exception):
    """All exceptions raised from this package's code."""


class InvalidWheelSource(InstallerError):
    """When a wheel source violates a contract, or is not supported."""


class InvalidSourceDateEpoch(InstallerError):
    """When ``SOURCE_DATE_EPOCH`` is unset or invalid for a reproducible install.

    See https://reproducible-builds.org/docs/source-date-epoch/ for the
    specification of the environment variable.
    """


class InvalidReproducibleConfiguration(InstallerError):
    """When a reproducible install cannot be performed as requested.

    This is raised when the target interpreter does not support the
    capabilities required for reproducible installation, such as
    hash-based :pep:`552` bytecode invalidation.  The installer does not
    silently fall back to timestamp-based bytecode in this case.
    """
