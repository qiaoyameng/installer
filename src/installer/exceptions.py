"""Errors raised from this package."""


class InstallerError(Exception):
    """All exceptions raised from this package's code."""


class InvalidWheelSource(InstallerError):
    """When a wheel source violates a contract, or is not supported."""


class ReproducibleInstallError(InstallerError):
    """When a reproducible installation cannot be performed.

    This is raised when the user requests a reproducible installation (see
    :attr:`installer.destinations.SchemeDictionaryDestination.reproducible`)
    but its prerequisites cannot be satisfied -- for example, when
    ``SOURCE_DATE_EPOCH`` is not set to a valid value, or when the target
    interpreter cannot generate hash-based bytecode.
    """
