"""A library for installing Python wheels."""

__version__ = "1.0.1"
__all__ = ["apply_uninstall", "install", "plan_uninstall"]

from installer._core import install
from installer.uninstall import apply_uninstall, plan_uninstall
