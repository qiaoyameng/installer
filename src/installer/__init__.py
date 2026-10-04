"""A library for installing Python wheels."""

__version__ = "1.0.1"
__all__ = ["install", "plan_installation"]

from installer._core import install
from installer.plan import plan_installation
