"""Plugin interfaces and dependency-aware registry."""

from .base import Plugin, PluginContext, PluginResult
from .registry import PluginRegistry

__all__ = ["Plugin", "PluginContext", "PluginRegistry", "PluginResult"]
