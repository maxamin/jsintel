"""Dependency ordering and validation for platform plugins."""
from __future__ import annotations

from collections.abc import Iterable

from .base import Plugin


class PluginRegistry:
    """Registry that validates identifiers and returns topologically sorted plugins."""

    def __init__(self, plugins: Iterable[type[Plugin]] = ()) -> None:
        self._plugins: dict[str, type[Plugin]] = {}
        for plugin in plugins:
            self.register(plugin)

    def register(self, plugin: type[Plugin]) -> None:
        plugin_id = plugin.id()
        if not plugin_id or plugin_id in self._plugins:
            raise ValueError(f"Duplicate or empty plugin id: {plugin_id!r}")
        self._plugins[plugin_id] = plugin

    def get(self, plugin_id: str) -> type[Plugin]:
        try:
            return self._plugins[plugin_id]
        except KeyError as error:
            raise KeyError(f"Unknown plugin: {plugin_id}") from error

    def ordered(self, requested: Iterable[str] | None = None) -> tuple[type[Plugin], ...]:
        """Resolve the requested plugins and all dependencies in run order."""
        wanted = tuple(requested) if requested is not None else tuple(self._plugins)
        state: dict[str, int] = {}
        result: list[type[Plugin]] = []

        def visit(plugin_id: str) -> None:
            marker = state.get(plugin_id, 0)
            if marker == 1:
                raise ValueError(f"Plugin dependency cycle includes: {plugin_id}")
            if marker == 2:
                return
            plugin = self.get(plugin_id)
            state[plugin_id] = 1
            for dependency in plugin.dependencies():
                visit(dependency)
            state[plugin_id] = 2
            result.append(plugin)

        for plugin_id in wanted:
            visit(plugin_id)
        return tuple(result)
