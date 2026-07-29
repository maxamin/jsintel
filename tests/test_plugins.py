from jsintel.models import Asset
from jsintel.plugins import Plugin, PluginContext, PluginRegistry, PluginResult


class BasePlugin(Plugin):
    @classmethod
    def id(cls) -> str:
        return "test.base"

    @classmethod
    def version(cls) -> str:
        return "1.0"

    @classmethod
    def supported_asset_types(cls) -> tuple[str, ...]:
        return ("javascript",)

    def run(self, assets: tuple[Asset, ...], context: PluginContext) -> PluginResult:
        return PluginResult()


class DependentPlugin(BasePlugin):
    @classmethod
    def id(cls) -> str:
        return "test.dependent"

    @classmethod
    def dependencies(cls) -> tuple[str, ...]:
        return ("test.base",)


def test_registry_resolves_dependencies_before_dependents() -> None:
    registry = PluginRegistry((DependentPlugin, BasePlugin))
    assert tuple(plugin.id() for plugin in registry.ordered(("test.dependent",))) == (
        "test.base",
        "test.dependent",
    )


def test_registry_rejects_duplicate_ids() -> None:
    registry = PluginRegistry((BasePlugin,))
    try:
        registry.register(BasePlugin)
    except ValueError as error:
        assert "Duplicate" in str(error)
    else:
        raise AssertionError("expected duplicate registration to fail")
