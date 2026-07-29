# Plugin guide

Plugins are classes derived from `jsintel.plugins.Plugin`. They receive only
typed `Asset` input and a `PluginContext`; they return a `PluginResult`.

```python
from jsintel.models import Asset, Endpoint
from jsintel.plugins import Plugin, PluginContext, PluginResult

class EndpointPlugin(Plugin):
    @classmethod
    def id(cls) -> str:
        return "analysis.endpoint-ast"

    @classmethod
    def version(cls) -> str:
        return "1.0.0"

    @classmethod
    def supported_asset_types(cls) -> tuple[str, ...]:
        return ("javascript",)

    def run(self, assets: tuple[Asset, ...], context: PluginContext) -> PluginResult:
        endpoint = Endpoint(value="/api/example", confidence=90)
        return PluginResult(records=(endpoint,))
```

The platform persists records and relationships through the context sink.
Plugins must avoid direct SQLite use, raw JSON interchange, and direct access
to other plugin internals. Declare a dependency only when another plugin's
normalized model is required.
