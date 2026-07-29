"""JSIntel's typed platform API.

The package is additive in Phase 2. The legacy shell launcher remains supported
while collection and analysis modules are progressively moved behind this API.
"""

from .models import Asset, Endpoint, Framework, ScanRun

__all__ = ["Asset", "Endpoint", "Framework", "ScanRun"]
