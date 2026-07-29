from pathlib import Path

from jsintel.models import Endpoint, JavaScriptAsset, ScanRun
from jsintel.storage import KnowledgeGraphStore, connect


def test_graph_store_persists_and_traverses_relationships(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    connection = connect(tmp_path / "recon.db", root / "database" / "migrations")
    scan = ScanRun(target="https://app.example.test")
    store = KnowledgeGraphStore(connection, scan)
    asset = JavaScriptAsset(url="https://app.example.test/dashboard.js")
    endpoint = Endpoint(value="/api/admin/users", asset_id=asset.id, confidence=97)
    store.relate(asset, "reaches", endpoint, "AST call path: loadUsers -> fetch")
    store.commit()
    edges = store.traverse(asset)
    assert len(edges) == 1
    assert edges[0]["relationship"] == "reaches"
    assert "fetch" in edges[0]["evidence"]
