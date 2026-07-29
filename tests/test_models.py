from jsintel.models import AssetType, JavaScriptAsset


def test_models_serialize_identifiers_and_enums() -> None:
    asset = JavaScriptAsset(url="https://app.example.test/app.js", sha256="abc")
    data = asset.to_dict()
    assert data["asset_type"] == AssetType.JAVASCRIPT
    assert data["url"] == "https://app.example.test/app.js"
    assert isinstance(data["id"], str)
