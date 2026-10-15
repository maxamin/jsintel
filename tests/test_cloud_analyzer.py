"""Cloud storage reference analyzer."""
import time
from modules.extractor.models import Asset
from modules.extractor.analyzers.cloud_analyzer import CloudStorageAnalyzer


def _a(t="javascript"):
    return Asset(url="http://h/app.js", asset_type=t, local_path="x", status="downloaded")


def test_detects_s3_gcs_azure_spaces():
    src = """
      var a="https://my-app-assets.s3.amazonaws.com/x.png";
      var b="https://s3.eu-west-1.amazonaws.com/other-bucket/key";
      var c="s3://raw-bucket/path/file";
      var d="https://cdn.storage.googleapis.com/img";
      var e="https://storage.googleapis.com/gcs-bucket/o";
      var f="gs://gcs-native/obj";
      var g="https://acct123.blob.core.windows.net/container/blob";
      var h="https://space1.nyc3.digitaloceanspaces.com/f";
    """
    out = [f.to_record() for f in CloudStorageAnalyzer().analyze(_a(), src)]
    providers = {r["sink"] for r in out}
    assert {"aws-s3", "gcs", "azure-blob", "do-spaces"} <= providers, providers
    assert all(r["finding_type"] == "cloud_bucket_reference" for r in out)


def test_no_false_positive_on_plain_text():
    out = list(CloudStorageAnalyzer().analyze(_a(), "just a normal string with amazon and google words"))
    assert out == []


def test_bounded_on_huge_input():
    t = time.time()
    list(CloudStorageAnalyzer().analyze(_a(), ("s3://" + "a" * 100) * 100000))
    assert time.time() - t < 3, "cloud analyzer must stay bounded on huge input"


def test_runs_on_pages_and_sourcemaps():
    assert "page" in CloudStorageAnalyzer.supported_asset_types
    assert "source_map" in CloudStorageAnalyzer.supported_asset_types


def test_virtual_hosted_url_is_not_also_reported_path_style():
    # Regression: "chain-icons.s3.amazonaws.com/ethereum.png" also produced the
    # bogus bucket "s3.amazonaws.com/ethereum.png" (240 sweep findings).
    src = 'a="https://chain-icons.s3.amazonaws.com/ethereum.png";b="https://cdn.storage.googleapis.com/x/y.png"'
    values = sorted(f.value for f in CloudStorageAnalyzer().analyze(_a(), src))
    assert values == ["aws-s3: chain-icons.s3.amazonaws.com", "gcs: cdn.storage.googleapis.com"]


def test_path_style_still_detected():
    src = 'a="https://s3.us-east-2.amazonaws.com/my-bucket/k";b="//storage.googleapis.com/gcs-b/o"'
    values = {f.value for f in CloudStorageAnalyzer().analyze(_a(), src)}
    assert values == {"aws-s3: s3.us-east-2.amazonaws.com/my-bucket/k", "gcs: storage.googleapis.com/gcs-b/o"}
