from pathlib import Path

import pytest

from jsintel.config import PlatformConfig


def test_current_configuration_is_loaded() -> None:
    config = PlatformConfig.from_yaml(Path("config/config.yaml"))
    assert config.threads == 50
    assert config.crawler.depth == 5
    assert config.download.retries == 3


def test_invalid_thread_count_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("threads: 0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="threads"):
        PlatformConfig.from_yaml(path)
