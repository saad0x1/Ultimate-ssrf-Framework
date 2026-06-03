import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ssrf_arsenal import TargetManager


def test_clean_domain_with_https():
    assert TargetManager._clean("https://example.com/path") == "example.com"


def test_clean_domain_with_http():
    assert TargetManager._clean("http://example.com/test") == "example.com"


def test_clean_plain_domain():
    assert TargetManager._clean("example.com") == "example.com"


def test_clean_empty_domain():
    assert TargetManager._clean("") is None
