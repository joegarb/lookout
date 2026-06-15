import pytest

from lookout import enrichment
from lookout.enrichment import IPInfo, _is_public


@pytest.fixture(autouse=True)
def _reset_enrichment():
    # Isolate each test from module-level state.
    enrichment._cache.clear()
    enrichment.configure(False)
    yield
    enrichment._cache.clear()
    enrichment.configure(False)


def test_is_public():
    assert _is_public("8.8.8.8") is True
    assert _is_public("10.0.0.1") is False
    assert _is_public("192.168.1.5") is False
    assert _is_public("127.0.0.1") is False
    assert _is_public("-") is False
    assert _is_public("not-an-ip") is False


def test_label_formatting():
    full = IPInfo(org="DigitalOcean, LLC", country="Germany")
    assert full.label() == " (DigitalOcean, LLC, Germany)"
    assert IPInfo(country="Germany").label() == " (Germany)"
    assert IPInfo().label() == ""


def test_describe_is_empty_when_disabled():
    enrichment.configure(False)
    assert enrichment.describe("8.8.8.8") == ""


def test_private_ips_never_trigger_lookup(monkeypatch):
    enrichment.configure(True)
    calls: list[list[str]] = []
    monkeypatch.setattr(enrichment, "_lookup_batch", lambda ips: calls.append(ips) or {})
    enrichment.prefetch(["10.0.0.1", "127.0.0.1", "-"])
    assert calls == []  # nothing public to resolve


def test_prefetch_then_describe(monkeypatch):
    enrichment.configure(True)
    monkeypatch.setattr(
        enrichment,
        "_lookup_batch",
        lambda ips: {"8.8.8.8": IPInfo(org="Google LLC", country="United States")},
    )
    enrichment.prefetch(["8.8.8.8"])
    assert enrichment.describe("8.8.8.8") == " (Google LLC, United States)"


def test_misses_are_cached(monkeypatch):
    enrichment.configure(True)
    calls: list[list[str]] = []

    def fake(ips: list[str]) -> dict:
        calls.append(ips)
        return {}  # API returned nothing for this IP

    monkeypatch.setattr(enrichment, "_lookup_batch", fake)
    assert enrichment.describe("8.8.8.8") == ""
    assert enrichment.describe("8.8.8.8") == ""  # second call should not re-query
    assert len(calls) == 1
