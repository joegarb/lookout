"""Tests for DigestBuffer accumulation and windowing."""

from datetime import UTC, datetime, timedelta

from lookout.digest import DigestBuffer
from lookout.models import Alert, AlertKind, LogEntry


def _entry(path: str = "/", status: int = 200, age_hours: float = 0) -> LogEntry:
    ts = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=age_hours)
    return LogEntry(
        timestamp=ts,
        ip="1.2.3.4",
        method="GET",
        path=path,
        status=status,
        bytes_sent=100,
        user_agent="test",
        source="test",
    )


def _finding(kind: AlertKind = AlertKind.SENSITIVE_PATH, age_hours: float = 0) -> Alert:
    return Alert(kind=kind, source="test", ip="1.2.3.4", detail="x")


def test_entries_since_returns_recent():
    buf = DigestBuffer()
    buf.add(_entry(age_hours=0))
    buf.add(_entry(age_hours=2))
    assert len(buf.entries_since(hours=24)) == 2


def test_entries_since_excludes_old():
    buf = DigestBuffer()
    buf.add(_entry(age_hours=25))
    assert buf.entries_since(hours=24) == []


def test_findings_since_returns_recent():
    buf = DigestBuffer()
    buf.add_finding(_finding())
    assert len(buf.findings_since(hours=24)) == 1


def test_maxsize_cap_drops_oldest():
    buf = DigestBuffer(maxsize=3)
    for i in range(5):
        buf.add(_entry(path=f"/{i}"))
    entries = buf.entries_since(hours=1)
    assert len(entries) == 3
    assert entries[0].path == "/2"


def test_empty_buffer_returns_empty_lists():
    buf = DigestBuffer()
    assert buf.entries_since(hours=24) == []
    assert buf.findings_since(hours=24) == []
