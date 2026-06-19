from lookout.alerter import (
    Alerter,
    MultiNotifier,
    _webhook_payload,
    resolve_smtp_encryption,
)
from lookout.models import Alert, AlertKind


class _RecordingNotifier:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self._fail = fail

    def send(self, title: str, body: str) -> None:
        if self._fail:
            raise RuntimeError("boom")
        self.calls.append((title, body))


def test_resolve_encryption_auto_by_port():
    assert resolve_smtp_encryption("auto", 465) == "ssl"
    assert resolve_smtp_encryption("auto", 587) == "starttls"
    assert resolve_smtp_encryption("auto", 25) == "starttls"


def test_resolve_encryption_explicit_override():
    assert resolve_smtp_encryption("starttls", 465) == "starttls"
    assert resolve_smtp_encryption("ssl", 587) == "ssl"
    assert resolve_smtp_encryption("none", 587) == "none"


def test_webhook_payload_covers_common_targets():
    payload = _webhook_payload("Title", "Body")
    assert payload["content"] == "Title\nBody"  # Discord
    assert payload["text"] == "Title\nBody"  # Slack
    assert payload["title"] == "Title" and payload["message"] == "Body"  # generic


def test_multinotifier_fans_out_and_survives_failure():
    ok1 = _RecordingNotifier()
    bad = _RecordingNotifier(fail=True)
    ok2 = _RecordingNotifier()
    MultiNotifier([ok1, bad, ok2]).send("t", "b")
    assert ok1.calls == [("t", "b")]
    assert ok2.calls == [("t", "b")]  # not blocked by the failing notifier in between


def test_alerter_routes_through_notifier():
    rec = _RecordingNotifier()
    Alerter(notifier=rec).send_alert(
        Alert(kind=AlertKind.SCANNER, source="web", ip="1.2.3.4", detail="x")
    )
    assert len(rec.calls) == 1
    title, _ = rec.calls[0]
    assert "1.2.3.4" in title


def test_alerter_cooldown_suppresses_duplicates():
    rec = _RecordingNotifier()
    alerter = Alerter(notifier=rec, cooldown_minutes=60)
    alert = Alert(kind=AlertKind.BRUTE_FORCE, source="web", ip="9.9.9.9", detail="x")
    alerter.send_alert(alert)
    alerter.send_alert(alert)
    assert len(rec.calls) == 1
