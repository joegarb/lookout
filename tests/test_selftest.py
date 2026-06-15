from lookout import selftest
from lookout.alerter import NtfyNotifier, SmtpNotifier, WebhookNotifier
from lookout.config import Settings
from lookout.main import build_notifier


def test_build_notifier_selects_configured_channels():
    cfg = Settings(ntfy_url="https://ntfy.sh/x", webhook_url="https://example.com/hook")
    types = {type(n) for n in build_notifier(cfg)._notifiers}
    assert types == {NtfyNotifier, WebhookNotifier}


def test_build_notifier_includes_smtp_when_host_set():
    cfg = Settings(smtp_host="smtp.example.com", alert_email_to="a@b.c", alert_email_from="d@e.f")
    types = {type(n) for n in build_notifier(cfg)._notifiers}
    assert types == {SmtpNotifier}


def test_build_notifier_empty_when_nothing_configured():
    assert build_notifier(Settings())._notifiers == []


def test_selftest_sends_through_notifier(monkeypatch):
    sent: list[tuple[str, str]] = []

    class _FakeNotifier:
        def send(self, title: str, body: str) -> None:
            sent.append((title, body))

    monkeypatch.setattr(selftest.settings, "ntfy_url", "https://ntfy.sh/x")
    monkeypatch.setattr(selftest, "build_notifier", lambda cfg: _FakeNotifier())
    selftest.main()

    assert len(sent) == 1
    assert "Test alert" in sent[0][0]
