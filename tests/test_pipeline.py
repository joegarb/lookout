"""Integration tests: raw log line → parser → detector → alert."""

import json
from datetime import UTC, datetime

from lookout.detector import Detector
from lookout.models import AlertKind, LogFormat
from lookout.parser import parse_line

TRAEFIK_LINE = json.dumps(
    {
        "ClientHost": "1.2.3.4",
        "RequestMethod": "GET",
        "RequestPath": "/.env",
        "DownstreamStatus": 404,
        "DownstreamContentSize": 0,
        "RequestHost": "app.example.com",
        "time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "request_User-Agent": "curl/7.88",
    }
)

NGINX_LINE = '5.6.7.8 - - [10/Jun/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.88"'


def _parse(line: str, fmt: LogFormat) -> object:
    entry = parse_line(line, fmt, "test")
    assert entry is not None
    return entry


def test_traefik_sensitive_path_detected_end_to_end():
    entry = _parse(TRAEFIK_LINE, LogFormat.TRAEFIK_JSON)
    alerts = Detector().process(entry)
    assert any(a.kind == AlertKind.SENSITIVE_PATH for a in alerts)


def test_traefik_host_preserved_through_pipeline():
    entry = _parse(TRAEFIK_LINE, LogFormat.TRAEFIK_JSON)
    assert entry.host == "app.example.com"  # type: ignore[union-attr]


def test_nginx_sensitive_path_detected_end_to_end():
    entry = _parse(NGINX_LINE, LogFormat.NGINX_COMBINED)
    alerts = Detector().process(entry)
    assert any(a.kind == AlertKind.SENSITIVE_PATH for a in alerts)


def test_traefik_error_spike_end_to_end():
    detector = Detector()
    alerts = []
    for i in range(50):
        line = json.dumps(
            {
                "ClientHost": "1.2.3.4",
                "RequestMethod": "GET",
                "RequestPath": f"/api/{i}",
                "DownstreamStatus": 502,
                "DownstreamContentSize": 0,
                "RequestHost": "app.example.com",
                "time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "request_User-Agent": "curl/7.88",
            }
        )
        entry = parse_line(line, LogFormat.TRAEFIK_JSON, "traefik")
        assert entry is not None
        alerts.extend(detector.process(entry))
    assert any(a.kind == AlertKind.ERROR_SPIKE for a in alerts)
