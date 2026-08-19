"""Digest eval scenarios, fed through the real digest_prompt by gen_prompt.py."""

from dataclasses import dataclass, field
from datetime import datetime

from lookout.models import Alert, AlertKind, Exposure, ExposureRisk, LogEntry

_T = datetime(2026, 8, 17, 3, 0, 0)


@dataclass
class Scenario:
    entries: list[LogEntry] = field(default_factory=list)
    findings: list[Alert] = field(default_factory=list)
    exposures: list[Exposure] = field(default_factory=list)
    period_hours: int = 24


def _entry(
    ip: str,
    method: str,
    path: str,
    status: int,
    ua: str = "curl/8.5",
    source: str = "traefik",
) -> LogEntry:
    return LogEntry(_T, ip, method, path, status, 0, ua, source, host="lab.example.com")


SCENARIOS: dict[str, Scenario] = {
    # exposed db + probing; the db should lead
    "critical_db_exposed": Scenario(
        entries=[
            _entry("45.9.1.2", "GET", "/.env", 404),
            _entry("45.9.1.2", "GET", "/wp-admin/", 404),
            _entry("8.8.8.8", "GET", "/", 200, ua="Mozilla/5.0"),
        ],
        findings=[
            Alert(
                AlertKind.SENSITIVE_PATH,
                "traefik",
                "45.9.1.2",
                "probing for /.env and /wp-admin",
                immediate=False,
            ),
        ],
        exposures=[
            Exposure(
                "app-db",
                "postgres:16",
                "0.0.0.0",
                "5432",
                "5432/tcp",
                "PostgreSQL",
                ExposureRisk.CRITICAL,
            ),
        ],
    ),
    # just noise; should read as normal
    "routine_scanning_only": Scenario(
        entries=[
            _entry("103.5.2.7", "GET", "/.git/config", 404),
            _entry("103.5.2.7", "GET", "/phpmyadmin/", 404),
            _entry("62.4.9.10", "POST", "/xmlrpc.php", 404),
            _entry("8.8.4.4", "GET", "/", 200, ua="Mozilla/5.0"),
        ],
        findings=[
            Alert(
                AlertKind.SCANNER,
                "traefik",
                "103.5.2.7",
                "scanning for common admin paths",
                immediate=False,
            ),
        ],
    ),
    # 5xx spike; own service, not an attack
    "real_error_spike": Scenario(
        entries=(
            [
                _entry("198.51.100.23", "POST", "/api/checkout", 500, ua="Mozilla/5.0")
                for _ in range(40)
            ]
            + [_entry("198.51.100.24", "GET", "/", 200, ua="Mozilla/5.0")]
        ),
        findings=[
            Alert(
                AlertKind.ERROR_SPIKE,
                "traefik",
                "-",
                "40 HTTP 500s on /api/checkout in 5 minutes",
                immediate=False,
            ),
        ],
    ),
    # sensitive file actually served (200, not a 404 probe); confirmed impact
    "sensitive_path_hit": Scenario(
        entries=[
            _entry("45.9.1.2", "GET", "/.env", 200),
            _entry("45.9.1.2", "GET", "/.git/config", 200),
            _entry("8.8.8.8", "GET", "/", 200, ua="Mozilla/5.0"),
        ],
        findings=[
            Alert(
                AlertKind.SENSITIVE_PATH,
                "traefik",
                "45.9.1.2",
                "/.env served with 200 (file is publicly readable)",
                immediate=True,
            ),
        ],
    ),
    # WARNING-level exposure (a plain web app, not a datastore); note it, don't alarm
    "exposure_warning": Scenario(
        entries=[
            _entry("8.8.8.8", "GET", "/", 200, ua="Mozilla/5.0"),
        ],
        exposures=[
            Exposure(
                "webapp",
                "nginx:1.27-alpine",
                "0.0.0.0",
                "8080",
                "8080/tcp",
                "",
                ExposureRisk.WARNING,
            ),
        ],
    ),
    # benign day; nothing to report, must not invent concerns
    "all_clear": Scenario(
        entries=[
            _entry("8.8.8.8", "GET", "/", 200, ua="Mozilla/5.0"),
            _entry("8.8.4.4", "GET", "/blog/hello", 200, ua="Mozilla/5.0"),
            _entry("1.1.1.1", "GET", "/favicon.ico", 200, ua="Mozilla/5.0"),
        ],
    ),
}
