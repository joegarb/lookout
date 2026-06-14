import json

from lookout.models import LogFormat
from lookout.parser import detect_format, parse_line

NGINX_LINE = (
    '1.2.3.4 - - [10/Jun/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
)

TRAEFIK_LINE = json.dumps(
    {
        "ClientHost": "5.6.7.8",
        "RequestMethod": "POST",
        "RequestPath": "/api/login",
        "DownstreamStatus": 401,
        "DownstreamContentSize": 42,
        "time": "2026-06-10T12:00:00Z",
        "request_User-Agent": "curl/7.88",
    }
)

CADDY_LINE = json.dumps(
    {
        "ts": 1749556800.0,
        "request": {
            "method": "GET",
            "uri": "/health",
            "remote_ip": "9.10.11.12",
            "headers": {"User-Agent": ["Go-http-client/1.1"]},
        },
        "status": 200,
        "size": 2,
    }
)


def test_parse_nginx_basic():
    entry = parse_line(NGINX_LINE, LogFormat.NGINX_COMBINED, "nginx")
    assert entry is not None
    assert entry.ip == "1.2.3.4"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.status == 200
    assert entry.bytes_sent == 1234
    assert entry.source == "nginx"


def test_parse_nginx_bad_line():
    assert parse_line("not a log line", LogFormat.NGINX_COMBINED, "nginx") is None


def test_parse_traefik():
    entry = parse_line(TRAEFIK_LINE, LogFormat.TRAEFIK_JSON, "traefik")
    assert entry is not None
    assert entry.ip == "5.6.7.8"
    assert entry.method == "POST"
    assert entry.path == "/api/login"
    assert entry.status == 401


def test_parse_caddy():
    entry = parse_line(CADDY_LINE, LogFormat.CADDY_JSON, "caddy")
    assert entry is not None
    assert entry.ip == "9.10.11.12"
    assert entry.method == "GET"
    assert entry.path == "/health"
    assert entry.status == 200


def test_detect_format_nginx():
    assert detect_format([NGINX_LINE]) == LogFormat.NGINX_COMBINED


def test_detect_format_traefik():
    assert detect_format([TRAEFIK_LINE]) == LogFormat.TRAEFIK_JSON


def test_detect_format_caddy():
    assert detect_format([CADDY_LINE]) == LogFormat.CADDY_JSON


def test_detect_format_empty():
    assert detect_format([]) is None


def test_detect_format_skips_blanks():
    assert detect_format(["", "  ", NGINX_LINE]) == LogFormat.NGINX_COMBINED
