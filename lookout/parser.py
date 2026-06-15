import json
import re
from datetime import UTC, datetime

from lookout.models import LogEntry, LogFormat

_NGINX_RE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r"(?P<status>\d{3}) (?P<bytes>\d+|-) "
    r'"[^"]*" "(?P<ua>[^"]*)"'
)
_NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_nginx(line: str, source: str) -> LogEntry | None:
    m = _NGINX_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], _NGINX_TIME_FMT).astimezone(UTC).replace(tzinfo=None)
        return LogEntry(
            timestamp=ts,
            ip=m["ip"],
            method=m["method"],
            path=m["path"],
            status=int(m["status"]),
            bytes_sent=int(m["bytes"]) if m["bytes"] != "-" else 0,
            user_agent=m["ua"],
            source=source,
        )
    except (ValueError, KeyError):
        return None


def _parse_traefik(line: str, source: str) -> LogEntry | None:
    try:
        d = json.loads(line.strip())
        ts = (
            datetime.fromisoformat(d.get("time", d.get("StartUTC", "")).replace("Z", "+00:00"))
            .astimezone(UTC)
            .replace(tzinfo=None)
        )
        return LogEntry(
            timestamp=ts,
            ip=d.get("ClientHost", ""),
            method=d.get("RequestMethod", ""),
            path=d.get("RequestPath", ""),
            status=int(d.get("DownstreamStatus", 0)),
            bytes_sent=int(d.get("DownstreamContentSize", 0)),
            user_agent=d.get("request_User-Agent", ""),
            source=source,
        )
    except (ValueError, KeyError, json.JSONDecodeError):
        # Fall back to CLF — traefik can be configured to log in either format
        return _parse_nginx(line, source)


def _parse_caddy(line: str, source: str) -> LogEntry | None:
    try:
        d = json.loads(line.strip())
        req = d.get("request", {})
        ts = datetime.fromtimestamp(d["ts"], UTC).replace(tzinfo=None)
        return LogEntry(
            timestamp=ts,
            ip=d.get("request", {}).get("remote_ip", ""),
            method=req.get("method", ""),
            path=req.get("uri", ""),
            status=int(d.get("status", 0)),
            bytes_sent=int(d.get("size", 0)),
            user_agent=req.get("headers", {}).get("User-Agent", [""])[0],
            source=source,
        )
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


_PARSERS = {
    LogFormat.NGINX_COMBINED: _parse_nginx,
    LogFormat.APACHE_COMBINED: _parse_nginx,  # same format
    LogFormat.TRAEFIK_JSON: _parse_traefik,
    LogFormat.CADDY_JSON: _parse_caddy,
}


def parse_line(line: str, fmt: LogFormat, source: str) -> LogEntry | None:
    return _PARSERS[fmt](line, source)


def detect_format(sample_lines: list[str]) -> LogFormat | None:
    for line in sample_lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                d = json.loads(line)
                if "RequestMethod" in d or "DownstreamStatus" in d:
                    return LogFormat.TRAEFIK_JSON
                if "request" in d and "ts" in d:
                    return LogFormat.CADDY_JSON
            except json.JSONDecodeError:
                pass
        if _NGINX_RE.match(line):
            return LogFormat.NGINX_COMBINED
    return None
