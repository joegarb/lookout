import dataclasses
import re
import threading
from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timedelta
from urllib.parse import unquote

from lookout.models import Alert, AlertKind, LogEntry

_AUTH_PATHS = re.compile(r"/(login|signin|auth|wp-login|admin/login|user/login)", re.IGNORECASE)
_SENSITIVE_PATHS = re.compile(
    r"(\.\./|/(\.|wp-admin|wp-config|\.env|\.git|\.htaccess|phpinfo|server-status|actuator|"
    r"config\.php|setup\.php|install\.php|admin|phpmyadmin|pma|adminer|shell\.php|c99\.php|"
    r"r57\.php|cmd\.php))",
    re.IGNORECASE,
)
_INJECTION_PATTERNS = re.compile(
    r"(\$\{jndi:|union\s+select|<script[\s>]|/etc/passwd|/proc/self)",
    re.IGNORECASE,
)

_BRUTE_WINDOW = timedelta(minutes=5)
_BRUTE_THRESHOLD = 20
_SCAN_WINDOW = timedelta(minutes=5)
_SCAN_THRESHOLD = 30
_ERROR_WINDOW = timedelta(minutes=1)
_ERROR_THRESHOLD = 50


def _path_prefix(path: str) -> str:
    parts = path.split("/")
    prefix = "/".join(parts[:3])  # keep at most two segments, e.g. /api/v1
    return (prefix or "/")[:40]


def _is_success(status: int) -> bool:
    """A 2xx response means the request was actually served (not blocked/missing)."""
    return 200 <= status < 300


class Detector:
    def __init__(self, max_tracked_ips: int = 10_000) -> None:
        self._max_tracked_ips = max_tracked_ips
        self._lock = threading.Lock()
        self._auth_hits: OrderedDict[str, deque[tuple[datetime, str]]] = OrderedDict()
        self._path_hits: OrderedDict[str, deque[tuple[datetime, str]]] = OrderedDict()
        # sources are bounded (a handful of services), so no cap needed here
        self._error_hits: dict[str, deque[tuple[datetime, LogEntry]]] = defaultdict(deque)
        # keys currently over threshold — so we alert once on crossing, not per line
        self._brute_active: set[str] = set()
        self._scan_active: set[str] = set()
        self._error_active: set[str] = set()

    def _get_ip_deque(
        self,
        d: OrderedDict[str, deque[tuple[datetime, str]]],
        active: set[str],
        ip: str,
    ) -> deque[tuple[datetime, str]]:
        if ip not in d:
            if len(d) >= self._max_tracked_ips:
                old, _ = d.popitem(last=False)
                active.discard(old)
            d[ip] = deque()
        return d[ip]

    def process(self, entry: LogEntry) -> list[Alert]:
        # Decode percent-encoded paths so evasion attempts like /.%65nv are caught
        entry = dataclasses.replace(entry, path=unquote(entry.path))
        alerts: list[Alert] = []
        with self._lock:
            alerts.extend(self._check_sensitive(entry))
            alerts.extend(self._check_brute_force(entry))
            alerts.extend(self._check_scanner(entry))
            alerts.extend(self._check_error_spike(entry))
        return alerts

    def _check_sensitive(self, entry: LogEntry) -> list[Alert]:
        if not (_SENSITIVE_PATHS.search(entry.path) or _INJECTION_PATTERNS.search(entry.path)):
            return []
        detail = f"{entry.method} {entry.path} → {entry.status}"
        if _is_success(entry.status):
            # The probe worked — the file/path was actually served. Interrupt-worthy.
            return [
                Alert(
                    kind=AlertKind.SENSITIVE_HIT,
                    source=entry.source,
                    ip=entry.ip,
                    detail=detail,
                    immediate=True,
                    entries=[entry],
                )
            ]
        # A blocked/missing probe is background noise — record it for the digest only.
        return [
            Alert(
                kind=AlertKind.SENSITIVE_PATH,
                source=entry.source,
                ip=entry.ip,
                detail=detail,
                immediate=False,
                entries=[entry],
            )
        ]

    def _crossed(self, count: int, threshold: int, key: str, active: set[str]) -> bool:
        """True only on the transition up to the threshold; resets once below again."""
        if count >= threshold:
            if key in active:
                return False
            active.add(key)
            return True
        active.discard(key)
        return False

    def _check_brute_force(self, entry: LogEntry) -> list[Alert]:
        if not _AUTH_PATHS.search(entry.path):
            return []
        q = self._get_ip_deque(self._auth_hits, self._brute_active, entry.ip)
        q.append((entry.timestamp, entry.path))
        cutoff = entry.timestamp - _BRUTE_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        if self._crossed(len(q), _BRUTE_THRESHOLD, entry.ip, self._brute_active):
            return [
                Alert(
                    kind=AlertKind.BRUTE_FORCE,
                    source=entry.source,
                    ip=entry.ip,
                    detail=f"{len(q)} auth requests in {_BRUTE_WINDOW}",
                    immediate=False,
                )
            ]
        return []

    def _check_scanner(self, entry: LogEntry) -> list[Alert]:
        q = self._get_ip_deque(self._path_hits, self._scan_active, entry.ip)
        q.append((entry.timestamp, entry.path))
        cutoff = entry.timestamp - _SCAN_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        distinct = len({p for _, p in q})
        if self._crossed(distinct, _SCAN_THRESHOLD, entry.ip, self._scan_active):
            return [
                Alert(
                    kind=AlertKind.SCANNER,
                    source=entry.source,
                    ip=entry.ip,
                    detail=f"{distinct} distinct paths in {_SCAN_WINDOW}",
                    immediate=False,
                )
            ]
        return []

    def _check_error_spike(self, entry: LogEntry) -> list[Alert]:
        if entry.status < 400:
            return []
        q = self._error_hits[entry.source]
        q.append((entry.timestamp, entry))
        cutoff = entry.timestamp - _ERROR_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        if self._crossed(len(q), _ERROR_THRESHOLD, entry.source, self._error_active):
            group_counts: dict[tuple[int, str], int] = defaultdict(int)
            group_paths: dict[tuple[int, str], list[str]] = defaultdict(list)
            for _, e in q:
                key = (e.status, e.host)
                group_counts[key] += 1
                prefix = _path_prefix(e.path)
                if prefix not in group_paths[key]:
                    group_paths[key].append(prefix)
            lines = [f"{len(q)} errors in {_ERROR_WINDOW}"]
            for (status, host), count in sorted(group_counts.items(), key=lambda x: -x[1])[:5]:
                label = f"  {host + ' ' if host else ''}{status} \xd7{count}:"
                prefixes = group_paths[(status, host)]
                shown = prefixes[:3]
                ellipsis = ", ..." if len(prefixes) > 3 else ""
                lines.append(f"{label} {', '.join(shown)}{ellipsis}")
            # Errors come from many IPs; attributing the spike to one is misleading.
            return [
                Alert(
                    kind=AlertKind.ERROR_SPIKE,
                    source=entry.source,
                    ip="-",
                    detail="\n".join(lines),
                    immediate=True,
                )
            ]
        return []
