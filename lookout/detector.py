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


class Detector:
    def __init__(self, max_tracked_ips: int = 10_000) -> None:
        self._max_tracked_ips = max_tracked_ips
        self._lock = threading.Lock()
        self._auth_hits: OrderedDict[str, deque[tuple[datetime, str]]] = OrderedDict()
        self._path_hits: OrderedDict[str, deque[tuple[datetime, str]]] = OrderedDict()
        # sources are bounded (a handful of services), so no cap needed here
        self._error_hits: dict[str, deque[datetime]] = defaultdict(deque)

    def _get_ip_deque(
        self,
        d: OrderedDict[str, deque[tuple[datetime, str]]],
        ip: str,
    ) -> deque[tuple[datetime, str]]:
        if ip not in d:
            if len(d) >= self._max_tracked_ips:
                d.popitem(last=False)
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
        if _SENSITIVE_PATHS.search(entry.path) or _INJECTION_PATTERNS.search(entry.path):
            return [
                Alert(
                    kind=AlertKind.SENSITIVE_PATH,
                    source=entry.source,
                    ip=entry.ip,
                    detail=f"{entry.method} {entry.path} → {entry.status}",
                    entries=[entry],
                )
            ]
        return []

    def _check_brute_force(self, entry: LogEntry) -> list[Alert]:
        if not _AUTH_PATHS.search(entry.path):
            return []
        q = self._get_ip_deque(self._auth_hits, entry.ip)
        q.append((entry.timestamp, entry.path))
        cutoff = entry.timestamp - _BRUTE_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        if len(q) == _BRUTE_THRESHOLD:
            return [
                Alert(
                    kind=AlertKind.BRUTE_FORCE,
                    source=entry.source,
                    ip=entry.ip,
                    detail=f"{len(q)} auth requests in {_BRUTE_WINDOW}",
                )
            ]
        return []

    def _check_scanner(self, entry: LogEntry) -> list[Alert]:
        q = self._get_ip_deque(self._path_hits, entry.ip)
        q.append((entry.timestamp, entry.path))
        cutoff = entry.timestamp - _SCAN_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        distinct = len({p for _, p in q})
        if distinct == _SCAN_THRESHOLD:
            return [
                Alert(
                    kind=AlertKind.SCANNER,
                    source=entry.source,
                    ip=entry.ip,
                    detail=f"{distinct} distinct paths in {_SCAN_WINDOW}",
                )
            ]
        return []

    def _check_error_spike(self, entry: LogEntry) -> list[Alert]:
        if entry.status < 400:
            return []
        q = self._error_hits[entry.source]
        q.append(entry.timestamp)
        cutoff = entry.timestamp - _ERROR_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) == _ERROR_THRESHOLD:
            return [
                Alert(
                    kind=AlertKind.ERROR_SPIKE,
                    source=entry.source,
                    ip=entry.ip,
                    detail=f"{len(q)} errors in {_ERROR_WINDOW}",
                )
            ]
        return []
