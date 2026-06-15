import logging
from collections import deque
from datetime import UTC, datetime, timedelta
from threading import Lock

from lookout.alerter import Alerter
from lookout.analyzer import AIProvider, digest_prompt
from lookout.exposure import scan_exposure
from lookout.models import Alert, LogEntry

logger = logging.getLogger(__name__)


class DigestBuffer:
    def __init__(self, maxsize: int = 50_000) -> None:
        self._buf: deque[LogEntry] = deque(maxlen=maxsize)
        self._findings: deque[tuple[datetime, Alert]] = deque(maxlen=maxsize)
        self._lock = Lock()

    def add(self, entry: LogEntry) -> None:
        with self._lock:
            self._buf.append(entry)

    def add_finding(self, alert: Alert) -> None:
        # Non-immediate alerts (probes, scanning, failed brute force) surface in the digest.
        with self._lock:
            self._findings.append((datetime.now(UTC).replace(tzinfo=None), alert))

    def last_24h(self) -> list[LogEntry]:
        cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
        with self._lock:
            return [e for e in self._buf if e.timestamp >= cutoff]

    def last_24h_findings(self) -> list[Alert]:
        cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
        with self._lock:
            return [a for ts, a in self._findings if ts >= cutoff]


def send_daily_digest(
    buffer: DigestBuffer, ai: AIProvider, alerter: Alerter, docker_url: str
) -> None:
    logger.info("generating daily digest")
    entries = buffer.last_24h()
    findings = buffer.last_24h_findings()
    exposures = scan_exposure(docker_url)
    prompt = digest_prompt(entries, findings, exposures)
    try:
        summary = ai.complete(prompt)
        alerter.send_digest(summary)
    except Exception:
        logger.exception("digest generation failed")
