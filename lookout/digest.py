import logging
from collections import deque
from datetime import UTC, datetime, timedelta
from threading import Lock

from lookout.alerter import Alerter
from lookout.analyzer import AIProvider, digest_prompt
from lookout.models import LogEntry

logger = logging.getLogger(__name__)


class DigestBuffer:
    def __init__(self, maxsize: int = 50_000) -> None:
        self._buf: deque[LogEntry] = deque(maxlen=maxsize)
        self._lock = Lock()

    def add(self, entry: LogEntry) -> None:
        with self._lock:
            self._buf.append(entry)

    def last_24h(self) -> list[LogEntry]:
        cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
        with self._lock:
            return [e for e in self._buf if e.timestamp >= cutoff]


def send_daily_digest(buffer: DigestBuffer, ai: AIProvider, alerter: Alerter) -> None:
    logger.info("generating daily digest")
    entries = buffer.last_24h()
    prompt = digest_prompt(entries)
    try:
        summary = ai.complete(prompt)
        alerter.send_digest(summary)
    except Exception:
        logger.exception("digest generation failed")
