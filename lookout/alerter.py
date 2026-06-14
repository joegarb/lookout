import logging
import smtplib
import threading
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from typing import Protocol

from lookout.models import Alert

logger = logging.getLogger(__name__)


class Notifier(Protocol):
    def send(self, title: str, body: str) -> None: ...


class SmtpNotifier:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        to_addr: str,
        from_addr: str,
        use_tls: bool = True,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._to = to_addr
        self._from = from_addr
        self._use_tls = use_tls

    def send(self, title: str, body: str) -> None:
        msg = MIMEText(body)
        msg["Subject"] = title
        msg["From"] = self._from
        msg["To"] = self._to
        try:
            if self._use_tls:
                with smtplib.SMTP_SSL(self._host, self._port) as smtp:
                    smtp.login(self._username, self._password)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(self._host, self._port) as smtp:
                    smtp.starttls()
                    smtp.login(self._username, self._password)
                    smtp.send_message(msg)
        except smtplib.SMTPException as exc:
            logger.error("SMTP send failed for '%s': %s", title, exc)


class Alerter:
    def __init__(self, notifier: Notifier, cooldown_minutes: int = 60) -> None:
        self._notifier = notifier
        self._cooldown = timedelta(minutes=cooldown_minutes)
        self._lock = threading.Lock()
        self._sent: dict[str, datetime] = {}

    def _dedup_key(self, alert: Alert) -> str:
        return f"{alert.kind.value}:{alert.ip}"

    def _should_send(self, alert: Alert) -> bool:
        key = self._dedup_key(alert)
        with self._lock:
            last = self._sent.get(key)
            if last and datetime.now() - last < self._cooldown:
                return False
            self._sent[key] = datetime.now()
            return True

    def send_alert(self, alert: Alert) -> None:
        if not self._should_send(alert):
            logger.debug("suppressed duplicate %s from %s", alert.kind.value, alert.ip)
            return
        title = f"[lookout] {alert.kind.value.replace('_', ' ').title()} — {alert.ip}"
        body = f"Source: {alert.source}\nDetail: {alert.detail}"
        self._notifier.send(title, body)
        logger.info("alert sent: %s", title)

    def send_digest(self, body: str) -> None:
        self._notifier.send("[lookout] Daily digest", body)
        logger.info("digest sent")
