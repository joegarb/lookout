import json
import logging
import smtplib
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from typing import Protocol

from lookout import enrichment
from lookout.models import Alert

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 10


class Notifier(Protocol):
    def send(self, title: str, body: str) -> None: ...


def resolve_smtp_encryption(mode: str, port: int) -> str:
    """Map the configured mode to a concrete scheme.

    "auto" picks by port: 465 is implicit TLS (SMTPS), everything else is STARTTLS —
    which is what the common submission port 587 actually expects.
    """
    mode = mode.lower()
    if mode in ("ssl", "starttls", "none"):
        return mode
    return "ssl" if port == 465 else "starttls"


class SmtpNotifier:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        to_addr: str,
        from_addr: str,
        encryption: str = "starttls",
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._to = to_addr
        self._from = from_addr
        self._encryption = encryption

    def send(self, title: str, body: str) -> None:
        msg = MIMEText(body)
        msg["Subject"] = title
        msg["From"] = self._from
        msg["To"] = self._to
        try:
            if self._encryption == "ssl":
                with smtplib.SMTP_SSL(self._host, self._port) as smtp:
                    self._deliver(smtp, msg)
            else:
                with smtplib.SMTP(self._host, self._port) as smtp:
                    if self._encryption == "starttls":
                        smtp.starttls()
                    self._deliver(smtp, msg)
        except (smtplib.SMTPException, OSError) as exc:
            logger.error("SMTP send failed for '%s': %s", title, exc)

    def _deliver(self, smtp: smtplib.SMTP, msg: MIMEText) -> None:
        if self._username:
            smtp.login(self._username, self._password)
        smtp.send_message(msg)


def _post(url: str, data: bytes, headers: dict[str, str], label: str) -> None:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT):
            pass
    except (urllib.error.URLError, OSError) as exc:
        logger.error("%s send failed: %s", label, exc)


class NtfyNotifier:
    def __init__(self, url: str, token: str | None = None) -> None:
        self._url = url
        self._token = token

    def send(self, title: str, body: str) -> None:
        # ntfy carries the title in a header, which must be ASCII-safe.
        headers = {"Title": title.encode("ascii", "replace").decode("ascii")}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        _post(self._url, body.encode("utf-8"), headers, "ntfy")


def _webhook_payload(title: str, body: str) -> dict[str, str]:
    text = f"{title}\n{body}"
    # "content" satisfies Discord, "text" satisfies Slack, and title/message cover
    # generic consumers — so one payload works across the common webhook targets.
    return {"title": title, "message": body, "content": text, "text": text}


class WebhookNotifier:
    def __init__(self, url: str) -> None:
        self._url = url

    def send(self, title: str, body: str) -> None:
        data = json.dumps(_webhook_payload(title, body)).encode("utf-8")
        _post(self._url, data, {"Content-Type": "application/json"}, "webhook")


class MultiNotifier:
    """Fans an alert out to every configured channel; one failing channel can't block the rest."""

    def __init__(self, notifiers: list[Notifier]) -> None:
        self._notifiers = notifiers

    def send(self, title: str, body: str) -> None:
        for notifier in self._notifiers:
            try:
                notifier.send(title, body)
            except Exception:
                logger.exception("notifier %s failed", type(notifier).__name__)


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
        title = f"[lookout] {alert.kind.value.replace('_', ' ').title()} - {alert.ip}"
        ip_line = ""
        if alert.ip and alert.ip != "-":
            ip_line = f"\nIP: {alert.ip}{enrichment.describe(alert.ip)}"
        body = f"Source: {alert.source}{ip_line}\nDetail: {alert.detail}"
        self._notifier.send(title, body)
        logger.info("alert sent: %s", title)

    def send_digest(self, body: str) -> None:
        self._notifier.send("[lookout] Security digest", body)
        logger.info("digest sent")
