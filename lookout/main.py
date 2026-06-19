import logging
import signal
import sys
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from lookout import enrichment
from lookout.alerter import (
    Alerter,
    MultiNotifier,
    Notifier,
    NtfyNotifier,
    SmtpNotifier,
    WebhookNotifier,
    resolve_smtp_encryption,
)
from lookout.analyzer import build_provider
from lookout.config import Settings, settings
from lookout.detector import Detector
from lookout.digest import DigestBuffer, send_digest
from lookout.discovery import discover
from lookout.exposure import exposure_alert, scan_exposure
from lookout.models import ExposureRisk
from lookout.watcher import start_watchers, stop_watchers

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def digest_period_hours(trigger: CronTrigger) -> int:
    # Lookback window = the gap between two consecutive runs, so each digest covers
    # exactly the activity since the previous one (24h daily, 1h hourly, etc.).
    now = datetime.now().astimezone()
    first: datetime = trigger.get_next_fire_time(None, now)
    second: datetime = trigger.get_next_fire_time(first, first + timedelta(seconds=1))
    hours = round((second - first).total_seconds() / 3600)
    return max(int(hours), 1)


def build_notifier(cfg: Settings) -> MultiNotifier:
    notifiers: list[Notifier] = []
    if cfg.smtp_host:
        notifiers.append(
            SmtpNotifier(
                host=cfg.smtp_host,
                port=cfg.smtp_port,
                username=cfg.smtp_username,
                password=cfg.smtp_password,
                to_addr=cfg.alert_email_to,
                from_addr=cfg.alert_email_from,
                encryption=resolve_smtp_encryption(cfg.smtp_encryption, cfg.smtp_port),
            )
        )
    if cfg.ntfy_url:
        notifiers.append(NtfyNotifier(cfg.ntfy_url, cfg.ntfy_token or None))
    if cfg.webhook_url:
        notifiers.append(WebhookNotifier(cfg.webhook_url))
    for n in notifiers:
        logger.info("notifications enabled: %s", type(n).__name__)
    return MultiNotifier(notifiers)


def main() -> None:
    settings.validate_ai()
    settings.validate_notifications()
    enrichment.configure(settings.ip_enrichment)

    sources = discover(settings.docker_socket)
    if not sources:
        logger.error("no log sources found — nothing to watch")
        sys.exit(1)

    for s in sources:
        logger.info("discovered %s source: %s (%s)", s.kind.value, s.name, s.format.value)

    ai = build_provider(
        settings.ai_provider_order, settings.anthropic_api_key, settings.openai_api_key
    )
    alerter = Alerter(
        notifier=build_notifier(settings), cooldown_minutes=settings.alert_cooldown_minutes
    )

    def _parse_patterns(s: str) -> list[str]:
        return [p.strip() for p in s.split(",") if p.strip()]

    detector = Detector(
        host_allowlist=_parse_patterns(settings.error_spike_hosts),
        host_denylist=_parse_patterns(settings.error_spike_ignore_hosts),
    )
    buffer = DigestBuffer(maxsize=settings.log_buffer_size)

    # Catch dangerous exposure (e.g. a database published to the internet) at startup,
    # rather than waiting up to a day for the first digest.
    for exposure in scan_exposure(settings.docker_socket):
        if exposure.risk == ExposureRisk.CRITICAL:
            alerter.send_alert(exposure_alert(exposure))

    trigger = CronTrigger.from_crontab(settings.digest_schedule)
    period_hours = digest_period_hours(trigger)
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        send_digest,
        trigger=trigger,
        args=[buffer, ai, alerter, settings.docker_socket, period_hours],
    )
    scheduler.start()

    threads, observer, stop_event = start_watchers(
        sources, settings.docker_socket, detector, buffer, alerter
    )

    def _shutdown(sig: int, _: object) -> None:
        logger.info("shutting down")
        stop_watchers(threads, observer, stop_event)
        scheduler.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("lookout is running")
    stop_event.wait()


if __name__ == "__main__":
    main()
