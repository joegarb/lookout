import logging
import signal
import sys

from apscheduler.schedulers.background import BackgroundScheduler

from lookout.alerter import Alerter, SmtpNotifier
from lookout.analyzer import build_provider
from lookout.config import settings
from lookout.detector import Detector
from lookout.digest import DigestBuffer, send_daily_digest
from lookout.discovery import discover
from lookout.exposure import exposure_alert, scan_exposure
from lookout.models import ExposureRisk
from lookout.watcher import start_watchers, stop_watchers

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    settings.validate_ai()
    settings.validate_notifications()

    sources = discover(settings.docker_socket)
    if not sources:
        logger.error("no log sources found — nothing to watch")
        sys.exit(1)

    for s in sources:
        logger.info("discovered %s source: %s (%s)", s.kind.value, s.name, s.format.value)

    ai = build_provider(
        settings.ai_provider_order, settings.anthropic_api_key, settings.openai_api_key
    )
    notifier = SmtpNotifier(
        host=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username,
        password=settings.smtp_password,
        to_addr=settings.alert_email_to,
        from_addr=settings.alert_email_from,
        use_tls=settings.smtp_use_tls,
    )
    alerter = Alerter(notifier=notifier, cooldown_minutes=settings.alert_cooldown_minutes)
    detector = Detector()
    buffer = DigestBuffer(maxsize=settings.log_buffer_size)

    # Catch dangerous exposure (e.g. a database published to the internet) at startup,
    # rather than waiting up to a day for the first digest.
    for exposure in scan_exposure(settings.docker_socket):
        if exposure.risk == ExposureRisk.CRITICAL:
            alerter.send_alert(exposure_alert(exposure))

    hour, minute = (int(p) for p in settings.digest_time.split(":"))
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        send_daily_digest,
        trigger="cron",
        hour=hour,
        minute=minute,
        args=[buffer, ai, alerter, settings.docker_socket],
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
