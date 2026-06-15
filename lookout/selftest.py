"""Send a test alert through every configured channel, to verify delivery works.

Run it against a running container:

    docker compose exec lookout python -m lookout.selftest
"""

import logging

from lookout.config import settings
from lookout.main import build_notifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    settings.validate_notifications()
    notifier = build_notifier(settings)
    notifier.send(
        "[lookout] Test alert",
        "This is a test alert from lookout. If you received it, alerting is set up correctly.",
    )
    logger.info("test alert dispatched to all configured channels")


if __name__ == "__main__":
    main()
