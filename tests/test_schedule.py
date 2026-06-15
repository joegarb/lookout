from apscheduler.triggers.cron import CronTrigger

from lookout.main import digest_period_hours


def test_daily_period_is_24h():
    assert digest_period_hours(CronTrigger(hour=8, minute=0)) == 24


def test_hourly_period_is_1h():
    assert digest_period_hours(CronTrigger.from_crontab("0 * * * *")) == 1


def test_interval_period_matches_gap():
    assert digest_period_hours(CronTrigger.from_crontab("0 */6 * * *")) == 6


def test_weekly_period_is_168h():
    assert digest_period_hours(CronTrigger.from_crontab("0 8 * * 1")) == 168


def test_sub_hour_period_floors_to_1h():
    assert digest_period_hours(CronTrigger.from_crontab("*/15 * * * *")) == 1
