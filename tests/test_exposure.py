from lookout.exposure import _exposures_for_container, exposure_alert
from lookout.models import AlertKind, ExposureRisk


def test_localhost_binding_is_not_exposed():
    ports = {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
    assert _exposures_for_container("app", "app:latest", ports) == []


def test_private_ip_binding_is_not_exposed():
    ports = {"8080/tcp": [{"HostIp": "192.168.1.10", "HostPort": "8080"}]}
    assert _exposures_for_container("app", "app:latest", ports) == []


def test_public_ip_binding_is_exposed():
    ports = {"8080/tcp": [{"HostIp": "1.2.3.4", "HostPort": "8080"}]}
    found = _exposures_for_container("app", "app:latest", ports)
    assert len(found) == 1


def test_unpublished_port_is_not_exposed():
    ports = {"9000/tcp": None}  # exposed internally but not published
    assert _exposures_for_container("app", "app:latest", ports) == []


def test_public_database_is_critical():
    ports = {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}
    found = _exposures_for_container("db", "postgres:16", ports)
    assert len(found) == 1
    assert found[0].risk == ExposureRisk.CRITICAL
    assert found[0].service == "PostgreSQL"


def test_public_nonsensitive_port_is_warning():
    ports = {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
    found = _exposures_for_container("app", "app:latest", ports)
    assert len(found) == 1
    assert found[0].risk == ExposureRisk.WARNING
    assert found[0].service == ""


def test_ipv6_wildcard_is_exposed():
    ports = {"6379/tcp": [{"HostIp": "::", "HostPort": "6379"}]}
    found = _exposures_for_container("cache", "redis:7", ports)
    assert found[0].risk == ExposureRisk.CRITICAL


def test_mixed_bindings_only_reports_public():
    ports = {
        "5432/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "5432"},
            {"HostIp": "0.0.0.0", "HostPort": "5432"},
        ]
    }
    found = _exposures_for_container("db", "postgres:16", ports)
    assert len(found) == 1
    assert found[0].host_ip == "0.0.0.0"


def test_exposure_alert_is_immediate():
    ports = {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}
    alert = exposure_alert(_exposures_for_container("db", "postgres:16", ports)[0])
    assert alert.kind == AlertKind.EXPOSURE
    assert alert.immediate is True
    assert "PostgreSQL" in alert.detail
