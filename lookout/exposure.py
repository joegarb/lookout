import ipaddress
from typing import Any

import docker
import docker.errors

from lookout.dockerutil import image_tag
from lookout.models import Alert, AlertKind, Exposure, ExposureRisk

# Ports that should essentially never face the internet directly.
_SENSITIVE_PORTS: dict[int, str] = {
    5432: "PostgreSQL",
    3306: "MySQL/MariaDB",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    5984: "CouchDB",
    2375: "Docker API (plaintext)",
    2376: "Docker API",
}


def _is_public(host_ip: str) -> bool:
    # All-interfaces wildcards are unambiguously internet-reachable.
    if host_ip in {"0.0.0.0", "::", ""}:
        return True
    try:
        addr = ipaddress.ip_address(host_ip)
        return not (addr.is_private or addr.is_loopback)
    except ValueError:
        return False


def _exposures_for_container(
    name: str, image: str, ports: dict[str, list[dict[str, str]] | None]
) -> list[Exposure]:
    """Pure mapping from a container's NetworkSettings.Ports to Exposure findings."""
    found: list[Exposure] = []
    for container_port, bindings in ports.items():
        for binding in bindings or []:
            host_ip = binding.get("HostIp", "")
            if not _is_public(host_ip):
                continue  # private or loopback — not internet-reachable, skip
            try:
                num = int(container_port.split("/")[0])
            except ValueError:
                continue
            service = _SENSITIVE_PORTS.get(num, "")
            risk = ExposureRisk.CRITICAL if service else ExposureRisk.WARNING
            found.append(
                Exposure(
                    container=name,
                    image=image,
                    host_ip=host_ip,
                    host_port=binding.get("HostPort", ""),
                    container_port=container_port,
                    service=service,
                    risk=risk,
                )
            )
    return found


def scan_exposure(docker_url: str = "unix:///var/run/docker.sock") -> list[Exposure]:
    found: list[Exposure] = []
    try:
        client = docker.DockerClient(base_url=docker_url)
        for container in client.containers.list():
            network: dict[str, Any] = container.attrs.get("NetworkSettings") or {}
            ports = network.get("Ports") or {}
            found.extend(
                _exposures_for_container(container.name or "", image_tag(container), ports)
            )
        client.close()
    except Exception:
        # Docker socket may not be present or accessible — not fatal, same as discovery.
        pass
    return found


def exposure_alert(e: Exposure) -> Alert:
    """An immediate alert for a critical exposure (e.g. a database open to the internet)."""
    service = f"{e.service} " if e.service else ""
    return Alert(
        kind=AlertKind.EXPOSURE,
        source=e.container,
        ip="-",
        detail=(
            f"{service}reachable from the internet on "
            f"{e.host_ip}:{e.host_port} ({e.container_port})"
        ),
        immediate=True,
    )
