import re
from pathlib import Path

import docker
import docker.errors

from lookout.dockerutil import image_tag
from lookout.models import LogFormat, LogSource, SourceKind

_WELL_KNOWN: list[tuple[Path, LogFormat]] = [
    (Path("/var/log/nginx/access.log"), LogFormat.NGINX_COMBINED),
    (Path("/var/log/apache2/access.log"), LogFormat.APACHE_COMBINED),
    (Path("/var/log/httpd/access.log"), LogFormat.APACHE_COMBINED),
    (Path("/var/log/caddy/access.log"), LogFormat.CADDY_JSON),
    (Path("/var/log/traefik/access.log"), LogFormat.TRAEFIK_JSON),
]

_PROXY_IMAGE_PATTERNS = re.compile(r"nginx|traefik|caddy|apache|httpd", re.IGNORECASE)

_CONTAINER_FORMAT: dict[str, LogFormat] = {
    "nginx": LogFormat.NGINX_COMBINED,
    "traefik": LogFormat.TRAEFIK_JSON,
    "caddy": LogFormat.CADDY_JSON,
    "apache": LogFormat.APACHE_COMBINED,
    "httpd": LogFormat.APACHE_COMBINED,
}


def _format_for_container(image: str, name: str) -> LogFormat:
    combined = f"{image} {name}".lower()
    for keyword, fmt in _CONTAINER_FORMAT.items():
        if keyword in combined:
            return fmt
    return LogFormat.NGINX_COMBINED


def _nginx_config_paths() -> list[Path]:
    paths: list[Path] = []
    sites_enabled = Path("/etc/nginx/sites-enabled")
    conf_d = Path("/etc/nginx/conf.d")
    config_files: list[Path] = [Path("/etc/nginx/nginx.conf")]
    if sites_enabled.exists():
        config_files.extend(sites_enabled.glob("*"))
    if conf_d.exists():
        config_files.extend(conf_d.glob("*.conf"))
    for cf in config_files:
        if not cf.is_file():
            continue
        for match in re.finditer(r"access_log\s+(\S+)", cf.read_text(errors="ignore")):
            p = Path(match.group(1))
            if p != Path("off") and p not in paths:
                paths.append(p)
    return paths


def discover(docker_url: str = "unix:///var/run/docker.sock") -> list[LogSource]:
    sources: list[LogSource] = []
    seen: set[str] = set()

    try:
        client = docker.DockerClient(base_url=docker_url)
        for container in client.containers.list():
            image = image_tag(container)
            name = container.name or ""
            container_id = container.id or ""
            if _PROXY_IMAGE_PATTERNS.search(image) or _PROXY_IMAGE_PATTERNS.search(name):
                key = f"docker:{name}"
                if key not in seen:
                    seen.add(key)
                    sources.append(
                        LogSource(
                            kind=SourceKind.DOCKER,
                            name=name,
                            location=container_id,
                            format=_format_for_container(image, name),
                        )
                    )
        client.close()
    except Exception:
        # Docker socket may not be present or accessible — not fatal
        pass

    for path, fmt in _WELL_KNOWN:
        if path.exists():
            key = f"file:{path}"
            if key not in seen:
                seen.add(key)
                sources.append(
                    LogSource(kind=SourceKind.FILE, name=path.name, location=str(path), format=fmt)
                )

    for path in _nginx_config_paths():
        if path.exists():
            key = f"file:{path}"
            if key not in seen:
                seen.add(key)
                sources.append(
                    LogSource(
                        kind=SourceKind.FILE,
                        name=path.name,
                        location=str(path),
                        format=LogFormat.NGINX_COMBINED,
                    )
                )

    return sources
