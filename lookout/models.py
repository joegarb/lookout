from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class LogFormat(Enum):
    NGINX_COMBINED = "nginx_combined"
    TRAEFIK_JSON = "traefik_json"
    APACHE_COMBINED = "apache_combined"
    CADDY_JSON = "caddy_json"


class SourceKind(Enum):
    DOCKER = "docker"
    FILE = "file"


@dataclass
class LogSource:
    kind: SourceKind
    name: str
    location: str
    format: LogFormat


@dataclass
class LogEntry:
    timestamp: datetime
    ip: str
    method: str
    path: str
    status: int
    bytes_sent: int
    user_agent: str
    source: str
    host: str = ""


class AlertKind(Enum):
    BRUTE_FORCE = "brute_force"
    SCANNER = "scanner"
    ERROR_SPIKE = "error_spike"
    SENSITIVE_PATH = "sensitive_path"
    SENSITIVE_HIT = "sensitive_hit"
    EXPOSURE = "exposure"


class ExposureRisk(Enum):
    CRITICAL = "critical"  # a database, cache, or the Docker API open to the world
    WARNING = "warning"  # anything else published on all interfaces


@dataclass
class Exposure:
    container: str
    image: str
    host_ip: str
    host_port: str
    container_port: str  # e.g. "5432/tcp"
    service: str  # human name like "PostgreSQL", or "" if unknown
    risk: ExposureRisk


@dataclass
class Alert:
    kind: AlertKind
    source: str
    ip: str
    detail: str
    # immediate alerts are emailed at once; non-immediate ones feed the digest
    immediate: bool = True
    entries: list[LogEntry] = field(default_factory=list)
