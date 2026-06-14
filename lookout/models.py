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


class AlertKind(Enum):
    BRUTE_FORCE = "brute_force"
    SCANNER = "scanner"
    ERROR_SPIKE = "error_spike"
    SENSITIVE_PATH = "sensitive_path"


@dataclass
class Alert:
    kind: AlertKind
    source: str
    ip: str
    detail: str
    entries: list[LogEntry] = field(default_factory=list)
