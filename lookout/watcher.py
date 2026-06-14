import logging
import threading
from typing import Any

import docker
import docker.errors
from watchdog.events import FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from lookout.alerter import Alerter
from lookout.detector import Detector
from lookout.digest import DigestBuffer
from lookout.models import LogFormat, LogSource, SourceKind
from lookout.parser import detect_format, parse_line

logger = logging.getLogger(__name__)


def _handle_line(
    line: str,
    fmt: LogFormat,
    source_name: str,
    detector: Detector,
    buffer: DigestBuffer,
    alerter: Alerter,
) -> None:
    entry = parse_line(line, fmt, source_name)
    if not entry:
        return
    buffer.add(entry)
    for alert in detector.process(entry):
        alerter.send_alert(alert)


def _watch_docker(
    source: LogSource,
    docker_url: str,
    detector: Detector,
    buffer: DigestBuffer,
    alerter: Alerter,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            client = docker.DockerClient(base_url=docker_url)
            container = client.containers.get(source.location)
            logger.info("watching docker container %s", source.name)
            for raw in container.logs(stream=True, follow=True, tail=0):
                if stop_event.is_set():
                    break
                line = raw.decode(errors="ignore").strip()
                _handle_line(line, source.format, source.name, detector, buffer, alerter)
            client.close()
        except docker.errors.DockerException as exc:
            logger.warning("docker watch error for %s: %s — retrying in 10s", source.name, exc)
            stop_event.wait(10)


class _TailHandler(FileSystemEventHandler):
    def __init__(
        self,
        path: str,
        fmt: LogFormat,
        source_name: str,
        detector: Detector,
        buffer: DigestBuffer,
        alerter: Alerter,
    ) -> None:
        self._path = path
        self._fmt = fmt
        self._source_name = source_name
        self._detector = detector
        self._buffer = buffer
        self._alerter = alerter
        self._pos = 0
        self._detect_format()

    def _detect_format(self) -> None:
        try:
            with open(self._path) as f:
                sample = [f.readline() for _ in range(10)]
            detected = detect_format(sample)
            if detected:
                self._fmt = detected
        except OSError:
            pass

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.src_path != self._path:
            return
        try:
            with open(self._path) as f:
                f.seek(self._pos)
                for line in f:
                    _handle_line(
                        line,
                        self._fmt,
                        self._source_name,
                        self._detector,
                        self._buffer,
                        self._alerter,
                    )
                self._pos = f.tell()
        except OSError:
            pass


def start_watchers(
    sources: list[LogSource],
    docker_url: str,
    detector: Detector,
    buffer: DigestBuffer,
    alerter: Alerter,
) -> tuple[list[threading.Thread], Any, threading.Event]:
    stop_event = threading.Event()
    threads: list[threading.Thread] = []
    observer = Observer()

    for source in sources:
        if source.kind == SourceKind.DOCKER:
            t = threading.Thread(
                target=_watch_docker,
                args=(source, docker_url, detector, buffer, alerter, stop_event),
                daemon=True,
                name=f"docker-{source.name}",
            )
            threads.append(t)
            t.start()
        else:
            handler = _TailHandler(
                source.location, source.format, source.name, detector, buffer, alerter
            )
            observer.schedule(handler, path=source.location, recursive=False)
            logger.info("watching file %s", source.location)

    if any(s.kind == SourceKind.FILE for s in sources):
        observer.start()

    return threads, observer, stop_event


def stop_watchers(
    threads: list[threading.Thread], observer: Any, stop_event: threading.Event
) -> None:
    stop_event.set()
    observer.stop()
    observer.join()
    for t in threads:
        t.join(timeout=5)
