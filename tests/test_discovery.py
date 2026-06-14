from pathlib import Path
from unittest.mock import MagicMock, patch

from lookout.discovery import discover
from lookout.models import LogFormat, SourceKind


def test_discover_well_known_file(tmp_path: Path):
    log_file = tmp_path / "access.log"
    log_file.write_text("")

    well_known = [(log_file, LogFormat.NGINX_COMBINED)]
    with (
        patch("lookout.discovery._WELL_KNOWN", well_known),
        patch("lookout.discovery.docker.DockerClient", side_effect=Exception),
        patch("lookout.discovery._nginx_config_paths", return_value=[]),
    ):
        sources = discover()

    assert len(sources) == 1
    assert sources[0].kind == SourceKind.FILE
    assert sources[0].format == LogFormat.NGINX_COMBINED


def test_discover_no_sources_when_nothing_present():
    with (
        patch("lookout.discovery._WELL_KNOWN", []),
        patch("lookout.discovery.docker.DockerClient", side_effect=Exception),
        patch("lookout.discovery._nginx_config_paths", return_value=[]),
    ):
        sources = discover()

    assert sources == []


def test_discover_docker_container():
    mock_container = MagicMock()
    mock_container.image.tags = ["nginx:latest"]
    mock_container.name = "my-nginx"
    mock_container.id = "abc123"

    mock_client = MagicMock()
    mock_client.containers.list.return_value = [mock_container]

    with (
        patch("lookout.discovery.docker.DockerClient", return_value=mock_client),
        patch("lookout.discovery._WELL_KNOWN", []),
        patch("lookout.discovery._nginx_config_paths", return_value=[]),
    ):
        sources = discover()

    assert len(sources) == 1
    assert sources[0].kind == SourceKind.DOCKER
    assert sources[0].format == LogFormat.NGINX_COMBINED
    assert sources[0].name == "my-nginx"


def test_discover_deduplicates_file_sources(tmp_path: Path):
    log_file = tmp_path / "access.log"
    log_file.write_text("")

    # Same path appears in both well-known list and nginx config — should only be discovered once
    well_known = [(log_file, LogFormat.NGINX_COMBINED)]
    with (
        patch("lookout.discovery._WELL_KNOWN", well_known),
        patch("lookout.discovery.docker.DockerClient", side_effect=Exception),
        patch("lookout.discovery._nginx_config_paths", return_value=[log_file]),
    ):
        sources = discover()

    assert len(sources) == 1
