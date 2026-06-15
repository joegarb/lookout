from typing import Any


def image_tag(container: Any) -> str:
    """First image tag of a container, or "" if it has none (e.g. untagged build)."""
    img = container.image
    return img.tags[0] if img and img.tags else ""
