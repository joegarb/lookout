import ipaddress
import json
import logging
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ip-api.com: free, no key, batch endpoint (up to 100 IPs/request). HTTPS is paid-only,
# but geolocation of observed IPs over plaintext is not sensitive.
_BATCH_URL = "http://ip-api.com/batch?fields=query,status,country,as"
_BATCH_SIZE = 100
_TIMEOUT = 10

_enabled = False
_cache: dict[str, "IPInfo"] = {}


@dataclass(frozen=True)
class IPInfo:
    country: str = ""
    org: str = ""  # ASN organisation, e.g. "DigitalOcean, LLC"

    def label(self) -> str:
        """A trailing ` (Org, Country)` suffix, or "" when nothing is known."""
        parts = [p for p in (self.org, self.country) if p]
        return f" ({', '.join(parts)})" if parts else ""


_EMPTY = IPInfo()


def configure(enabled: bool) -> None:
    global _enabled
    _enabled = enabled


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False  # not an IP (e.g. the "-" used for source-wide alerts)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )


def _lookup_batch(ips: list[str]) -> dict[str, IPInfo]:
    payload = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        _BATCH_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            results = json.load(resp)
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        logger.warning("IP enrichment lookup failed: %s", exc)
        return {}

    found: dict[str, IPInfo] = {}
    for r in results:
        if not isinstance(r, dict) or r.get("status") != "success":
            continue
        asn = r.get("as", "")
        # "as" arrives as "AS14061 DigitalOcean, LLC" — drop the leading AS number.
        org = asn.split(" ", 1)[1] if asn.startswith("AS") and " " in asn else asn
        found[r.get("query", "")] = IPInfo(country=r.get("country", ""), org=org)
    return found


def prefetch(ips: Iterable[str]) -> None:
    """Resolve a set of IPs in as few batched requests as possible, populating the cache."""
    if not _enabled:
        return
    pending = sorted({ip for ip in ips if _is_public(ip) and ip not in _cache})
    for start in range(0, len(pending), _BATCH_SIZE):
        chunk = pending[start : start + _BATCH_SIZE]
        found = _lookup_batch(chunk)
        for ip in chunk:
            _cache[ip] = found.get(ip, _EMPTY)  # cache misses too, so we don't re-query


def info(ip: str) -> IPInfo:
    if not _enabled or not _is_public(ip):
        return _EMPTY
    if ip not in _cache:
        prefetch([ip])
    return _cache.get(ip, _EMPTY)


def describe(ip: str) -> str:
    return info(ip).label()
