"""Non-LLM promptfoo assertions."""

import re
from typing import Any

from evals.scenarios import SCENARIOS
from lookout.enrichment import _is_public

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _allowed_ips(scenario_key: str) -> set[str]:
    s = SCENARIOS[scenario_key]
    ips = {e.ip for e in s.entries} | {f.ip for f in s.findings}
    ips |= {e.host_ip for e in s.exposures}
    return {ip for ip in ips if _IP.fullmatch(ip)}


def ips_grounded(output: str, context: dict[str, Any]) -> dict[str, Any]:
    """Fail if the digest cites a public IP that wasn't in the scenario input.

    Only public IPs count — loopback/private/0.0.0.0 are networking concepts a good
    digest may reference (e.g. "bound to 0.0.0.0 not 127.0.0.1"), not hallucinations.
    """
    allowed = _allowed_ips(context["vars"]["scenario"])
    found = {ip for ip in _IP.findall(output) if _is_public(ip)}
    invented = sorted(found - allowed)
    return {
        "pass": not invented,
        "score": 0.0 if invented else 1.0,
        "reason": (
            "no invented IPs"
            if not invented
            else f"digest cites IPs absent from the input (hallucinated): {invented}"
        ),
    }
