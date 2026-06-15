import textwrap
from collections import Counter
from datetime import datetime, timedelta
from typing import Protocol
from urllib.parse import urlsplit

import anthropic
import openai

from lookout import enrichment
from lookout.models import Alert, Exposure, ExposureRisk, LogEntry


class AIProvider(Protocol):
    def complete(self, prompt: str) -> str: ...


class AnthropicProvider:
    def __init__(self, api_key: str) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)

    def complete(self, prompt: str) -> str:
        msg = self._client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text  # type: ignore[union-attr]


class OpenAIProvider:
    def __init__(self, api_key: str) -> None:
        self._client = openai.OpenAI(api_key=api_key)

    def complete(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model="gpt-4o",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content or ""


def build_provider(
    provider_order: str,
    anthropic_key: str | None,
    openai_key: str | None,
) -> AIProvider:
    available: dict[str, str] = {}
    if anthropic_key:
        available["anthropic"] = anthropic_key
    if openai_key:
        available["openai"] = openai_key

    for name in [p.strip() for p in provider_order.split(",")]:
        if name in available:
            if name == "anthropic":
                return AnthropicProvider(available[name])
            if name == "openai":
                return OpenAIProvider(available[name])

    raise ValueError("No usable AI provider — check API keys and AI_PROVIDER_ORDER")


def _summarise_entries(entries: list[LogEntry]) -> str:
    if not entries:
        return "No log entries recorded."

    def _strip_qs(path: str) -> str:
        return urlsplit(path).path

    total = len(entries)
    status_counts = Counter(e.status for e in entries)
    top_ips = Counter(e.ip for e in entries).most_common(5)
    top_paths = Counter(_strip_qs(e.path) for e in entries).most_common(10)
    errors = [e for e in entries if e.status >= 400]

    # Resolve every IP we're about to print in one batch, then annotate each.
    enrichment.prefetch([ip for ip, _ in top_ips] + [e.ip for e in errors[:20]])
    top_ips_str = ", ".join(f"{ip}{enrichment.describe(ip)} ({n})" for ip, n in top_ips)

    lines = [
        f"Total requests: {total}",
        f"Status codes: {dict(status_counts)}",
        f"Top IPs: {top_ips_str}",
        f"Top paths: {top_paths}",
        f"Error requests ({len(errors)} total, sample of up to 20):",
    ]
    for e in errors[:20]:
        path = _strip_qs(e.path)
        lines.append(
            f"  {e.timestamp.isoformat()} {e.ip}{enrichment.describe(e.ip)} "
            f"{e.method} {path} {e.status}"
        )

    return "\n".join(lines)


def _summarise_findings(findings: list[Alert]) -> str:
    if not findings:
        return "No suspicious patterns were flagged."

    enrichment.prefetch(f.ip for f in findings)
    by_kind = Counter(f.kind.value for f in findings)
    lines = ["Flagged patterns (low-confidence — not individually alerted):"]
    for kind, count in by_kind.most_common():
        top_ips = Counter(f.ip for f in findings if f.kind.value == kind).most_common(5)
        ips_str = ", ".join(f"{ip}{enrichment.describe(ip)} ({n})" for ip, n in top_ips)
        lines.append(f"  {kind}: {count} events; top IPs: {ips_str}")
    return "\n".join(lines)


def _summarise_exposure(exposures: list[Exposure]) -> str:
    if not exposures:
        return "Exposure check: no containers are publishing ports to all interfaces."

    # Surface CRITICAL findings first.
    ordered = sorted(exposures, key=lambda e: e.risk != ExposureRisk.CRITICAL)
    lines = ["Exposure check (containers reachable on all interfaces):"]
    for e in ordered:
        label = "CRITICAL" if e.risk == ExposureRisk.CRITICAL else "WARNING"
        service = f"{e.service} " if e.service else ""
        lines.append(
            f"  {label}: {service}container '{e.container}' on "
            f"{e.host_ip}:{e.host_port} ({e.container_port})"
        )
    return "\n".join(lines)


def digest_prompt(
    entries: list[LogEntry],
    findings: list[Alert] | None = None,
    exposures: list[Exposure] | None = None,
    period_hours: int = 24,
) -> str:
    summary = _summarise_entries(entries)
    findings_summary = _summarise_findings(findings or [])
    exposure_summary = _summarise_exposure(exposures or [])
    since = (datetime.now() - timedelta(hours=period_hours)).strftime("%Y-%m-%d %H:%M")
    return textwrap.dedent(f"""
        You are a security assistant for a self-hosted homelab. Analyse the following web server
        traffic summary from the last {period_hours} hours (since {since}) and write a plain-English
        digest for the homelab owner.

        Structure your response as:
        1. A one-sentence overall assessment (safe / some concerns / needs attention)
        2. Notable findings (bullet points) — patterns, anomalies, or anything worth knowing
        3. Recommended actions (if any) — specific and actionable
        4. A closing note if everything looks normal

        Be concise. Avoid jargon. The owner is technically literate but not a security professional.
        Probing and scanning are constant background noise on any public server; only call them out
        if the volume or pattern is genuinely unusual. Focus the owner's attention on what changed.
        Treat any CRITICAL exposure as the most important thing to report — a database, cache,
        or Docker API reachable from the internet is a serious misconfiguration to fix now.

        Traffic summary:
        {summary}

        {findings_summary}

        {exposure_summary}
    """).strip()
