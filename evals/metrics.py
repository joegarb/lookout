"""Metrics for the digest eval: GEval rubrics plus one deterministic check.

The judge is chosen by JUDGE (anthropic | openai | ollama); it defaults to ollama when
OLLAMA_BASE_URL is set, else DeepEval's default (OpenAI). A small local judge is slow and
perhaps unreliable — set JUDGE=anthropic or JUDGE=openai for scores you can trust.
"""

import os

from deepeval.metrics import BaseMetric, GEval
from deepeval.models import AnthropicModel, DeepEvalBaseLLM, OllamaModel
from deepeval.test_case import LLMTestCase, SingleTurnParams
from scenarios import IP_RE

from lookout.enrichment import _is_public

_IO = [SingleTurnParams.INPUT, SingleTurnParams.ACTUAL_OUTPUT]


def _build_judge() -> DeepEvalBaseLLM | None:
    base = os.environ.get("OLLAMA_BASE_URL")
    judge = os.environ.get("JUDGE", "ollama" if base else "openai").lower()
    if judge == "anthropic":
        return AnthropicModel(model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"))
    if judge == "ollama" and base:
        return OllamaModel(model=os.environ.get("OLLAMA_MODEL", "llama3.2:3b"), base_url=base)
    return None  # openai / DeepEval's default judge


_JUDGE = _build_judge()


class NoHallucinatedIP(BaseMetric):
    """Deterministic: the digest must not cite a public IP absent from the input.

    Loopback/private/0.0.0.0 are networking concepts a good digest may reference, so only
    public IPs count — mirroring lookout's own `_is_public`.
    """

    _required_params = [SingleTurnParams.ACTUAL_OUTPUT]

    def __init__(self, threshold: float = 1.0) -> None:
        self.threshold = threshold
        self.async_mode = False
        self.include_reason = True

    def measure(self, test_case: LLMTestCase) -> float:
        allowed = set((test_case.additional_metadata or {}).get("input_ips", []))
        found = {ip for ip in IP_RE.findall(test_case.actual_output) if _is_public(ip)}
        invented = sorted(found - allowed)
        self.score = 0.0 if invented else 1.0
        self.success = self.score >= self.threshold
        self.reason = "no invented public IPs" if not invented else f"invented: {invented}"
        return self.score

    async def a_measure(self, test_case: LLMTestCase) -> float:
        return self.measure(test_case)

    def is_successful(self) -> bool:
        if self.error is not None:
            self.success = False
        elif self.success is None:
            self.success = (self.score or 0) >= self.threshold
        return self.success

    @property
    def __name__(self) -> str:
        return "No hallucinated IP"


def _rubric(name: str, steps: list[str], threshold: float = 0.8) -> GEval:
    return GEval(
        name=name,
        model=_JUDGE,
        evaluation_params=_IO,
        evaluation_steps=steps,
        threshold=threshold,
    )


def _structure() -> GEval:
    return GEval(
        name="Structure",
        model=_JUDGE,
        evaluation_params=[SingleTurnParams.ACTUAL_OUTPUT],
        criteria=(
            "The digest gives a clear one-line overall assessment, notable findings, and "
            "any recommended actions."
        ),
        threshold=0.7,
    )


_SCENARIO_METRIC = {
    "critical_db_exposed": lambda: _rubric(
        "Severity ordering",
        [
            "The exposed PostgreSQL database (a CRITICAL finding) must be the single most "
            "prominent item and framed as something to fix now.",
            "The concurrent scanning/probing must NOT be presented as the main concern.",
        ],
    ),
    "routine_scanning_only": lambda: _rubric(
        "No alarmism",
        [
            "Ordinary background scanning/probing must not be described as an attack or an "
            "emergency.",
            "The overall assessment should read as broadly safe/normal, not 'needs attention'.",
        ],
    ),
    "real_error_spike": lambda: _rubric(
        "Error-spike framing",
        [
            "The spike in 5xx/server errors must be identified as most likely the owner's own "
            "service failing, with a suggestion to check that service.",
            "It must NOT be framed as an external attack.",
        ],
    ),
    "sensitive_path_hit": lambda: _rubric(
        "Sensitive-hit framing",
        [
            "Sensitive files returning 200 (e.g. /.env being publicly readable) must be treated "
            "as a real, serious problem needing action.",
            "It must NOT be dismissed as harmless routine probing or scanning.",
        ],
    ),
    "exposure_warning": lambda: _rubric(
        "Warning proportionality",
        [
            "The exposed web service on all interfaces is noted as worth reviewing or confirming "
            "it is intentional.",
            "It must NOT be framed as a critical, fix-now emergency on par with an exposed "
            "database, cache, or the Docker API.",
        ],
    ),
    "all_clear": lambda: _rubric(
        "No invented concern",
        [
            "The overall assessment is safe/normal.",
            "The digest must not invent security concerns or recommend urgent action when there "
            "is nothing wrong.",
        ],
    ),
}


def metrics_for(scenario: str) -> list[BaseMetric]:
    """The shared checks plus the one rubric specific to this scenario."""
    return [NoHallucinatedIP(), _structure(), _SCENARIO_METRIC[scenario]()]
