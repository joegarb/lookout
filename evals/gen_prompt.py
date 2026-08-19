"""promptfoo hook: render the real digest_prompt for context['vars']['scenario']."""

from typing import Any

from evals.scenarios import SCENARIOS
from lookout.analyzer import digest_prompt


def create_prompt(context: dict[str, Any]) -> str:
    s = SCENARIOS[context["vars"]["scenario"]]
    return digest_prompt(s.entries, s.findings, s.exposures, period_hours=s.period_hours)
