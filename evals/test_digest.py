"""Scores the generated digest per scenario. Run with `deepeval test run evals/test_digest.py`.

The system under test is lookout's own provider (selected from the app's env); DeepEval has
no provider matrix, so to compare providers you set the env and re-run.
"""

import pytest
from deepeval import assert_test
from deepeval.test_case import LLMTestCase
from metrics import metrics_for
from scenarios import SCENARIOS, scenario_ips

from lookout.analyzer import AIProvider, digest_prompt


@pytest.mark.parametrize("scenario", list(SCENARIOS), ids=list(SCENARIOS))
def test_digest(scenario: str, provider: AIProvider) -> None:
    sc = SCENARIOS[scenario]
    prompt = digest_prompt(sc.entries, sc.findings, sc.exposures, period_hours=sc.period_hours)
    test_case = LLMTestCase(
        input=prompt,
        actual_output=provider.complete(prompt),
        additional_metadata={"input_ips": scenario_ips(scenario)},
    )
    assert_test(test_case, metrics_for(scenario))
