import os
import urllib.request

import pytest

from lookout.analyzer import OllamaProvider, build_provider
from lookout.config import Settings

# Opt out of DeepEval's telemetry. conftest loads before the test modules that import
# deepeval, so setting it here (rather than above the imports) takes effect in time.
os.environ.setdefault("DEEPEVAL_TELEMETRY_OPT_OUT", "YES")


def _reachable(url: str) -> bool:
    try:
        urllib.request.urlopen(f"{url.rstrip('/')}/api/tags", timeout=3)
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def provider():
    """lookout's real provider, selected from the app's own env (system under test)."""
    s = Settings()
    try:
        p = build_provider(
            s.ai_provider_order,
            s.anthropic_api_key,
            s.anthropic_model,
            s.openai_api_key,
            s.openai_model,
            s.ollama_base_url,
            s.ollama_model,
        )
    except ValueError as e:
        pytest.skip(str(e))
    # Fail fast if Ollama is the system under test but unreachable — its calls otherwise hang.
    if isinstance(p, OllamaProvider) and not _reachable(s.ollama_base_url or ""):
        pytest.skip(f"Ollama not reachable at {s.ollama_base_url}")
    return p
