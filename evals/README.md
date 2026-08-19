# Digest evals

[DeepEval](https://deepeval.com) suite scoring the generated digest. Everything else is
covered by `tests/`; this hits real models and the grading isn't deterministic, so it is
kept out of the default `pytest` run.

Unlike a provider matrix, DeepEval scores one system under test at a time: it runs
lookout's own provider (selected from the app's env). To compare providers, change the
env and re-run.

## Run

```sh
uv sync
uv run deepeval test run evals/test_digest.py
```

Configure the system under test the same way you configure the app — e.g. Ollama:

```sh
export OLLAMA_BASE_URL=http://192.168.1.x:11434
uv run deepeval test run evals/test_digest.py
```

The judge defaults to the local Ollama model when `OLLAMA_BASE_URL` is set, but a small
local model is both slow and unreliable as a judge. Set `JUDGE` (`anthropic`/`openai`) for
fast, trustworthy scores:

```sh
export ANTHROPIC_API_KEY=...
export AI_PROVIDER_ORDER=anthropic   # system under test = Claude
export JUDGE=anthropic               # judge = Claude
uv run deepeval test run evals/test_digest.py
```

## Configuration

Provider selection and models mirror the app — same var names and defaults.

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_BASE_URL` | — | Ollama server. When set, both the local provider and the judge use it |
| `AI_PROVIDER_ORDER` | `ollama,anthropic,openai` | Which provider is the system under test; first one configured wins |
| `JUDGE` | `ollama` if `OLLAMA_BASE_URL` else `openai` | Grading model: `anthropic`, `openai`, or `ollama` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | — | Enable the Anthropic / OpenAI provider (and OpenAI as the default judge) |
| `OLLAMA_MODEL` | `llama3.2:3b` | Ollama model (system under test and judge) |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Anthropic model |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model |

## Adding a case

An entry in `SCENARIOS` (`scenarios.py`) plus a rubric in `_SCENARIO_METRIC` (`metrics.py`).
