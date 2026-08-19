# Digest evals

promptfoo harness scoring the generated digest across all three: Ollama, Anthropic, OpenAI.
Not wired into `pytest` since this hits real models and the grading isn't deterministic.

## Run

```sh
npm install
./run.sh
npm run view
```

A bare `./run.sh` runs all three providers, so it needs a reachable Ollama plus both API
keys. Run a subset with `--filter-providers`, e.g. Ollama only:

```sh
export OLLAMA_BASE_URL=http://192.168.1.x:11434
./run.sh --filter-providers ollama
```

## Configuration

Model names and keys mirror the app — same var names and defaults. `GRADER` is eval-only.

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables the Anthropic column (unset = skipped) |
| `OPENAI_API_KEY` | — | Enables the OpenAI column (unset = skipped) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server for the local column and grader |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Anthropic model under test |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model under test |
| `OLLAMA_MODEL` | `llama3.2:3b` | Ollama model under test |
| `GRADER` | `ollama:chat:llama3.2:3b` | Judge provider id (`provider:apitype:model`). The local default grades unreliably — set a cloud model for scores you can trust, e.g. `anthropic:messages:claude-sonnet-4-6` or `openai:chat:gpt-4o` |

## Adding a case

An entry in `SCENARIOS` plus a matching block in `cases.yaml`.
