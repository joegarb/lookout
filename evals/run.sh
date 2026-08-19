#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." # repo root

export PROMPTFOO_DISABLE_TELEMETRY=1
export PROMPTFOO_DISABLE_SHARING=1
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$(pwd)"

# run hooks under the venv so lookout's deps import
if [[ -x .venv/bin/python ]]; then
  export PROMPTFOO_PYTHON="${PROMPTFOO_PYTHON:-$(pwd)/.venv/bin/python}"
fi

# Fail fast if the run will use Ollama but it isn't reachable — promptfoo otherwise
# retries for minutes. Skipped when --filter-providers excludes ollama.
if [[ -n "${OLLAMA_BASE_URL:-}" && ( "$*" != *--filter-providers* || "$*" == *ollama* ) ]]; then
  if ! curl -sf --max-time 3 "${OLLAMA_BASE_URL%/}/api/tags" >/dev/null 2>&1; then
    echo "error: Ollama not reachable at $OLLAMA_BASE_URL" >&2
    exit 1
  fi
fi

# local install if present, else fetch the version pinned in package.json
if [[ -x evals/node_modules/.bin/promptfoo ]]; then
  PROMPTFOO=(evals/node_modules/.bin/promptfoo)
else
  PROMPTFOO=(npx --yes "promptfoo@$(node -p "require('./evals/package.json').devDependencies.promptfoo")")
fi

exec "${PROMPTFOO[@]}" eval -c evals/promptfooconfig.yaml "$@"
