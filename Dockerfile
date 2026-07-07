FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1
# Put the uv venv on PATH so `python` / `lookout` resolve to it (e.g. for `python -m lookout.selftest`)
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN pip install uv

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY lookout/ lookout/
RUN uv sync --frozen --no-dev && test -f /app/.venv/bin/lookout

CMD ["lookout"]
