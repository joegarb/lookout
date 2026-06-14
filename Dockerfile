FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install uv

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY lookout/ lookout/
RUN uv sync --frozen --no-dev && test -f /app/.venv/bin/lookout

CMD ["/app/.venv/bin/lookout"]
