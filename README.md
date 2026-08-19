# lookout

Self-hosted security monitor for homelabs. It tails your web server logs and sends a plain-English digest of recent activity, plus the occasional real-time alert when something needs attention.

Lookout doesn't block anything — keep fail2ban, CrowdSec, or a WAF for that. It tells you what got through and whether it matters.

## How it works

Findings go to one of two places:

- **Digest** — a summary on whatever schedule you set (daily by default). Routine noise lands here: sensitive-path probes (`.env`, `wp-admin`, `.git`), path traversal and injection attempts, scanning, and brute force.
- **Real-time alerts** — sent immediately and kept rare, for confirmed impact: an error spike (usually your own service breaking) or a container port exposed to the internet. Duplicates are suppressed for a cooldown window.

Log sources are discovered automatically from running Docker containers and common file paths (nginx, Traefik, Caddy, Apache). The digest is written by an AI model — Anthropic, OpenAI, or a local [Ollama](https://ollama.com) instance, which keeps traffic data on your network.

## Quick start

Add to your existing `docker-compose.yml`:

```yaml
services:
  lookout:
    image: ghcr.io/joegarb/lookout:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      # Only needed for services that write log files on the host (not in Docker)
      # - /var/log:/var/log:ro
    environment:
      - OLLAMA_BASE_URL=http://192.168.1.x:11434   # or ANTHROPIC_API_KEY / OPENAI_API_KEY
      - SMTP_HOST=smtp-relay.brevo.com
      - SMTP_PORT=587
      - SMTP_USERNAME=your@email.com
      - SMTP_PASSWORD=your-smtp-key
      - ALERT_EMAIL_TO=you@example.com
      - ALERT_EMAIL_FROM=lookout@yourdomain.com
```

## Configuration

Options are environment variables. At least one AI provider and one notification channel are required.

**AI provider** — `AI_PROVIDER_ORDER` (default `ollama,anthropic,openai`) sets which is tried first.

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OLLAMA_BASE_URL` | — | Local Ollama URL, e.g. `http://192.168.1.x:11434` |
| `OLLAMA_MODEL` | `llama3.2:3b` | Ollama model |
| `AI_PROVIDER_ORDER` | `ollama,anthropic,openai` | Provider preference order |

**Notifications** — alerts and digests go to every configured channel.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | — | SMTP server |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | — | SMTP credentials |
| `SMTP_ENCRYPTION` | `auto` | `auto` (465 → SSL, else STARTTLS), or `ssl` / `starttls` / `none` |
| `ALERT_EMAIL_TO` / `ALERT_EMAIL_FROM` | — | Required when `SMTP_HOST` is set |
| `NTFY_URL` / `NTFY_TOKEN` | — | ntfy topic URL; token only for protected topics |
| `WEBHOOK_URL` | — | JSON POST endpoint (works with Discord/Slack incoming webhooks) |

Send a test through every configured channel:

```bash
docker compose exec lookout python -m lookout.selftest
```

**Advanced options**

| Variable | Default | Description |
|---|---|---|
| `DIGEST_SCHEDULE` | `0 8 * * *` | Digest cron. Uses APScheduler day-of-week (0=Mon … 6=Sun); lookback matches the interval. |
| `ALERT_COOLDOWN_MINUTES` | `60` | Suppress duplicate alerts for this long |
| `IP_ENRICHMENT` | `true` | Annotate IPs with country/network via ip-api.com; `false` disables the lookups |
| `ERROR_SPIKE_HOSTS` | — | Comma-separated host globs to watch for error spikes; non-matching hosts ignored |
| `ERROR_SPIKE_IGNORE_HOSTS` | — | Comma-separated host globs to exclude from error-spike detection |
| `DIGEST_INCLUDE_FILES` | — | Comma-separated report files from other tools, appended verbatim to each digest |

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy lookout/
```

## Evaluating the digest

The digest is model-generated, so its quality is covered by a [promptfoo](https://www.promptfoo.dev) harness in [`evals/`](evals/) rather than the unit tests: a set of scenarios scored by an LLM judge across all three providers. See [`evals/README.md`](evals/README.md).
