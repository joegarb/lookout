# lookout

Self-hosted homelab security monitor for non-security-experts. It watches your web server logs and tells you what's going on in two ways: a **plain-English digest** (daily by default) so you stay aware without reading access logs, and **rare real-time alerts** reserved for things that actually need you *now*.

## What it tells you, and when

Lookout splits findings into two channels:

- **Digest** — a plain-English summary of recent activity, on whatever schedule you set (daily by default). This is where the constant noise goes: sensitive-path probes (`.env`, `wp-admin`, `.git`), path traversal and injection attempts (`../`, Log4Shell, SQL injection), scanning, and brute force.
- **Real-time alerts** — emailed immediately and kept rare, for confirmed impact: an error spike that usually means your own service is broken, or a container port that's dangerously exposed. Repeats are suppressed for a cooldown window so one event can't flood your inbox.

Discovery is automatic: it finds log sources from running Docker containers and well-known file paths (nginx, Traefik, Caddy, Apache) — no manual config needed.

Lookout doesn't block anything, so keep running fail2ban, CrowdSec, or a WAF to actually stop attacks — lookout just tells you, in plain English, what got through and whether you should care.

## Quick start

Add to your existing `docker-compose.yml`:

```yaml
services:
  lookout:
    image: ghcr.io/joegarb/lookout:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      # Only needed if services run on the host and write log files (not in Docker containers)
      # - /var/log:/var/log:ro
    environment:
      - ANTHROPIC_API_KEY=sk-ant-...   # or OPENAI_API_KEY, or both
      - SMTP_HOST=smtp-relay.brevo.com
      - SMTP_PORT=587
      - SMTP_USERNAME=your@email.com
      - SMTP_PASSWORD=your-smtp-key
      - ALERT_EMAIL_TO=you@example.com
      - ALERT_EMAIL_FROM=lookout@yourdomain.com
    restart: unless-stopped
```

## Configuration

### AI

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `AI_PROVIDER_ORDER` | `anthropic,openai` | Which provider to prefer when multiple keys are set |

At least one key is required. If both are set, `AI_PROVIDER_ORDER` controls which is used first.

### Notifications

Configure any combination of the channels below — alerts and the digest are sent to all of them. At least one is required.

**Email (SMTP)**

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | — | SMTP server (e.g. `smtp-relay.brevo.com`) |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `SMTP_ENCRYPTION` | `auto` | `auto` picks by port (465 → SSL, otherwise STARTTLS). Override with `ssl`, `starttls`, or `none`. |
| `ALERT_EMAIL_TO` | — | Recipient address (required if `SMTP_HOST` is set) |
| `ALERT_EMAIL_FROM` | — | Sender address (required if `SMTP_HOST` is set) |

**ntfy** (push to your phone/desktop)

| Variable | Default | Description |
|---|---|---|
| `NTFY_URL` | — | Full topic URL, e.g. `https://ntfy.sh/your-topic` |
| `NTFY_TOKEN` | — | Access token, only for protected topics |

**Webhook** (Discord, Slack, Home Assistant, etc.)

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | — | Receives a JSON POST; the payload includes `content`/`text` so Discord and Slack incoming webhooks work as-is |

To confirm delivery is working, send a test through every configured channel:

```bash
docker compose exec lookout python -m lookout.selftest
```

### General

| Variable | Default | Description |
|---|---|---|
| `DIGEST_SCHEDULE` | `0 8 * * *` | Cron expression for the digest (default 8am daily; e.g. `0 * * * *` hourly, `0 8 * * 0` 8am Mondays). **Note:** day_of_week uses APScheduler convention (0=Mon, 1=Tue, …, 6=Sun), not standard cron (where 0=Sun). The lookback window matches the interval automatically. |
| `ALERT_COOLDOWN_MINUTES` | `60` | Suppress duplicate alerts for this long |
| `IP_ENRICHMENT` | `true` | Annotate IPs with country/network via ip-api.com (so alerts read "… from DigitalOcean, Germany"). Set `false` to disable the external lookups. |
| `ERROR_SPIKE_HOSTS` | — | Comma-separated glob patterns of hosts to monitor for error spikes (e.g. `myapp.example.com,*.prod.example.com`). If set, hosts that don't match are ignored. |
| `ERROR_SPIKE_IGNORE_HOSTS` | — | Comma-separated glob patterns of hosts to exclude from error spike detection (e.g. `lab.example.com,*.catchall.example.com`). Useful for Traefik catchall routes or hosts with no real service behind them. |

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy lookout/
```
