# lookout

Self-hosted homelab security monitor for non-security-experts. It watches your web server logs and tells you what's going on in two ways: a **plain-English daily digest** so you stay aware without reading access logs, and **rare real-time alerts** reserved for things that actually need you *now*.

## What it tells you, and when

Lookout splits findings into two channels:

- **Daily digest** — a plain-English summary of the last 24 hours. This is where the constant noise goes: sensitive-path probes (`.env`, `wp-admin`, `.git`), path traversal and injection attempts (`../`, Log4Shell, SQL injection) that got blocked, scanning, and failed brute force.
- **Real-time alerts** — emailed immediately and kept rare, for confirmed impact: a probe that *succeeded* (e.g. `.env` returned `200`), or an error spike that usually means your own service is broken. Repeats are suppressed for a cooldown window so one event can't flood your inbox.

It also checks what your containers actually expose. Using the Docker socket, it spots ports published to all interfaces (`0.0.0.0`) — and because Docker bypasses host firewalls like ufw, this catches things a firewall check would miss. A database, cache, or the Docker API left open to the internet is flagged immediately; everything else is noted in the digest.

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

### Notifications (SMTP)

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | — | SMTP server (e.g. `smtp-relay.brevo.com`) |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `SMTP_USE_TLS` | `true` | Whether to use TLS |
| `ALERT_EMAIL_TO` | — | Recipient address |
| `ALERT_EMAIL_FROM` | — | Sender address |

### General

| Variable | Default | Description |
|---|---|---|
| `DIGEST_TIME` | `08:00` | Daily digest time (local, 24h format) |
| `ALERT_COOLDOWN_MINUTES` | `60` | Suppress duplicate alerts for this long |

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy lookout/
```
