# lookout

Self-hosted homelab security monitor for non-security-experts. Watches your web server logs, spots suspicious traffic in real-time, and emails you a plain-English daily digest so you know what's going on without having to be a security professional.

## What it watches for

- **Brute force** — repeated auth attempts from the same IP
- **Scanning** — IPs probing many different paths in a short window
- **Sensitive path probes** — requests for `.env`, `wp-admin`, `.git`, admin panels, and common web shells
- **Path traversal** — `../` sequences attempting to escape the web root
- **Injection probes** — Log4Shell (`${jndi:`), SQL injection, and similar payload patterns
- **Error spikes** — sudden surges in 4xx/5xx responses

Discovery is automatic: it finds log sources from running Docker containers and well-known file paths (nginx, Traefik, Caddy, Apache) — no manual config needed.

If you use fail2ban or CrowdSec, those tools may ban IPs before lookout's brute-force threshold is reached — that's fine, it means they're working. Lookout covers what they don't: scanning patterns, sensitive path probes, and injection attempts. If traffic passes through a WAF or Cloudflare before hitting your server, lookout only sees what those filters let through (which is still the traffic that matters).

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
