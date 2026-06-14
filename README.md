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

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy lookout/
```
