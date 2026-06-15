from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Comma-separated provider order; first one with a key present wins
    ai_provider_order: str = "anthropic,openai"
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    # auto (by port: 465=ssl, else starttls), or force ssl / starttls / none
    smtp_encryption: str = "auto"
    alert_email_to: str = ""
    alert_email_from: str = ""

    # ntfy: full topic URL, e.g. https://ntfy.sh/your-topic (token optional, for protected topics)
    ntfy_url: str = ""
    ntfy_token: str = ""
    # Generic webhook (Discord, Slack, Home Assistant, etc.) — receives a JSON POST
    webhook_url: str = ""

    digest_time: str = "08:00"
    alert_cooldown_minutes: int = 60

    docker_socket: str = "unix:///var/run/docker.sock"
    log_buffer_size: int = 50_000

    def validate_ai(self) -> None:
        available = {"anthropic": self.anthropic_api_key, "openai": self.openai_api_key}
        order = [p.strip() for p in self.ai_provider_order.split(",")]
        if not any(available.get(p) for p in order):
            raise ValueError("No AI API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.")

    def validate_notifications(self) -> None:
        if not (self.smtp_host or self.ntfy_url or self.webhook_url):
            raise ValueError(
                "No notification channel configured. Set SMTP_HOST, NTFY_URL, or WEBHOOK_URL."
            )
        if self.smtp_host:
            if not self.alert_email_to:
                raise ValueError("ALERT_EMAIL_TO is required when SMTP_HOST is set")
            if not self.alert_email_from:
                raise ValueError("ALERT_EMAIL_FROM is required when SMTP_HOST is set")


settings = Settings()
