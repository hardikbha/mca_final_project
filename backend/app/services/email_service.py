"""Email service stub — logs instead of sending via an external provider."""

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


async def send_email(
    to: str,
    subject: str,
    html_body: str,
    attachment_path: str | None = None,
) -> dict[str, Any]:
    """Log the email instead of sending it. Drop-in replacement for any provider."""
    now = datetime.now(timezone.utc).isoformat()
    logger.info(
        "EMAIL LOGGED | to=%s | subject=%s | attachment=%s | time=%s",
        to,
        subject,
        attachment_path or "(none)",
        now,
    )
    return {
        "status": "logged",
        "to": to,
        "subject": subject,
        "has_attachment": attachment_path is not None,
        "logged_at": now,
        "note": "Email logged to console. Plug in SendGrid/SES/Resend for production delivery.",
    }
