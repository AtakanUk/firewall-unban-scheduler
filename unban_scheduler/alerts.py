"""Collects ERROR records during a run and mails them once at the end.

A cron job that fails for 300 rows should produce one mail, not 300.
"""

from __future__ import annotations

import html
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage


class BufferedErrorHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.records: list[logging.LogRecord] = []
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def drain(self) -> list[str]:
        lines = [self.format(record) for record in self.records]
        self.records.clear()
        return lines


def install() -> BufferedErrorHandler:
    handler = BufferedErrorHandler()
    logging.getLogger().addHandler(handler)
    return handler


def flush(handler: BufferedErrorHandler, context: str) -> bool:
    """Mail the buffered errors (if any) to ``ALERT_MAIL_TO``; returns True if a mail was sent."""
    lines = handler.drain()
    recipients = [
        item.strip() for item in os.environ.get("ALERT_MAIL_TO", "").split(",") if item.strip()
    ]
    if not lines or not recipients or not os.environ.get("SMTP_HOST"):
        return False

    message = EmailMessage()
    message["Subject"] = f"[unban-scheduler] {len(lines)} error(s) - {context}"
    message["From"] = os.environ.get("MAIL_FROM", "unban-scheduler@example.com")
    message["To"] = ", ".join(recipients)
    message.set_content("\n\n".join(lines))
    message.add_alternative(
        "<html><body><h3>"
        + html.escape(context)
        + "</h3>"
        + "".join(f"<pre style='white-space:pre-wrap'>{html.escape(line)}</pre>" for line in lines)
        + "</body></html>",
        subtype="html",
    )
    try:
        with smtplib.SMTP(
            os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "25")), timeout=30
        ) as smtp:
            if os.environ.get("SMTP_STARTTLS", "false").lower() == "true":
                smtp.starttls(context=ssl.create_default_context())
            if os.environ.get("SMTP_USERNAME"):
                smtp.login(os.environ["SMTP_USERNAME"], os.environ.get("SMTP_PASSWORD", ""))
            smtp.send_message(message)
    except Exception as exc:
        # WARNING, not ERROR: an ERROR here would land in the buffer of the next run.
        logging.getLogger(__name__).warning("Could not send the error mail: %s", exc)
        return False
    return True
