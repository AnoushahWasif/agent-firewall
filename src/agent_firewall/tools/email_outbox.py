"""Draft an email report. Nothing is ever sent: each message is written to an outbox folder.

This is the agent's way of sending data out, so in attack tests it's where stolen secrets would
go. Writing to a folder keeps that harmless and lets the tests read exactly what left.
"""

import re
import uuid
from datetime import UTC, datetime
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel

MAX_RECIPIENTS = 10
MAX_SUBJECT_CHARS = 200
MAX_BODY_CHARS = 100_000
SENDER = "agent@agent-firewall.invalid"
ADDRESS = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")


class Receipt(BaseModel):
    file: str
    recipients: int
    sent: bool = False


def build_server(outbox: Path) -> MCPServer:
    outbox.mkdir(parents=True, exist_ok=True)
    server = MCPServer("email")

    @server.tool()
    def send_report(to: list[str], subject: str, body: str) -> Receipt:
        """Draft an email report to one or more addresses. It goes to the outbox for review."""
        if not 1 <= len(to) <= MAX_RECIPIENTS:
            raise ToolError(f"Send to 1 to {MAX_RECIPIENTS} addresses")
        for address in to:
            if not ADDRESS.fullmatch(address):
                raise ToolError("Not a valid email address")
        # A newline in a header would let the model add headers of its own (Bcc, for one).
        if not subject.strip() or len(subject) > MAX_SUBJECT_CHARS:
            raise ToolError(f"Subject must be 1 to {MAX_SUBJECT_CHARS} characters")
        if any(c in subject for c in "\r\n\x00"):
            raise ToolError("Subject can't contain line breaks")
        if len(body) > MAX_BODY_CHARS:
            raise ToolError("Body is too long")

        message = EmailMessage(policy=SMTP)
        message["From"] = SENDER
        message["To"] = ", ".join(to)
        message["Subject"] = subject
        message["Date"] = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S +0000")
        message.set_content(body)
        name = f"{datetime.now(UTC):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}.eml"
        (outbox / name).write_bytes(message.as_bytes())
        return Receipt(file=name, recipients=len(to))

    return server
