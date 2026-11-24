"""The agent never talks to a tool server directly: everything goes through the firewall."""

import pytest
from mcp import Client

from agent_firewall.agent.loop import run_task
from agent_firewall.agent.model import Answer, ScriptedModel, ToolCall
from agent_firewall.proxy.server import Upstream, build_firewall
from agent_firewall.tools import email_outbox, files

pytestmark = pytest.mark.anyio


async def test_agent_reads_a_log_and_drafts_a_report_through_the_firewall(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "auth.log").write_bytes(
        b"02:11 sshd: Failed password for root from 203.0.113.9\n"
        b"02:12 sshd: Failed password for root from 203.0.113.9\n"
    )
    firewall = build_firewall(
        [
            Upstream("files", files.build_server(shared)),
            Upstream("email", email_outbox.build_server(tmp_path / "outbox")),
        ]
    )

    def report(transcript):
        failures = transcript[-1].content.count("Failed password")
        return ToolCall(
            "email__send_report",
            {
                "to": ["soc@example.com"],
                "subject": "Night report",
                "body": f"{failures} failed root logins from 203.0.113.9.",
            },
        )

    model = ScriptedModel(
        [ToolCall("files__read_file", {"path": "auth.log"}), report, Answer("Report drafted.")]
    )
    async with Client(firewall) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        run = await run_task("Check last night's auth log and report it.", c, model)

    assert "files__read_file" in tools and "email__send_report" in tools
    assert run.stopped == "answered" and run.tool_calls == 2
    [draft] = (tmp_path / "outbox").iterdir()
    assert "2 failed root logins" in draft.read_text()
