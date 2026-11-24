from email import message_from_bytes
from email.policy import default

import pytest
from mcp import Client

from agent_firewall.tools.email_outbox import MAX_RECIPIENTS, build_server

pytestmark = pytest.mark.anyio


def text(result):
    return "\n".join(block.text for block in result.content)


async def send(outbox, **args):
    async with Client(build_server(outbox)) as c:
        return await c.call_tool("send_report", args)


async def test_writes_one_message_to_the_outbox(tmp_path):
    outbox = tmp_path / "outbox"
    result = await send(
        outbox, to=["soc@example.com"], subject="Night report", body="2 failed root logins."
    )
    receipt = result.structured_content
    assert receipt["sent"] is False and receipt["recipients"] == 1
    [file] = outbox.iterdir()
    assert file.name == receipt["file"]
    message = message_from_bytes(file.read_bytes(), policy=default)
    assert message["To"] == "soc@example.com" and message["Subject"] == "Night report"
    assert message.get_content().strip() == "2 failed root logins."


@pytest.mark.parametrize(
    "subject",
    ["Report\r\nBcc: attacker@evil.example", "Report\nX-Exfil: yes", "Report\x00", "", " "],
)
async def test_header_injection_is_refused(tmp_path, subject):
    result = await send(tmp_path / "o", to=["soc@example.com"], subject=subject, body="x")
    assert result.is_error
    assert not list((tmp_path / "o").iterdir())


@pytest.mark.parametrize(
    "address",
    ["soc@example.com\r\nBcc: a@b.co", "no-at-sign", "a@localhost", "a b@example.com", "@x.com"],
)
async def test_bad_addresses_are_refused(tmp_path, address):
    result = await send(tmp_path / "o", to=[address], subject="s", body="x")
    assert result.is_error and "valid email" in text(result)


async def test_recipient_and_size_limits(tmp_path):
    many = [f"u{i}@example.com" for i in range(MAX_RECIPIENTS + 1)]
    assert (await send(tmp_path / "o", to=many, subject="s", body="x")).is_error
    assert (await send(tmp_path / "o", to=[], subject="s", body="x")).is_error
    big = await send(tmp_path / "o", to=["a@example.com"], subject="s", body="x" * 100_001)
    assert big.is_error and "too long" in text(big)


async def test_two_reports_never_overwrite_each_other(tmp_path):
    outbox = tmp_path / "o"
    for _ in range(2):
        await send(outbox, to=["a@example.com"], subject="same", body="same")
    assert len(list(outbox.iterdir())) == 2
