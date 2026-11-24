"""The whole chain as real processes: client -> firewall (stdio) -> tool server (stdio)."""

import sys

import pytest
from mcp import Client, StdioServerParameters

from agent_firewall.__main__ import main

pytestmark = pytest.mark.anyio


async def test_firewall_runs_tool_servers_as_subprocesses(tmp_path):
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "notes.txt").write_bytes(b"through two processes")
    (tmp_path / "policy.toml").write_text('[tools."files__*"]\n')
    (tmp_path / "firewall.toml").write_text(
        'policy = "policy.toml"\n'
        "[servers.files]\n"
        'command = "python"\n'
        'args = ["-m", "agent_firewall.tools", "files", "--root", "shared"]\n'
    )
    firewall = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agent_firewall", "--config", str(tmp_path / "firewall.toml")],
    )
    async with Client(firewall) as c:
        names = [t.name for t in (await c.list_tools()).tools]
        result = await c.call_tool("files__read_file", {"path": "notes.txt"})
    assert "files__read_file" in names
    assert result.content[0].text == "through two processes"


def test_a_bad_config_exits_with_a_message(tmp_path, capsys):
    (tmp_path / "bad.toml").write_text("servers = {}")
    assert main(["--config", str(tmp_path / "bad.toml")]) == 2
    assert "agent-firewall:" in capsys.readouterr().err


def test_a_corrupt_pin_file_exits_with_a_message(tmp_path, capsys):
    (tmp_path / "pins.json").write_text("not json")
    (tmp_path / "policy.toml").write_text('[tools."files__*"]\n')
    (tmp_path / "f.toml").write_text(
        'policy = "policy.toml"\npins = "pins.json"\n[servers.files]\ncommand = "x"'
    )
    assert main(["--config", str(tmp_path / "f.toml")]) == 2
    assert "pin file" in capsys.readouterr().err
