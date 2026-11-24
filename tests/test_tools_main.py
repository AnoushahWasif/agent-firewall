import sys

import pytest
from mcp import Client, StdioServerParameters

from agent_firewall.tools.__main__ import build

pytestmark = pytest.mark.anyio


def test_each_server_builds(tmp_path):
    assert build(["files", "--root", str(tmp_path)]).name == "files"
    assert build(["web"]).name == "web"
    assert build(["cves"]).name == "cves"
    assert build(["email", "--outbox", str(tmp_path / "o")]).name == "email"


@pytest.mark.parametrize("argv", [[], ["files"], ["shell"], ["email"]])
def test_bad_arguments_exit(argv):
    with pytest.raises(SystemExit):
        build(argv)


async def test_runs_over_stdio_as_a_real_subprocess(tmp_path):
    (tmp_path / "hello.txt").write_text("from a subprocess")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agent_firewall.tools", "files", "--root", str(tmp_path)],
    )
    async with Client(params) as c:
        result = await c.call_tool("read_file", {"path": "hello.txt"})
    assert result.content[0].text == "from a subprocess"
