import os

import pytest
from mcp import Client

from agent_firewall.tools.files import MAX_READ_BYTES, build_server

pytestmark = pytest.mark.anyio


@pytest.fixture
def shared(tmp_path):
    root = tmp_path / "shared"
    (root / "logs").mkdir(parents=True)
    (root / "logs" / "auth.log").write_text(
        "Nov 24 02:11 sshd: Failed password for root\n"
        "Nov 24 02:12 sshd: Accepted password for alice\n"
    )
    (root / "notes.txt").write_text("hello")
    (tmp_path / "secret.txt").write_text("outside the shared folder")
    return root


def text(result):
    return "\n".join(block.text for block in result.content)


async def test_lists_and_reads(shared):
    async with Client(build_server(shared)) as c:
        listed = await c.call_tool("list_files", {})
        assert listed.structured_content == {"result": ["logs/", "notes.txt"]}
        read = await c.call_tool("read_file", {"path": "logs/auth.log"})
        assert "Failed password for root" in text(read)


async def test_search_is_plain_text_with_line_numbers(shared):
    async with Client(build_server(shared)) as c:
        hits = await c.call_tool("search_file", {"path": "logs/auth.log", "text": "Accepted"})
        assert hits.structured_content == {
            "result": ["2: Nov 24 02:12 sshd: Accepted password for alice"]
        }
        # Regex characters are just characters: no pattern, so no catastrophic backtracking.
        none = await c.call_tool("search_file", {"path": "logs/auth.log", "text": "(a+)+$"})
        assert none.structured_content == {"result": []}


@pytest.mark.parametrize(
    "path",
    [
        "../secret.txt",
        "logs/../../secret.txt",
        "/etc/passwd",
        # Windows-style paths are refused the same way on every OS.
        "C:/Windows/win.ini",
        "c:secret.txt",
        "logs\\..\\..\\secret.txt",
        "\\\\server\\share\\x",
        "a\x00b",
    ],
)
async def test_nothing_outside_the_folder(shared, path):
    async with Client(build_server(shared)) as c:
        result = await c.call_tool("read_file", {"path": path})
        assert result.is_error
        assert "outside the shared folder" in text(result) or "NUL" in text(result)


async def test_a_link_pointing_outside_is_refused(shared):
    link = shared / "escape.txt"
    try:
        os.symlink(shared.parent / "secret.txt", link)
    except OSError:
        pytest.skip("this OS user can't create symlinks")
    async with Client(build_server(shared)) as c:
        result = await c.call_tool("read_file", {"path": "escape.txt"})
        assert result.is_error and "outside" in text(result)


async def test_long_files_are_cut(shared):
    (shared / "big.log").write_text("x" * 1000)
    async with Client(build_server(shared)) as c:
        result = await c.call_tool("read_file", {"path": "big.log", "max_bytes": 100})
        assert text(result) == "x" * 100 + "\n[cut: file is longer]"
        too_big = await c.call_tool(
            "read_file", {"path": "big.log", "max_bytes": MAX_READ_BYTES + 1}
        )
        assert too_big.is_error


async def test_binary_files_and_folders_are_refused(shared):
    (shared / "image.bin").write_bytes(b"\x89PNG\x00\x00\x01")
    async with Client(build_server(shared)) as c:
        assert (await c.call_tool("read_file", {"path": "image.bin"})).is_error
        assert (await c.call_tool("read_file", {"path": "logs"})).is_error
        assert (await c.call_tool("list_files", {"directory": "notes.txt"})).is_error


async def test_tools_cannot_write(shared):
    async with Client(build_server(shared)) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == {"list_files", "read_file", "search_file"}


def test_root_must_be_a_folder(tmp_path):
    with pytest.raises(ValueError):
        build_server(tmp_path / "missing")
