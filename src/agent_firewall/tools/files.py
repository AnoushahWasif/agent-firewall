"""Read-only access to one folder, for the agent to read logs and notes.

Every path is resolved (symlinks included) and must stay inside the root, so `..`, absolute
paths and links pointing outside are all refused the same way.
"""

from pathlib import Path

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

MAX_READ_BYTES = 256_000
DEFAULT_READ_BYTES = 64_000
MAX_LIST_ENTRIES = 500
MAX_MATCHES = 200
MAX_SEARCH_TEXT = 200


def resolve_inside(root: Path, relative: str) -> Path:
    """`relative` under `root`, or ToolError if it points anywhere else."""
    if "\x00" in relative:
        raise ToolError("Path contains a NUL character")
    # Drive letters and backslashes mean "elsewhere" on Windows but are plain characters on
    # Linux. Refusing them everywhere keeps one rule for every machine the server runs on.
    if "\\" in relative or (len(relative) > 1 and relative[1] == ":"):
        raise ToolError("Path is outside the shared folder")
    root = root.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        raise ToolError("Path is outside the shared folder")
    return candidate


def _read_text(path: Path, limit: int) -> tuple[str, bool]:
    with path.open("rb") as f:
        data = f.read(limit + 1)
    if b"\x00" in data[:8000]:
        raise ToolError("That looks like a binary file")
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


def build_server(root: Path) -> MCPServer:
    if not root.is_dir():
        raise ValueError(f"{root} is not a folder")
    server = MCPServer("files")

    @server.tool()
    def list_files(directory: str = ".") -> list[str]:
        """List the files and folders in a folder of the shared folder. Folders end with /."""
        folder = resolve_inside(root, directory)
        if not folder.is_dir():
            raise ToolError("Not a folder")
        entries = sorted(folder.iterdir(), key=lambda p: p.name)[:MAX_LIST_ENTRIES]
        return [p.name + ("/" if p.is_dir() else "") for p in entries]

    @server.tool()
    def read_file(path: str, max_bytes: int = DEFAULT_READ_BYTES) -> str:
        """Read a text file from the shared folder. Long files are cut at max_bytes."""
        if not 1 <= max_bytes <= MAX_READ_BYTES:
            raise ToolError(f"max_bytes must be between 1 and {MAX_READ_BYTES}")
        file = resolve_inside(root, path)
        if not file.is_file():
            raise ToolError("No such file")
        text, truncated = _read_text(file, max_bytes)
        return text + ("\n[cut: file is longer]" if truncated else "")

    @server.tool()
    def search_file(path: str, text: str) -> list[str]:
        """Lines of a text file containing `text` (plain text, not a pattern), numbered."""
        if not 1 <= len(text) <= MAX_SEARCH_TEXT:
            raise ToolError(f"text must be 1 to {MAX_SEARCH_TEXT} characters")
        file = resolve_inside(root, path)
        if not file.is_file():
            raise ToolError("No such file")
        content, _ = _read_text(file, MAX_READ_BYTES)
        hits = [f"{n}: {line}" for n, line in enumerate(content.splitlines(), 1) if text in line]
        return hits[:MAX_MATCHES]

    return server
