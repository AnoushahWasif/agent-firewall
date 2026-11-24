"""Run one tool server over stdio, the way an MCP client (or the firewall) starts it.

python -m agent_firewall.tools files --root ./shared
python -m agent_firewall.tools web
python -m agent_firewall.tools cves
python -m agent_firewall.tools email --outbox ./outbox
"""

import argparse
from pathlib import Path

from mcp.server import MCPServer

from agent_firewall.tools import cves, email_outbox, files, web


def build(argv: list[str] | None = None) -> MCPServer:
    parser = argparse.ArgumentParser(prog="python -m agent_firewall.tools", description=__doc__)
    sub = parser.add_subparsers(dest="server", required=True)
    f = sub.add_parser("files", help="read-only access to one folder")
    f.add_argument("--root", type=Path, required=True)
    sub.add_parser("web", help="fetch public web pages")
    sub.add_parser("cves", help="look up vulnerabilities on OSV.dev")
    e = sub.add_parser("email", help="draft reports to an outbox folder (never sends)")
    e.add_argument("--outbox", type=Path, required=True)
    args = parser.parse_args(argv)
    match args.server:
        case "files":
            return files.build_server(args.root)
        case "web":
            return web.build_server()
        case "cves":
            return cves.build_server()
        case _:
            return email_outbox.build_server(args.outbox)


def main(argv: list[str] | None = None) -> None:
    build(argv).run("stdio")


if __name__ == "__main__":
    main()
