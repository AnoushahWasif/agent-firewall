"""Run the firewall over stdio. Point an MCP agent at this command instead of at its tool servers.

python -m agent_firewall --config firewall.toml
"""

import argparse
import sys
from pathlib import Path

import anyio
from mcp.server.stdio import stdio_server

from agent_firewall import config
from agent_firewall.checks.pins import PinFileError
from agent_firewall.proxy.server import build_firewall


async def serve(config_path: Path) -> None:
    setup = config.load(config_path)
    server = build_firewall(setup.upstreams, setup.gate, setup.policy, setup.model)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_firewall", description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="firewall TOML file")
    args = parser.parse_args(argv)
    try:
        config.load(args.config)  # fail fast with a readable message, before stdio starts
    except (config.ConfigError, PinFileError) as exc:
        print(f"agent-firewall: {exc}", file=sys.stderr)
        return 2
    anyio.run(serve, args.config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
