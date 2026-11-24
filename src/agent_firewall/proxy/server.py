"""The firewall as an MCP server: the agent's one connection, in front of every tool server.

Day 3 passes calls through unchanged. The checks (days 4 to 7) plug in around `call_tool`.

What it refuses, by construction:
- `resources/*` and `prompts/*`: no handlers are registered, so the agent gets "method not
  found" (decision 13).
- Requests from a tool server to the agent (`sampling`, `elicitation`, `roots`): the firewall's
  upstream clients offer none of those, so a server that tries gets an error and never reaches
  the agent's model or user.
"""

from collections.abc import AsyncIterator, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any

import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.server import MCPServer
from mcp.server.lowlevel import Server

from agent_firewall.proxy.gate import Listing, ToolGate, shown
from agent_firewall.proxy.naming import check_server_name, public_name, split_name

MAX_TOOLS_PER_SERVER = 200
MAX_PAGES = 10


@dataclass(frozen=True)
class Upstream:
    """A tool server behind the firewall: an in-process server (tests), a command, or a URL."""

    name: str
    target: MCPServer | Server | StdioServerParameters | str

    def __post_init__(self):
        check_server_name(self.name)


class UpstreamUnavailable(RuntimeError):
    pass


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


async def _all_tools(client: Client) -> list[types.Tool]:
    """The server's current tools. Never from the client's cache: pins must see the live ones."""
    tools: list[types.Tool] = []
    cursor = None
    for _ in range(MAX_PAGES):
        page = await client.list_tools(cursor=cursor, cache_mode="bypass")
        tools += page.tools
        cursor = page.next_cursor
        if not cursor or len(tools) >= MAX_TOOLS_PER_SERVER:
            break
    return tools[:MAX_TOOLS_PER_SERVER]


def build_firewall(
    upstreams: Sequence[Upstream], gate: ToolGate | None = None
) -> Server[dict[str, Any]]:
    gate = gate or ToolGate()
    names = [u.name for u in upstreams]
    if len(set(names)) != len(names):
        raise ValueError("two upstream servers share a name")

    @asynccontextmanager
    async def connect(_: Server) -> AsyncIterator[dict[str, Any]]:
        async with AsyncExitStack() as stack:
            clients: dict[str, Client] = {}
            for upstream in upstreams:
                try:
                    clients[upstream.name] = await stack.enter_async_context(
                        Client(upstream.target)
                    )
                except Exception as exc:
                    raise UpstreamUnavailable(
                        f"tool server {upstream.name!r} didn't start"
                    ) from exc
            yield {"clients": clients}

    async def live_listing(clients: dict[str, Client]) -> Listing:
        listing: Listing = []
        for server, client in clients.items():
            listing += [(server, tool) for tool in await _all_tools(client)]
        return listing

    async def list_tools(ctx, params) -> types.ListToolsResult:
        clients: dict[str, Client] = ctx.lifespan_context["clients"]
        listing = await live_listing(clients)
        decisions = gate.review(listing)
        return types.ListToolsResult(
            tools=[
                tool.model_copy(update={"name": name})
                for server, tool in listing
                if shown(decisions[name := public_name(server, tool.name)])
            ]
        )

    async def call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        clients: dict[str, Client] = ctx.lifespan_context["clients"]
        parts = split_name(params.name)
        if parts is None or parts[0] not in clients:
            return _error(f"Unknown tool {params.name!r}")
        server, tool = parts
        # Checked again at call time, against the live definitions: a tool that changed after
        # it was listed (a rug pull) is caught here, not at the next listing.
        try:
            listing = await live_listing(clients)
        except Exception:
            return _error(f"Tool server {server!r} failed to answer")
        decision = gate.review(listing).get(params.name)
        if decision is None:
            return _error(f"Unknown tool {params.name!r}")
        if not shown(decision):
            return _error(f"Blocked by the firewall ({decision.rule}): {decision.reason}")
        try:
            return await clients[server].call_tool(tool, params.arguments or {})
        except Exception:
            # The upstream's own error text could be anything; the agent gets a fixed message.
            return _error(f"Tool server {server!r} failed to answer")

    return Server(
        "agent-firewall",
        lifespan=connect,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
