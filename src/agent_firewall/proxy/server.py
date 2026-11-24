"""The firewall as an MCP server: the agent's one connection, in front of every tool server.

Day 3 passes calls through unchanged. The checks (days 4 to 7) plug in around `call_tool`.

What it refuses, by construction:
- `resources/*` and `prompts/*`: no handlers are registered, so the agent gets "method not
  found" (decision 13).
- Requests from a tool server to the agent (`sampling`, `elicitation`, `roots`): the firewall's
  upstream clients offer none of those, so a server that tries gets an error and never reaches
  the agent's model or user.
"""

import json
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any

import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.server import MCPServer
from mcp.server.lowlevel import Server

from agent_firewall.checks.injection_model import InjectionModel
from agent_firewall.checks.leaks import copied_output, personal_data, secret_in_arguments
from agent_firewall.checks.memory import OutputMemory
from agent_firewall.checks.result_scanner import decide, fence, scan_result
from agent_firewall.checks.verdict import Decision, Verdict, combine
from agent_firewall.policy import Policy, PolicyEngine, ToolPolicy, not_allowed
from agent_firewall.proxy.gate import Listing, ToolGate, shown
from agent_firewall.proxy.naming import SEP, check_server_name, public_name, split_name

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


def _result_text(result: types.CallToolResult) -> str:
    parts = [getattr(block, "text", "") or "" for block in result.content]
    text = "\n".join(parts)
    structured = result.structured_content
    # The SDK's {"result": text} wrapper repeats the content; anything else is extra data.
    if structured is not None and structured != {"result": text}:
        text += "\n" + json.dumps(structured, ensure_ascii=False, default=str)
    return text


_CANNOT_LABEL = object()


def _labelled_structure(output_schema: dict[str, Any] | None, fenced: str) -> Any:
    """Structured content for a labelled result. MCP clients require structured content from a
    tool that declares an output schema, so it can't simply be dropped:
    - no output schema: none;
    - the `{"result": string}` wrapper SDKs generate for text-returning tools: the fenced text;
    - anything else: the firewall can't fence data it doesn't understand, so the result is
      withheld instead (_CANNOT_LABEL)."""
    if output_schema is None:
        return None
    props = output_schema.get("properties") or {}
    if set(props) == {"result"} and (props["result"] or {}).get("type") == "string":
        return {"result": fenced}
    return _CANNOT_LABEL


def leak_checks(
    rule: ToolPolicy | None, arguments: dict[str, Any], memory: OutputMemory
) -> list[Decision | None]:
    """LK01 on every call; LK02 and LK03 only on tools the policy marks as sending data out."""
    found = [secret_in_arguments(arguments)]
    if rule is not None and rule.egress:
        on_copy = {"ask": Verdict.ASK, "block": Verdict.BLOCK, "allow": Verdict.ALLOW}
        found += [
            personal_data(arguments),
            copied_output(arguments, memory, on_copy[rule.copied_output]),
        ]
    return found


def allow_every_server(upstreams: Sequence[Upstream]) -> PolicyEngine:
    """A policy naming every server's tools, for tests and library use. The config file never
    falls back to this: it must name a policy file."""
    return PolicyEngine(Policy(tools={f"{u.name}{SEP}*": ToolPolicy() for u in upstreams}))


def build_firewall(
    upstreams: Sequence[Upstream],
    gate: ToolGate | None = None,
    policy: PolicyEngine | None = None,
    model: InjectionModel | None = None,
    enforce: bool = True,
    observe: Callable[[str, str, Decision], None] | None = None,
) -> Server[dict[str, Any]]:
    """`enforce=False` lists and routes everything with no checks at all: the same plumbing as
    the real firewall, used by the evaluation to measure what gets through without it.

    `observe(stage, tool, decision)` hears every decision that isn't a plain allow, at
    "list", "call" or "result": the hook the audit log and the evaluation build on."""
    gate = gate or ToolGate()

    def seen(stage: str, name: str, decision: Decision | None) -> None:
        if observe is not None and decision is not None and decision.verdict is not Verdict.ALLOW:
            observe(stage, name, decision)

    policy = policy or allow_every_server(upstreams)
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
            yield {"clients": clients, "memory": OutputMemory()}

    async def live_listing(clients: dict[str, Client]) -> Listing:
        listing: Listing = []
        for server, client in clients.items():
            listing += [(server, tool) for tool in await _all_tools(client)]
        return listing

    async def list_tools(ctx, params) -> types.ListToolsResult:
        clients: dict[str, Client] = ctx.lifespan_context["clients"]
        listing = await live_listing(clients)
        if not enforce:
            return types.ListToolsResult(
                tools=[t.model_copy(update={"name": public_name(s, t.name)}) for s, t in listing]
            )
        decisions = gate.review(listing)
        shown_tools = []
        for server, tool in listing:
            name = public_name(server, tool.name)
            hidden = (
                decisions[name] if not shown(decisions[name]) else not_allowed(policy.policy, name)
            )
            seen("list", name, hidden)
            if hidden is None:
                shown_tools.append(tool.model_copy(update={"name": name}))
        return types.ListToolsResult(tools=shown_tools)

    async def call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        clients: dict[str, Client] = ctx.lifespan_context["clients"]
        parts = split_name(params.name)
        if parts is None or parts[0] not in clients:
            return _error(f"Unknown tool {params.name!r}")
        server, tool = parts
        if not enforce:
            try:
                return await clients[server].call_tool(tool, params.arguments or {})
            except Exception:
                return _error(f"Tool server {server!r} failed to answer")
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
            seen("call", params.name, decision)
            return _error(f"Blocked by the firewall ({decision.rule}): {decision.reason}")
        live = next(t for srv, t in listing if srv == server and t.name == tool)
        arguments = params.arguments or {}
        memory: OutputMemory = ctx.lifespan_context["memory"]
        verdict = combine(
            d
            for d in (
                policy.review_call(params.name, arguments, live.input_schema),
                *leak_checks(policy.policy.rule_for(params.name), arguments, memory),
            )
            if d is not None
        )
        seen("call", params.name, verdict)
        if verdict.verdict is Verdict.ASK:
            # Approvals arrive on day 14; until a person can answer, "ask" means no.
            return _error(f"Needs a person's approval ({verdict.rule}): {verdict.reason}")
        if verdict.verdict is Verdict.BLOCK:
            return _error(f"Blocked by the firewall ({verdict.rule}): {verdict.reason}")
        try:
            result = await clients[server].call_tool(tool, arguments)
        except Exception:
            # The upstream's own error text could be anything; the agent gets a fixed message.
            return _error(f"Tool server {server!r} failed to answer")
        text = _result_text(result)
        if not result.is_error:
            memory.remember(text)
        # Error results are scanned too: the server writes that text as well.
        findings = scan_result(text, model)
        rule = policy.policy.rule_for(params.name)
        outcome = decide(findings, rule.result_injection if rule else "label")
        seen("result", params.name, outcome)
        if outcome is None:
            return result
        fenced = fence(text, params.name, findings)
        structured = _labelled_structure(live.output_schema, fenced)
        if outcome.verdict is Verdict.BLOCK or structured is _CANNOT_LABEL:
            return _error(
                f"The firewall withheld this tool's result ({outcome.rule}): {outcome.reason}"
            )
        # Labelled: the fenced text replaces the content. Structured content, which would carry
        # the same text to the model unfenced, is replaced too (see _labelled_structure).
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=fenced)],
            structured_content=structured,
            is_error=result.is_error,
        )

    return Server(
        "agent-firewall",
        lifespan=connect,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
