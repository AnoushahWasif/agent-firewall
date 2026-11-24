"""Decides which upstream tools the agent may see and call.

Every tool is scanned in the context of the whole listing (shadowing needs the others) and then
checked against its pin. Only a tool that passes the scan is pinned, so a poisoned tool is never
trusted on first sight. `ask` withholds the tool for now; approvals arrive on day 14.
"""

from dataclasses import dataclass, field

import mcp_types as types

from agent_firewall.checks.pins import PinStore, check_pin
from agent_firewall.checks.tool_scanner import ToolDef, scan
from agent_firewall.checks.verdict import Decision, Verdict, combine
from agent_firewall.proxy.naming import public_name

Listing = list[tuple[str, types.Tool]]  # (server, tool as the server described it)


def tool_def(server: str, tool: types.Tool) -> ToolDef:
    return ToolDef(server, tool.name, tool.description or "", tool.input_schema)


@dataclass
class ToolGate:
    pins: PinStore = field(default_factory=PinStore)

    def review(self, listing: Listing) -> dict[str, Decision]:
        """Decision per public tool name."""
        defs = [tool_def(server, tool) for server, tool in listing]
        decisions: dict[str, Decision] = {}
        for (server, tool), definition in zip(listing, defs, strict=True):
            name = public_name(server, tool.name)
            verdict = combine(scan(definition, defs))
            if verdict.verdict < Verdict.ASK:
                verdict = combine([verdict, check_pin(self.pins, name, tool) or verdict])
            decisions[name] = verdict
        return decisions


def shown(decision: Decision) -> bool:
    return decision.verdict < Verdict.ASK
