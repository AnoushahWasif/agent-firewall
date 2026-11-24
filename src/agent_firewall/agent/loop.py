"""The agent loop over one MCP connection.

The agent only ever knows one MCP server. Today that's a tool server; from day 3 it's the
firewall, which fronts all of them. The loop itself trusts nothing it gets back: results are cut
to size, and a call to a tool that wasn't listed is answered locally as an error.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from mcp import Client

from agent_firewall.agent.model import Answer, Message, Model, ToolCall, ToolSpec

MAX_STEPS = 8
MAX_RESULT_CHARS = 12_000

Stop = Literal["answered", "step_limit", "model_error"]


@dataclass(frozen=True)
class RunResult:
    transcript: list[Message]
    answer: str | None
    stopped: Stop
    tool_calls: int


def result_text(result) -> str:
    parts = [getattr(block, "text", None) or f"[{block.type} content]" for block in result.content]
    text = "\n".join(parts)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + "\n[cut: result is longer]"
    return text


async def list_tool_specs(client: Client) -> list[ToolSpec]:
    listed = await client.list_tools()
    return [ToolSpec(t.name, t.description or "", t.input_schema) for t in listed.tools]


async def run_task(
    task: str, client: Client, model: Model, max_steps: int = MAX_STEPS, relist: bool = False
) -> RunResult:
    """`relist=True` refreshes the tool list before every step, as clients do when a server
    says its tools changed. That's how a changed description (a rug pull) reaches the model."""
    tools = await list_tool_specs(client)
    offered = {t.name for t in tools}
    transcript = [Message("user", task)]
    calls = 0
    for _ in range(max_steps):
        if relist and calls:
            tools = await list_tool_specs(client)
            offered = {t.name for t in tools}
        try:
            step = await model.next_step(transcript, tools)
        except Exception as exc:  # a broken model ends the run, it doesn't crash the caller
            transcript.append(Message("assistant", f"model failed: {type(exc).__name__}"))
            return RunResult(transcript, None, "model_error", calls)
        if isinstance(step, Answer):
            transcript.append(Message("assistant", step.text))
            return RunResult(transcript, step.text, "answered", calls)
        transcript.append(Message("assistant", "", tool_call=step))
        calls += 1
        transcript.append(await _call(client, step, offered))
    return RunResult(transcript, None, "step_limit", calls)


async def _call(client: Client, call: ToolCall, offered: Sequence[str] | set[str]) -> Message:
    if call.name not in offered:
        return Message("tool", f"No tool named {call.name!r}", call, is_error=True)
    result = await client.call_tool(call.name, call.arguments)
    return Message("tool", result_text(result), call, is_error=bool(result.is_error))
