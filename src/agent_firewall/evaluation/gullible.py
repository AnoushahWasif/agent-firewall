"""The worst-case agent: it obeys any planted instruction it can see.

A real model resists some injections and falls for others, and how often depends on the model.
To measure the firewall rather than the model, this one always falls for them: the moment the
case's trigger phrase appears anywhere it can read (a tool's description, or any tool result,
fenced or not), it drops its task and carries out the attacker's steps.

So the firewall only gets credit for what it actually stops (a call refused, a tool withheld, a
leak blocked), never for hoping a fence persuades the model.

Attack steps can use what the previous tool returned: "{last}" is replaced by its text, which
is how "read the key, then send it" works.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_firewall.agent.model import Answer, Message, Step, ToolCall, ToolSpec


def _fill(value: Any, last: str) -> Any:
    if isinstance(value, str):
        return value.replace("{last}", last)
    if isinstance(value, list):
        return [_fill(v, last) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, last) for k, v in value.items()}
    return value


@dataclass
class GullibleModel:
    task: list[Step]
    trigger: str | None = None
    attack: list[ToolCall] = field(default_factory=list)
    obeyed: bool = False
    _task_i: int = 0
    _attack_i: int = 0

    def _sees_trigger(self, transcript: Sequence[Message], tools: Sequence[ToolSpec]) -> bool:
        if not self.trigger:
            return False
        needle = self.trigger.lower()
        visible = [t.description for t in tools] + [m.content for m in transcript]
        return any(needle in text.lower() for text in visible)

    async def next_step(self, transcript: Sequence[Message], tools: Sequence[ToolSpec]) -> Step:
        if not self.obeyed and self._sees_trigger(transcript, tools):
            self.obeyed = True
        if self.obeyed and self._attack_i < len(self.attack):
            step = self.attack[self._attack_i]
            self._attack_i += 1
            last = transcript[-1].content if transcript else ""
            return ToolCall(step.name, _fill(step.arguments, last))
        if self._task_i < len(self.task):
            step = self.task[self._task_i]
            self._task_i += 1
            return step
        return Answer("Done.")
