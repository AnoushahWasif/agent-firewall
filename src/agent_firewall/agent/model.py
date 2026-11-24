"""What the agent loop needs from a model: given the conversation so far and the tools on offer,
either call one tool or give the final answer.

`ScriptedModel` follows a fixed script and costs nothing, so tests and CI never need a real
model. A script step can also be a function of the transcript, which is how the evaluation
builds a deliberately gullible model that obeys instructions hidden in tool results.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Answer:
    text: str


Step = ToolCall | Answer


@dataclass(frozen=True)
class Message:
    role: Literal["user", "assistant", "tool"]
    content: str
    tool_call: ToolCall | None = None
    is_error: bool = False


class Model(Protocol):
    async def next_step(self, transcript: Sequence[Message], tools: Sequence[ToolSpec]) -> Step: ...


ScriptStep = Step | Callable[[Sequence[Message]], Step]


class ScriptExhausted(RuntimeError):
    """The script ran out of steps before the task finished."""


class ScriptedModel:
    def __init__(self, steps: Sequence[ScriptStep]):
        self._steps = list(steps)
        self.calls = 0

    async def next_step(self, transcript: Sequence[Message], tools: Sequence[ToolSpec]) -> Step:
        if self.calls >= len(self._steps):
            raise ScriptExhausted(f"no step {self.calls + 1} in a script of {len(self._steps)}")
        step = self._steps[self.calls]
        self.calls += 1
        return step(transcript) if callable(step) else step
