"""Checks a tool's definition before the agent sees it.

A tool description is text the model reads and tends to obey, written by whoever runs the
server. So it's checked like untrusted input: everywhere a model would read text (the
description, and every description, title, default, example and enum value inside the input
schema), not just the top line.

Rules (ids appear in the audit log):
  TS01 hidden characters: invisible or control characters a person reviewing the tool can't see
"""

import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from agent_firewall.checks.verdict import Decision, Verdict

MAX_SCHEMA_DEPTH = 12
MAX_TEXTS = 2_000
SCHEMA_TEXT_KEYS = ("description", "title", "default", "examples", "enum", "const")
VISIBLE_CONTROLS = {"\n", "\t", "\r"}


@dataclass(frozen=True)
class ToolDef:
    server: str
    name: str
    description: str
    input_schema: dict[str, Any]


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _schema_texts(schema: Any, depth: int = 0) -> Iterator[str]:
    if depth > MAX_SCHEMA_DEPTH or not isinstance(schema, dict):
        return
    for key, value in schema.items():
        if key in SCHEMA_TEXT_KEYS:
            yield from _strings(value)
        elif isinstance(value, dict):
            # property names are text the model reads too
            if key in ("properties", "patternProperties", "$defs", "definitions"):
                yield from (k for k in value if isinstance(k, str))
            yield from _schema_texts(value, depth + 1)
        elif isinstance(value, list):
            for item in value:
                yield from _schema_texts(item, depth + 1)


def texts(tool: ToolDef) -> list[str]:
    """Every piece of text in the definition that reaches the model."""
    found = [tool.name, tool.description]
    for text in _schema_texts(tool.input_schema):
        found.append(text)
        if len(found) >= MAX_TEXTS:
            break
    return found


def _hidden(text: str) -> bool:
    return any(
        unicodedata.category(c) in ("Cf", "Cc", "Co", "Cn") and c not in VISIBLE_CONTROLS
        for c in text
    )


def hidden_characters(tool: ToolDef) -> Decision | None:
    if any(_hidden(t) for t in texts(tool)):
        return Decision(Verdict.BLOCK, "TS01", "invisible or control characters in the definition")
    return None


RULES = (hidden_characters,)


def scan(tool: ToolDef) -> list[Decision]:
    return [d for rule in RULES if (d := rule(tool)) is not None]
