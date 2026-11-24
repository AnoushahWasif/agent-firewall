import pytest

from agent_firewall.checks.tool_scanner import ToolDef, scan, texts
from agent_firewall.checks.verdict import Verdict

SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string", "description": "File to read"}},
    "required": ["path"],
}


def tool(description="Read a text file.", schema=None, name="read_file", server="files"):
    return ToolDef(server, name, description, SCHEMA if schema is None else schema)


def rules(t):
    return {d.rule for d in scan(t)}


def test_a_plain_tool_passes():
    assert scan(tool()) == []


def test_texts_reach_into_the_schema():
    schema = {
        "type": "object",
        "properties": {
            "mode": {"type": "string", "enum": ["fast", "safe"], "default": "safe"},
            "nested": {"type": "object", "properties": {"deep": {"description": "deep text"}}},
            "list": {"type": "array", "items": [{"title": "item title"}]},
        },
        "$defs": {"X": {"description": "def text"}},
    }
    found = texts(tool(schema=schema))
    for expected in ["fast", "safe", "deep text", "item title", "def text", "mode", "nested"]:
        assert expected in found


@pytest.mark.parametrize(
    "hidden",
    [
        "\U000e0049\U000e0047\U000e004e",  # Unicode tag characters: invisible "IGN"
        "​",  # zero-width space
        "‮",  # right-to-left override
        "⁦",  # bidi isolate
        "﻿",  # byte-order mark mid-text
        "\x1b[8m",  # terminal escape that hides text
        "",  # private use
    ],
)
def test_hidden_characters_block_the_tool(hidden):
    assert rules(tool(description=f"Read a file.{hidden}")) == {"TS01"}


def test_hidden_characters_inside_a_parameter_description_count_too():
    schema = {"type": "object", "properties": {"p": {"description": "ok​hidden"}}}
    [decision] = scan(tool(schema=schema))
    assert decision.rule == "TS01" and decision.verdict is Verdict.BLOCK


def test_ordinary_line_breaks_and_accents_are_fine():
    assert scan(tool(description="Lis un fichier.\n\tRésumé: café, naïve, 日本語")) == []


def test_very_deep_schemas_stop_at_a_limit():
    schema: dict = {"description": "top"}
    for _ in range(50):
        schema = {"type": "object", "properties": {"x": schema}}
    texts(tool(schema=schema))  # finishes, no recursion error
