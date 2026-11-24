"""The firewall's policy: which tools the agent may use, and how. Deny by default (decision 2).

    [tools."cves__*"]                       # every tool of the cves server

    [tools."files__read_file"]
    rate = { calls = 30, per_seconds = 60 }

    [tools."files__read_file".args.path]
    pattern = "logs/.*"                     # the whole value must match

    [tools."email__send_report"]
    ask = true                              # a person approves every call

    [tools."email__send_report".args.to]
    domains = ["example.com"]               # every address must be at one of these

A tool the policy doesn't name is hidden from the agent and can't be called. An exact name
takes precedence over a `server__*` entry.

Rules (ids appear in the audit log):
  POL01 not allowed: the policy doesn't name the tool
  POL02 bad arguments: they don't fit the tool's own input schema, or they're too large
"""

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agent_firewall.checks.verdict import Decision, Verdict
from agent_firewall.proxy.naming import SEP, split_name

MAX_TOOLS = 500
MAX_ARGUMENT_BYTES = 64_000
GLOB = re.compile(r"^[a-z][a-z0-9-]{0,30}__\*$")


class PolicyError(ValueError):
    pass


class ToolPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: dict[str, ToolPolicy] = Field(default_factory=dict, max_length=MAX_TOOLS)

    @field_validator("tools")
    @classmethod
    def names_are_tools_or_server_globs(cls, tools: dict[str, ToolPolicy]):
        for name in tools:
            if not (GLOB.fullmatch(name) or split_name(name)):
                raise ValueError(f"{name!r} is neither server__tool nor server__*")
        return tools

    def rule_for(self, name: str) -> ToolPolicy | None:
        """The entry that governs a public tool name: the exact one, else its server's glob."""
        if name in self.tools:
            return self.tools[name]
        parts = split_name(name)
        if parts is None:
            return None
        return self.tools.get(f"{parts[0]}{SEP}*")

    def allows(self, name: str) -> bool:
        return self.rule_for(name) is not None


def not_allowed(policy: Policy, name: str) -> Decision | None:
    if not policy.allows(name):
        return Decision(Verdict.BLOCK, "POL01", "the policy doesn't allow this tool")
    return None


def bad_arguments(arguments: dict[str, Any], input_schema: dict[str, Any]) -> Decision | None:
    """Arguments checked against the schema the tool itself published (and the firewall pinned).
    Servers are supposed to validate their own input; this doesn't rely on it."""
    if len(json.dumps(arguments, ensure_ascii=False)) > MAX_ARGUMENT_BYTES:
        return Decision(Verdict.BLOCK, "POL02", "the arguments are too large")
    try:
        Draft202012Validator.check_schema(input_schema)
        error = next(Draft202012Validator(input_schema).iter_errors(arguments), None)
    except Exception:  # a schema we can't use must block, never pass (decision 14)
        return Decision(
            Verdict.BLOCK, "POL02", "the tool's schema can't be used to check arguments"
        )
    if error is not None:
        # The reason names the failing field, never the value that failed.
        field = ".".join(str(p) for p in error.absolute_path) or "(top level)"
        return Decision(
            Verdict.BLOCK, "POL02", f"argument {field[:80]} doesn't fit the tool's schema"
        )
    return None


def load(path: Path) -> Policy:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"can't read {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path} isn't valid TOML: {exc}") from exc
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"])
        raise PolicyError(f"{path}: {where}: {first['msg']}") from exc
