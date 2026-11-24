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
"""

import re
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agent_firewall.checks.verdict import Decision, Verdict
from agent_firewall.proxy.naming import SEP, split_name

MAX_TOOLS = 500
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
