"""The firewall's config file: which tool servers sit behind it.

    pins = "pins.json"            # where tool pins are kept; leave out to keep them in memory

    [servers.files]
    command = "python"            # "python" means the interpreter running the firewall
    args = ["-m", "agent_firewall.tools", "files", "--root", "shared"]

    [servers.email]
    command = "python"
    args = ["-m", "agent_firewall.tools", "email", "--outbox", "outbox"]
    env = { LANG = "C.UTF-8" }    # only what's listed here is added (see below)

Tool servers start in the config file's folder. They get a minimal environment (PATH, TEMP and
the like, from the MCP SDK) plus only the variables listed under `env`, so secrets in the
firewall's own environment never reach them.
"""

import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from mcp import StdioServerParameters
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agent_firewall.checks.pins import PinStore
from agent_firewall.proxy.gate import ToolGate
from agent_firewall.proxy.naming import check_server_name
from agent_firewall.proxy.server import Upstream

MAX_SERVERS = 20


class ConfigError(ValueError):
    pass


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1, max_length=500)
    args: list[str] = Field(default_factory=list, max_length=50)
    env: dict[str, str] = Field(default_factory=dict, max_length=50)


class FirewallConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pins: str | None = Field(default=None, min_length=1, max_length=500)
    servers: dict[str, ServerConfig] = Field(min_length=1, max_length=MAX_SERVERS)

    @field_validator("servers")
    @classmethod
    def names_follow_the_rules(cls, servers: dict[str, ServerConfig]):
        for name in servers:
            check_server_name(name)
        return servers


@dataclass(frozen=True)
class Setup:
    upstreams: list[Upstream]
    gate: ToolGate


def load(path: Path) -> Setup:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"can't read {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} isn't valid TOML: {exc}") from exc
    try:
        config = FirewallConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path}: {exc.errors()[0]['msg']}") from exc
    folder = path.resolve().parent
    upstreams = [
        Upstream(
            name,
            StdioServerParameters(
                command=sys.executable if server.command == "python" else server.command,
                args=server.args,
                env=server.env or None,
                cwd=folder,
            ),
        )
        for name, server in config.servers.items()
    ]
    pins = PinStore(folder / config.pins if config.pins else None)
    return Setup(upstreams, ToolGate(pins))
