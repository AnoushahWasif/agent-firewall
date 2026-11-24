# agent-firewall

**Work in progress.**

An AI agent with real tools, and the firewall that stops it being turned against its user.

**The agent:** a security assistant that reads logs, looks up CVEs and drafts reports, using MCP tool servers.

**The firewall:** it sits between the agent and every tool. It:
- checks tool descriptions for hidden instructions;
- applies a deny-by-default policy to every call;
- stops secrets leaving through tool arguments;
- labels instructions hidden in what tools return;
- logs every decision.

**Its own models:** one of the firewall's checks is a small open LLM fine-tuned to judge tool calls. A tiny GPT trained from scratch shows how the model works inside.

Design and threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Where attack cases come from: [docs/ATTACK-SOURCES.md](docs/ATTACK-SOURCES.md).

## What works so far

| Piece | Status |
|---|---|
| Tool servers (MCP, official Python SDK) | `files` (read-only, one folder), `web` (public pages only: SSRF checks, pinned address, size and time caps), `cves` (OSV.dev), `email` (drafts to an outbox, never sends) |
| Demo agent | Agent loop with a step limit, plus a scripted model for free, repeatable tests |
| Firewall | MCP proxy that lists every server's tools as `server__tool` and refuses resources, prompts and server-to-agent requests. **Tool scanner:** hidden characters, orders aimed at the model, mentions of secrets, shadowing of other servers' tools. **Pinning:** a tool that changes after it was trusted (rug pull) is blocked, checked again at every call. **Policy:** deny by default; arguments checked against each tool's schema; patterns, allowed URL and email domains, lengths and choices per argument; rate limits; tools that need a person |

## Quick start

```bash
uv sync
uv run pytest

# Run a tool server over stdio, the way an MCP client starts it
uv run python -m agent_firewall.tools files --root ./shared
```

### Put the firewall in front of an agent

Any MCP agent (Claude Desktop, an IDE agent, or the demo agent here) gets one server, the firewall, instead of its tool servers:

```json
{
  "mcpServers": {
    "firewall": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/agent-firewall",
               "python", "-m", "agent_firewall", "--config", "examples/firewall.toml"]
    }
  }
}
```

The firewall starts the servers named in [examples/firewall.toml](examples/firewall.toml) itself, so the agent never learns their commands.

## License

MIT
