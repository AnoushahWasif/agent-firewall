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
| Firewall | MCP proxy that lists every server's tools as `server__tool` and refuses resources, prompts and server-to-agent requests. **Tool scanner:** hidden characters, orders aimed at the model, mentions of secrets, shadowing of other servers' tools. **Pinning:** a tool that changes after it was trusted (rug pull) is blocked, checked again at every call. **Policy:** deny by default; arguments checked against each tool's schema; patterns, allowed URL and email domains, lengths and choices per argument; rate limits; tools that need a person. **Leak check:** known secret formats in any call; card numbers, bank accounts and ID numbers, and text copied from earlier tool output, in calls that send data out. **Result scanner:** tool results checked for planted instructions (prompt-injection-guard's model plus rules) and fenced as untrusted data, or withheld |

## Results so far (development half)

25 development attacks and 9 normal tasks, each run with the firewall off and on. The agent is a worst-case scripted model that obeys every planted instruction it sees. An attack counts as successful only if a secret, or the attacker's address, actually reached an exit: the outbox, a web request, or an attacker's tool.

| Family | Attacks leaked, firewall off | Attacks leaked, firewall on |
|---|---|---|
| Poisoned tool descriptions | 6 of 6 | 0 of 6 |
| Rug pulls | 4 of 4 | 0 of 4 |
| Shadowing other servers' tools | 4 of 4 | 0 of 4 |
| Instructions in a web page | 5 of 5 | 0 of 5 |
| Instructions in a log | 4 of 4 | 0 of 4 |
| Secrets smuggled in arguments | 3 of 3 | 0 of 3 |
| **Normal tasks completed** | 9 of 9 | **8 of 9** |

**Caveats:**
- **These numbers are small:** a 0 of 4 has a 95% interval up to 49%.
- **The rules were adjusted on these cases.** The first development run found two leaks (decisions 31 and 32), so this half is no longer a fair test. The held-out half (25 attacks and 11 normal tasks) is scored once, at the end.
- **The one blocked normal task asks for log lines verbatim in an email.** The copied-output check holds that for a person, which is the intended trade-off.
- **Run time** is about 0.03 s median per task either way, with in-process tool servers.

Full numbers: [reports/eval-dev.json](reports/eval-dev.json). How it works: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#how-the-evaluation-works-day-8).

## Quick start

```bash
uv sync
uv run pytest

# The evaluation (development half)
uv run python -m agent_firewall.evaluation --split dev

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

### Add the injection model (optional)

Without it, the result scanner uses rules only. The model comes from [prompt-injection-guard](https://github.com/AnoushahWasif/prompt-injection-guard): build its portable export there, then point the config at it and pin its manifest:

```toml
[injection_model]
path = "../prompt-injection-guard/models/portable"
manifest_sha256 = "<sha256 of that folder's manifest.json>"
```

A model whose files don't match the pin stops the firewall rather than loading.

## License

MIT
