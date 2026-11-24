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

Design and threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

```bash
uv sync
uv run pytest
```

## License

MIT
