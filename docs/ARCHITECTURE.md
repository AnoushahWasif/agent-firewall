# Architecture (v1)

Written before any code. It will change as the build teaches me things, and each change gets a line under "Decisions".

## Context

An AI agent with real tools, plus the security layer that stops it being turned against its user.

**The agent:** a security assistant that answers questions like "what happened on this server last night?". It reads log files, searches the web, looks up CVEs and can draft an email report. It uses MCP (Model Context Protocol) tool servers, the way agents connect to tools now.

**The firewall:** it sits between the agent and every tool server. It checks tool descriptions before the agent sees them, and every tool call before it runs. It also checks what each tool returns before it goes back to the model, and it logs every decision.

**The questions it answers, with numbers:**
1. **How often do known agent attacks get through, with the firewall on and off?** The attacks are poisoned tool descriptions, instructions hidden in web pages and logs, data leaking out through tool arguments, and a tool changing after it was approved.
2. **How often does it get in the way of normal work?** That's false blocks on ordinary agent tasks.
3. **What does it cost in latency?**

**Why this project:**
- Agents with MCP tools are what AI engineer roles ask for now.
- Securing them is new: OWASP's Top 10 for LLM applications and its agentic AI threat list both name these attacks.
- It builds on my [prompt-injection-guard](https://github.com/AnoushahWasif/prompt-injection-guard) project, whose model becomes one of the firewall's checks.

**Two LLMs of our own:**
- **A guard model:** a small open LLM, fine-tuned with LoRA to judge tool calls and tool results, used as one of the firewall's checks.
- **A tiny GPT trained from scratch:** a learning notebook that shows how an LLM works inside, from the tokenizer to attention and training.

## Components

| Component | What it does |
|---|---|
| **Demo agent** | A small agent loop: the LLM picks a tool, the call goes out through the firewall, the result comes back. One adapter for a local open model through Ollama (free, on this laptop); tests use a scripted fake model |
| **Tool servers (MCP)** | Our own small servers: `files` (read-only, one folder), `web` (fetch a page), `cves` (OSV lookup), `email` (writes to an outbox folder, never really sends). Plus deliberately malicious servers for the attack tests |
| **Firewall proxy** | Speaks MCP on both sides, so any MCP agent can use it, not just ours |
| ↳ Tool scanner | On `tools/list`: flags hidden instructions in descriptions (imperatives to the model, invisible Unicode, mentions of other tools or of secrets) and pins each tool's definition by hash. A changed definition is blocked until it's approved again |
| ↳ Policy engine | A YAML policy, deny by default. It sets which servers and tools are allowed, checks arguments against schemas, and keeps allow-lists for paths and URL domains, plus rate limits per tool |
| ↳ Leak check | Outgoing arguments are checked for secrets (keys, tokens, private keys), for personal data, and for content copied from earlier tool results that's heading to a tool that sends data out (web, email) |
| ↳ Result scanner | Tool results are scored by the prompt-injection-guard model. Suspicious text is fenced and labelled as untrusted data, or the result is withheld (policy decides) |
| ↳ Guard LLM | Our fine-tuned small model (see below). It judges what the rules can't settle, such as "is this tool result trying to give the agent orders?". Only borderline cases go to it, so it doesn't slow every call |
| ↳ Approval | Calls the policy marks as risky wait for a person to say yes or no |
| ↳ Audit log | One JSON line per decision: what was asked, the rule that decided, and the outcome. It holds hashes and rule ids rather than secrets |
| **Dashboard** | Next.js static site: recent decisions, blocked attacks, waiting approvals |
| **Evaluation harness** | Replays the attack set and the normal-task set with the firewall on and off, and writes the numbers to `reports/` |
