# Where the attack cases come from

Licences checked on 25 Nov 2026 (GitHub's licence field and each repository's LICENSE file).

| Source | Licence | What it covers | How it's used here |
|---|---|---|---|
| [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) | MIT | Prompt injections planted in tool results, against agents doing real tasks | Injection styles adapted into our own cases, with attribution. The copyright notice is kept in `attacks/NOTICE` for anything adapted |
| [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | MIT | Indirect injections in tool responses, aimed at harmful actions and data theft | Same as above |
| [invariantlabs-ai/mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments) | None stated (all rights reserved) | The original MCP tool-poisoning and "rug pull" demos | **Not copied.** The attack ideas are public and cited; every case here is written from scratch |
| [microsoft/BIPIA](https://github.com/microsoft/BIPIA) | Not machine-readable (`NOASSERTION`) | Indirect prompt injection benchmark | Not used until its terms are clear |
| [AI-secure/AgentPoison](https://github.com/AI-secure/AgentPoison) | MIT | Poisoning an agent's memory or knowledge base | Out of scope: this project has no memory store |

**Rules for `attacks/`:**
- **Every case names its family and its source:** "own", or a repository with the commit it was adapted from.
- **Nothing is copied from a source without a licence.**
- **MIT sources keep their copyright notice** in `attacks/NOTICE`.
- **The held-out half is chosen at random, with a fixed seed, before any rule is written.** Its file hash is recorded, so later edits would show.

**The six families map to published risk lists:**
- **Poisoned tool description, rug pull, tool shadowing:** MCP tool poisoning. This also falls under OWASP LLM01 (prompt injection) and LLM03 (supply chain).
- **Instructions hidden in a web page, instructions hidden in a log file:** indirect prompt injection (OWASP LLM01).
- **Secrets sent out through arguments:** sensitive information disclosure (OWASP LLM02) and excessive agency (LLM06).
