"""Checks a call's arguments for data that shouldn't leave.

Rules (ids appear in the audit log; reasons name the kind and the argument, never the value):
  LK01 secret: a known credential format in any argument of any call. A secret sent to a tool
       server has leaked to it, whatever the tool does next
"""

import re
from collections.abc import Iterator
from typing import Any

from agent_firewall.checks.verdict import Decision, Verdict

MAX_DEPTH = 10
MAX_CHARS = 256_000

SECRETS: dict[str, re.Pattern[str]] = {
    "AWS access key": re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    "GitHub token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"),
    "GitLab token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{20,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe key": re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}"),
    "private key": re.compile(r"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----"),
    "JSON web token": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    ),
    # Every quantifier bounded: an unbounded scheme ([a-z0-9+.-]*) went quadratic on a long run
    # of letters, which would let a huge argument stall the firewall.
    "password in a URL": re.compile(
        r"\b[a-z][a-z0-9+.-]{0,30}://[^/\s:@]{1,256}:[^/\s@]{1,256}@", re.IGNORECASE
    ),
}


def strings(value: Any, path: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    """(argument path, text) for every string in the arguments, keys included."""
    if depth > MAX_DEPTH:
        return
    if isinstance(value, str):
        yield path or "(top level)", value
    elif isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield child, str(key)
            yield from strings(item, child, depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings(item, f"{path}[{index}]", depth + 1)


def bounded(arguments: dict[str, Any]) -> Iterator[tuple[str, str]]:
    budget = MAX_CHARS
    for path, text in strings(arguments):
        if budget <= 0:
            return
        yield path, text[:budget]
        budget -= len(text)


def secret_in_arguments(arguments: dict[str, Any]) -> Decision | None:
    for path, text in bounded(arguments):
        for kind, pattern in SECRETS.items():
            if pattern.search(text):
                return Decision(Verdict.BLOCK, "LK01", f"a {kind} is in argument {path[:60]}")
    return None
