"""What every check returns, and how several answers combine (decision 14).

The strictest answer wins: block > ask > label > allow. A check that crashes counts as `block`
for calls and as `label` for results, so a broken check never lets something through quietly.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum


class Verdict(IntEnum):
    ALLOW = 0
    LABEL = 1  # allow, but fence the suspicious part of a result as untrusted data
    ASK = 2  # a person decides
    BLOCK = 3


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    rule: str  # short stable id, e.g. "TS02", shown in the audit log
    reason: str  # one line, never containing the data that triggered it

    def __post_init__(self):
        if not self.rule or len(self.reason) > 200:
            raise ValueError("a decision needs a rule id and a reason under 200 characters")


ALLOWED = Decision(Verdict.ALLOW, "OK", "no check objected")


def combine(decisions: Iterable[Decision]) -> Decision:
    """The strictest decision; the first of equally strict ones, so the order of checks is kept."""
    strictest = ALLOWED
    for decision in decisions:
        if decision.verdict > strictest.verdict:
            strictest = decision
    return strictest
