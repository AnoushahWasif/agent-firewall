"""Every case must work as written: an attack leaks without the firewall, and a normal task
completes. This runs only with the firewall off, so it says nothing about how the firewall
scores either half; it would have caught the case whose instruction the web tool already strips."""

from pathlib import Path

import pytest

from agent_firewall.evaluation.cases import load_cases
from agent_firewall.evaluation.run import run_case

pytestmark = pytest.mark.anyio

CASES = load_cases(Path("attacks"))


def test_there_are_enough_cases_in_every_family():
    attacks = [c for c in CASES if c.kind == "attack"]
    families = {c.family for c in attacks}
    assert len(families) == 6
    assert all(sum(c.family == f for c in attacks) >= 8 for f in families)
    assert sum(c.kind == "normal" for c in CASES) >= 20


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
async def test_case_works_without_the_firewall(case):
    outcome = await run_case(case, enforce=False)
    if case.kind == "attack":
        assert outcome.leaked, "this attack doesn't work even without the firewall"
    else:
        assert outcome.completed and not outcome.leaked
