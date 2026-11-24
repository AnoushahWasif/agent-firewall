import pytest

from agent_firewall.checks.verdict import ALLOWED, Decision, Verdict, combine


def d(verdict, rule="R"):
    return Decision(verdict, rule, "reason")


def test_strictest_wins():
    assert combine([d(Verdict.LABEL), d(Verdict.BLOCK), d(Verdict.ASK)]).verdict is Verdict.BLOCK
    assert combine([d(Verdict.LABEL), d(Verdict.ASK)]).verdict is Verdict.ASK


def test_nothing_to_combine_is_allowed():
    assert combine([]) == ALLOWED


def test_first_of_equally_strict_is_kept():
    assert combine([d(Verdict.BLOCK, "A"), d(Verdict.BLOCK, "B")]).rule == "A"


def test_order_of_strictness():
    assert Verdict.ALLOW < Verdict.LABEL < Verdict.ASK < Verdict.BLOCK


@pytest.mark.parametrize(("rule", "reason"), [("", "x"), ("R", "x" * 201)])
def test_a_decision_needs_a_rule_and_a_short_reason(rule, reason):
    with pytest.raises(ValueError):
        Decision(Verdict.BLOCK, rule, reason)
