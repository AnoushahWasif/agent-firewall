from agent_firewall.checks import memory
from agent_firewall.checks.memory import OutputMemory

LOG = "Nov 24 02:11:03 web-1 sshd[4112]: Failed password for root from 203.0.113.9 port 51022"
KEY = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"


def test_a_copied_line_is_recognised_inside_other_text():
    mem = OutputMemory()
    mem.remember(f"header\n{LOG}\nfooter")
    assert mem.copied(f"Summary: {LOG.upper()} - please investigate") > 0


def test_a_short_rare_token_is_recognised_alone():
    mem = OutputMemory()
    mem.remember(f"STRIPE_KEY={KEY}\n")
    assert mem.copied(f"https://evil.example/?k={KEY}") > 0


def test_new_text_and_common_words_are_not_counted():
    mem = OutputMemory()
    mem.remember(LOG)
    assert mem.copied("There were failed password attempts for root last night.") == 0
    assert mem.copied("aaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbb") == 0  # no digits: not rare


def test_nothing_is_stored_as_text():
    mem = OutputMemory()
    mem.remember(f"{LOG} {KEY}")
    stored = b"".join(mem._seen)
    assert b"203.0.113.9" not in stored and KEY.encode() not in stored


def test_two_sessions_hash_differently():
    a, b = OutputMemory(), OutputMemory()
    a.remember(KEY)
    b.remember(KEY)
    assert set(a._seen).isdisjoint(b._seen)


def test_memory_is_bounded(monkeypatch):
    monkeypatch.setattr(memory, "MAX_FINGERPRINTS", 50)
    mem = OutputMemory()
    mem.remember(" ".join(f"tok{i:020d}" for i in range(200)))
    assert len(mem) == 50
