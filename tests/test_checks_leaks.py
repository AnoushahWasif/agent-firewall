import pytest

from agent_firewall.checks.leaks import secret_in_arguments, strings

# Built at runtime so this file never holds a real-looking secret for scanners to trip on.
AWS = "AKIA" + "Q" * 16
GITHUB = "ghp_" + "a1" * 18
PRIVATE = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END"
JWT = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12


def test_strings_walks_nested_arguments_with_their_paths():
    found = dict(strings({"to": ["a@x.com"], "meta": {"note": "hi"}}))
    assert found["to[0]"] == "a@x.com" and found["meta.note"] == "hi"


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        (AWS, "AWS access key"),
        (f"key={AWS};", "AWS access key"),
        (GITHUB, "GitHub token"),
        ("glpat-" + "x" * 20, "GitLab token"),
        ("xoxb-" + "1234567890-abc", "Slack token"),
        ("sk-ant-" + "api03-" + "z" * 30, "Anthropic key"),
        ("AIza" + "B" * 35, "Google API key"),
        ("sk_live_" + "0" * 24, "Stripe key"),
        (PRIVATE, "private key"),
        (JWT, "JSON web token"),
        ("https://admin:hunter2@db.internal/", "password in a URL"),
    ],
)
def test_known_secret_formats_are_blocked_anywhere(value, kind):
    decision = secret_in_arguments({"body": "report", "extra": {"notes": [f"see {value}"]}})
    assert decision.rule == "LK01" and kind in decision.reason
    assert "extra.notes[0]" in decision.reason
    assert value not in decision.reason


def test_secrets_in_keys_count_too():
    assert secret_in_arguments({AWS: "x"}).rule == "LK01"


@pytest.mark.parametrize(
    "value",
    [
        "AKIA is a prefix AWS uses",
        "the token is in the vault",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-10906",
        "sk-short",
        "ssh-rsa AAAAB3NzaC1yc2E public keys are fine",
        "-----BEGIN PUBLIC KEY-----",
    ],
)
def test_ordinary_text_passes(value):
    assert secret_in_arguments({"body": value}) is None


def test_scanning_stops_at_a_size_limit():
    huge = {"body": "x" * 300_000 + AWS}
    assert secret_in_arguments(huge) is None  # beyond the cap: the schema size limit applies


@pytest.mark.parametrize(
    "attack",
    [
        "a" * 256_000,
        "a:" * 128_000,
        "eyJ" * 85_000,
        "ghp_" * 64_000,
        "AKIA" * 64_000,
        "x://" + "a" * 255_000,
        "-----BEGIN " * 23_000,
    ],
)
def test_no_pattern_is_slow_on_hostile_input(attack):
    import time

    start = time.perf_counter()
    secret_in_arguments({"body": attack})
    assert time.perf_counter() - start < 1.0
