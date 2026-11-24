import pytest

from agent_firewall.policy import (
    Policy,
    PolicyError,
    bad_arguments,
    broken_argument_rule,
    load,
    not_allowed,
)


def policy_from(tmp_path, text):
    path = tmp_path / "policy.toml"
    path.write_text(text)
    return load(path)


def test_an_empty_policy_allows_nothing():
    policy = Policy()
    assert not policy.allows("files__read_file")
    assert not_allowed(policy, "files__read_file").rule == "POL01"


def test_exact_names_and_server_globs(tmp_path):
    policy = policy_from(tmp_path, '[tools."cves__*"]\n[tools."files__read_file"]\n')
    assert policy.allows("cves__lookup_package") and policy.allows("cves__get_vulnerability")
    assert policy.allows("files__read_file")
    assert not policy.allows("files__list_files")
    assert not policy.allows("email__send_report")
    assert not_allowed(policy, "files__read_file") is None


def test_an_exact_entry_beats_the_glob(tmp_path):
    policy = policy_from(tmp_path, '[tools."files__*"]\n[tools."files__read_file"]\n')
    assert policy.rule_for("files__read_file") is policy.tools["files__read_file"]
    assert policy.rule_for("files__list_files") is policy.tools["files__*"]


@pytest.mark.parametrize("name", ["read_file", "files__", "*", "files*", "Files__x", "__*"])
def test_names_must_be_tools_or_server_globs(tmp_path, name):
    with pytest.raises(PolicyError, match="neither"):
        policy_from(tmp_path, f'[tools."{name}"]\n')


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[tools", "isn't valid TOML"),
        ('typo = 1\n[tools."a__b"]', "Extra inputs"),
        ('[tools."a__b"]\nunknown = 1', "Extra inputs"),
    ],
)
def test_bad_policies_say_where(tmp_path, text, message):
    with pytest.raises(PolicyError, match=message):
        policy_from(tmp_path, text)


def test_a_missing_policy_file(tmp_path):
    with pytest.raises(PolicyError, match="can't read"):
        load(tmp_path / "nope.toml")


READ_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1}},
    "required": ["path"],
    "additionalProperties": False,
}


def test_arguments_that_fit_the_schema_pass():
    assert bad_arguments({"path": "logs/a.log"}, READ_SCHEMA) is None


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"path": 7},
        {"path": "a", "max_bytes": 0},
        {"path": "a", "exfil": "~/.ssh/id_rsa"},
    ],
)
def test_arguments_that_do_not_fit_are_blocked(arguments):
    decision = bad_arguments(arguments, READ_SCHEMA)
    assert decision.rule == "POL02"
    assert "id_rsa" not in decision.reason  # the reason never repeats the value


def test_huge_arguments_are_blocked_before_validation():
    decision = bad_arguments({"path": "x" * 70_000}, {"type": "object"})
    assert decision.rule == "POL02" and "too large" in decision.reason


def test_a_broken_schema_blocks_rather_than_passes():
    decision = bad_arguments({"path": "a"}, {"type": "not-a-type"})
    assert decision.rule == "POL02"


def tool_policy(tmp_path, args_toml):
    return policy_from(tmp_path, '[tools."t__x"]\n' + args_toml).tools["t__x"]


def test_pattern_must_match_the_whole_value(tmp_path):
    rule = tool_policy(tmp_path, '[tools."t__x".args.path]\npattern = "logs/[a-z0-9._-]+"\n')
    assert broken_argument_rule(rule, {"path": "logs/auth.log"}) is None
    for bad in ["logs/../secret", "x/logs/a.log", "logs/a.log\n", 5]:
        assert broken_argument_rule(rule, {"path": bad}).rule == "POL03"


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("https://nvd.nist.gov/vuln/detail/CVE-2019-10906", True),
        ("https://www.nvd.nist.gov/x", True),
        ("https://NVD.NIST.GOV./x", True),
        ("https://nvd.nist.gov.evil.example/x", False),
        ("https://evilnvd.nist.gov.example/x", False),
        ("https://evil.example/?u=https://nvd.nist.gov", False),
        ("https://nvd.nist.gov@evil.example/", False),
        ("soc@example.com", True),
        ("soc@sub.example.com", True),
        ("soc@example.com.evil.example", False),
        ("soc@notexample.com", False),
        ("not a url or address", False),
    ],
)
def test_domains_for_urls_and_email_addresses(tmp_path, value, ok):
    rule = tool_policy(
        tmp_path, '[tools."t__x".args.target]\ndomains = ["nvd.nist.gov", "example.com"]\n'
    )
    assert (broken_argument_rule(rule, {"target": value}) is None) is ok


def test_lists_are_checked_item_by_item(tmp_path):
    rule = tool_policy(
        tmp_path, '[tools."t__x".args.to]\ndomains = ["example.com"]\nmax_length = 3\n'
    )
    assert broken_argument_rule(rule, {"to": ["a@example.com", "b@example.com"]}) is None
    smuggled = broken_argument_rule(rule, {"to": ["a@example.com", "attacker@evil.example"]})
    assert smuggled.rule == "POL03" and "evil" not in smuggled.reason
    assert "too many" in broken_argument_rule(rule, {"to": ["a@example.com"] * 4}).reason


def test_length_and_choices(tmp_path):
    rule = tool_policy(
        tmp_path,
        '[tools."t__x".args.body]\nmax_length = 10\n'
        '[tools."t__x".args.mode]\none_of = ["fast", "safe"]\n',
    )
    assert broken_argument_rule(rule, {"body": "short", "mode": "safe"}) is None
    assert "too long" in broken_argument_rule(rule, {"body": "x" * 11}).reason
    assert "allowed values" in broken_argument_rule(rule, {"mode": "unsafe"}).reason


def test_a_missing_argument_is_left_to_the_schema(tmp_path):
    rule = tool_policy(tmp_path, '[tools."t__x".args.path]\npattern = "logs/.*"\n')
    assert broken_argument_rule(rule, {}) is None


@pytest.mark.parametrize(
    ("args_toml", "message"),
    [
        ('[tools."t__x".args.p]\npattern = "("\n', "doesn't compile"),
        ('[tools."t__x".args.p]\ndomains = ["Example.com"]\n', "lower-case domain"),
        ('[tools."t__x".args.p]\ndomains = ["*.example.com"]\n', "lower-case domain"),
        ('[tools."t__x".args.p]\nmax_length = 0\n', "greater than or equal"),
        ('[tools."t__x".args.p]\nregex = "x"\n', "Extra inputs"),
    ],
)
def test_bad_argument_rules_are_refused_at_load(tmp_path, args_toml, message):
    with pytest.raises(PolicyError, match=message):
        tool_policy(tmp_path, args_toml)
