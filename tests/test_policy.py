import pytest

from agent_firewall.policy import Policy, PolicyError, bad_arguments, load, not_allowed


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
