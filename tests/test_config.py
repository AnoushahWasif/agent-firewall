import sys

import pytest

from agent_firewall.config import ConfigError, load


def write(tmp_path, text, policy=True):
    path = tmp_path / "firewall.toml"
    if policy:
        (tmp_path / "policy.toml").write_text('[tools."files__*"]\n')
        text = 'policy = "policy.toml"\n' + text
    path.write_text(text)
    return path


def test_loads_servers_with_the_firewalls_python(tmp_path):
    path = write(
        tmp_path,
        """
[servers.files]
command = "python"
args = ["-m", "agent_firewall.tools", "files", "--root", "shared"]

[servers.other]
command = "/usr/bin/other-server"
env = { LANG = "C.UTF-8" }
""",
    )
    files, other = load(path).upstreams
    assert files.name == "files" and files.target.command == sys.executable
    assert files.target.args[-1] == "shared"
    assert files.target.cwd == tmp_path.resolve()
    assert files.target.env is None
    assert other.target.command == "/usr/bin/other-server"
    assert other.target.env == {"LANG": "C.UTF-8"}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("servers = {}", "at least 1"),
        ('[servers.Files]\ncommand = "x"', "lower-case"),
        ('[servers.a__b]\ncommand = "x"', "lower-case"),
        ("[servers.files]\nargs = []", "required"),
        ('[servers.files]\ncommand = "x"\nshell = true', "not permitted"),
        ('[servers.files]\ncommand = ""', "at least 1"),
        ("[servers.files\ncommand = 1", "isn't valid TOML"),
        ('typo = 1\n[servers.files]\ncommand = "x"', "not permitted"),
    ],
)
def test_bad_configs_say_what_is_wrong(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load(write(tmp_path, text))


def test_a_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="can't read"):
        load(tmp_path / "nope.toml")


def test_a_policy_file_is_required(tmp_path):
    with pytest.raises(ConfigError, match="policy"):
        load(write(tmp_path, '[servers.files]\ncommand = "x"', policy=False))


def test_a_bad_policy_file_is_a_config_error(tmp_path):
    path = write(tmp_path, '[servers.files]\ncommand = "x"')
    (tmp_path / "policy.toml").write_text('[tools."nope"]\n')
    with pytest.raises(ConfigError, match="neither"):
        load(path)


def test_at_most_twenty_servers(tmp_path):
    text = "\n".join(f'[servers.s{i}]\ncommand = "x"' for i in range(21))
    with pytest.raises(ConfigError):
        load(write(tmp_path, text))


def test_pins_live_next_to_the_config(tmp_path):
    setup = load(write(tmp_path, 'pins = "state/pins.json"\n[servers.files]\ncommand = "x"'))
    assert setup.gate.pins.path == tmp_path.resolve() / "state" / "pins.json"
    assert load(write(tmp_path, '[servers.files]\ncommand = "x"')).gate.pins.path is None


def test_an_injection_model_loads_only_with_the_right_pin(tmp_path):
    from test_checks_injection_model import export, fit

    pin = export(fit(), tmp_path / "model")
    section = f'[injection_model]\npath = "model"\nmanifest_sha256 = "{pin}"\n'
    setup = load(write(tmp_path, section + '[servers.files]\ncommand = "x"'))
    assert setup.model is not None and 0 < setup.model.threshold <= 1
    wrong = section.replace(pin, "0" * 64)
    with pytest.raises(ConfigError, match="injection model"):
        load(write(tmp_path, wrong + '[servers.files]\ncommand = "x"'))
    with pytest.raises(ConfigError):
        load(write(tmp_path, section.replace(pin, "short") + '[servers.files]\ncommand = "x"'))


def test_no_model_configured_means_rules_only(tmp_path):
    assert load(write(tmp_path, '[servers.files]\ncommand = "x"')).model is None
