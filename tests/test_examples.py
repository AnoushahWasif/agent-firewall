from pathlib import Path

from agent_firewall import config


def test_the_example_config_loads():
    upstreams = config.load(Path("examples/firewall.toml"))
    assert [u.name for u in upstreams] == ["files", "web", "cves", "email"]
