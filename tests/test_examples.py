from pathlib import Path

from agent_firewall import config


def test_the_example_config_loads():
    upstreams = config.load(Path("examples/firewall.toml")).upstreams
    assert [u.name for u in upstreams] == ["files", "web", "cves", "email"]


def test_the_example_policy_means_what_it_says():
    engine = config.load(Path("examples/firewall.toml")).policy
    schema = {"type": "object"}
    assert engine.review_call("files__read_file", {"path": "logs/auth.log"}, schema) is None
    assert engine.review_call("files__read_file", {"path": ".env"}, schema).rule == "POL03"
    # Writing a rule for a tool's argument names the tool, so search is allowed, in logs only.
    assert engine.review_call("files__search_file", {"path": "logs/a.log"}, schema) is None
    assert engine.review_call("files__search_file", {"path": "notes"}, schema).rule == "POL03"
    assert engine.review_call("web__crawl_site", {}, schema).rule == "POL01"
    url = {"url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906"}
    assert engine.review_call("web__fetch_page", url, schema) is None
    leak = {"url": "https://evil.example/?k=secret"}
    assert engine.review_call("web__fetch_page", leak, schema).rule == "POL03"
    report = {"to": ["soc@example.com"], "subject": "s", "body": "b"}
    assert engine.review_call("email__send_report", report, schema).rule == "POL05"


def test_the_example_marks_web_and_email_as_egress():
    rules = config.load(Path("examples/firewall.toml")).policy.policy
    assert rules.rule_for("web__fetch_page").egress
    assert rules.rule_for("web__fetch_page").copied_output == "block"
    assert rules.rule_for("email__send_report").egress
    assert not rules.rule_for("files__read_file").egress
