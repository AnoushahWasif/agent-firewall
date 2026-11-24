import pytest

from agent_firewall.evaluation.__main__ import main, wilson


def test_wilson_intervals():
    low, high = wilson(0, 6)
    assert low == 0.0 and 0.38 < high < 0.40
    low, high = wilson(6, 6)
    assert 0.60 < low < 0.62 and high == 1.0
    assert wilson(0, 0) == (0.0, 1.0)


def test_the_held_out_half_is_scored_once(tmp_path, capsys):
    out = tmp_path / "eval-test.json"
    out.write_text("{}")
    assert main(["--split", "test", "--out", str(out)]) == 2
    assert "scored once" in capsys.readouterr().err


def test_there_is_no_all_split():
    with pytest.raises(SystemExit):
        main(["--split", "all"])
