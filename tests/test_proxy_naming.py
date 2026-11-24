import pytest

from agent_firewall.proxy.naming import check_server_name, public_name, split_name


def test_round_trip():
    assert public_name("files", "read_file") == "files__read_file"
    assert split_name("files__read_file") == ("files", "read_file")


def test_tool_names_may_contain_the_separator():
    assert split_name("files__read__all") == ("files", "read__all")


@pytest.mark.parametrize(
    "name", ["read_file", "files__", "__read_file", "Files__x", "a b__x", "f" * 32 + "__x"]
)
def test_names_the_firewall_never_hands_out(name):
    assert split_name(name) is None


@pytest.mark.parametrize("name", ["files", "web-2", "a"])
def test_good_server_names(name):
    assert check_server_name(name) == name


@pytest.mark.parametrize("name", ["", "Files", "two__parts", "-lead", "1st", "x" * 32, "a.b"])
def test_bad_server_names(name):
    with pytest.raises(ValueError):
        check_server_name(name)
