"""Tool names as the agent sees them: `server__tool` (decision 16).

Server names can't contain the separator, so splitting on the first one is always right, even
for upstream tools whose own names contain "__".
"""

import re

SEP = "__"
SERVER_NAME = re.compile(r"^[a-z][a-z0-9-]{0,30}$")


def check_server_name(name: str) -> str:
    if not SERVER_NAME.fullmatch(name):
        raise ValueError(
            f"server name {name!r}: use 1 to 31 lower-case letters, digits or dashes, "
            "starting with a letter"
        )
    return name


def public_name(server: str, tool: str) -> str:
    return f"{server}{SEP}{tool}"


def split_name(name: str) -> tuple[str, str] | None:
    """(server, tool), or None if the name isn't one the firewall handed out."""
    server, sep, tool = name.partition(SEP)
    if not sep or not tool or not SERVER_NAME.fullmatch(server):
        return None
    return server, tool
