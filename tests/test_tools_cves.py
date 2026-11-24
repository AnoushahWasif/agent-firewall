import json

import httpx2 as httpx
import pytest
from mcp import Client

from agent_firewall.tools.cves import MAX_DETAILS_CHARS, build_server

pytestmark = pytest.mark.anyio

JINJA = {
    "id": "GHSA-462w-v97r-4m45",
    "aliases": ["CVE-2019-10906"],
    "summary": "Jinja2 sandbox escape",
    "details": "The sandbox can be escaped via str.format_map.",
    "database_specific": {"severity": "high"},
    "published": "2019-04-10T14:30:13Z",
    "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906"}],
}


def text(result):
    return "\n".join(block.text for block in result.content)


async def call(tool, args, handler):
    async with Client(build_server(transport=httpx.MockTransport(handler))) as c:
        return await c.call_tool(tool, args)


async def test_lookup_package_follows_pages():
    bodies = []

    def handler(request):
        assert request.url.host == "api.osv.dev" and request.url.path == "/v1/query"
        body = json.loads(request.content)
        bodies.append(body)
        if "page_token" not in body:
            return httpx.Response(200, json={"vulns": [JINJA], "next_page_token": "p2"})
        other = {
            "id": "PYSEC-2019-217",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
        }
        return httpx.Response(200, json={"vulns": [other]})

    result = await call(
        "lookup_package", {"ecosystem": "PyPI", "name": "jinja2", "version": "2.10"}, handler
    )
    found = result.structured_content["result"]
    assert [v["id"] for v in found] == ["GHSA-462w-v97r-4m45", "PYSEC-2019-217"]
    assert found[0]["severity"] == "HIGH" and found[1]["severity"] == "CVSS:3.1/AV:N"
    assert bodies[0] == {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.10"}
    assert bodies[1]["page_token"] == "p2"


async def test_no_vulnerabilities_is_an_empty_list():
    result = await call(
        "lookup_package",
        {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0"},
        lambda r: httpx.Response(200, json={}),
    )
    assert result.structured_content == {"result": []}


async def test_unknown_ecosystems_and_bad_lengths_are_refused():
    def handler(request):
        raise AssertionError("no request")

    bad = await call(
        "lookup_package", {"ecosystem": "Hackage", "name": "x", "version": "1"}, handler
    )
    assert bad.is_error
    long = await call(
        "lookup_package", {"ecosystem": "PyPI", "name": "x" * 201, "version": "1"}, handler
    )
    assert long.is_error


async def test_get_vulnerability_is_cut_to_size():
    long = {**JINJA, "details": "d" * (MAX_DETAILS_CHARS + 500)}
    result = await call(
        "get_vulnerability",
        {"vuln_id": "GHSA-462w-v97r-4m45"},
        lambda r: httpx.Response(200, json=long),
    )
    vuln = result.structured_content
    assert vuln["aliases"] == ["CVE-2019-10906"] and len(vuln["details"]) == MAX_DETAILS_CHARS
    assert vuln["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2019-10906"]


@pytest.mark.parametrize("vuln_id", ["../../v1/query", "a", "GHSA/../x", "x" * 70, "1CVE"])
async def test_ids_that_could_change_the_path_are_refused(vuln_id):
    def handler(request):
        raise AssertionError("no request")

    result = await call("get_vulnerability", {"vuln_id": vuln_id}, handler)
    assert result.is_error and "advisory id" in text(result)


async def test_osv_failures_are_plain_messages():
    missing = await call(
        "get_vulnerability", {"vuln_id": "CVE-2099-0001"}, lambda r: httpx.Response(404)
    )
    assert "No advisory" in text(missing)
    down = await call(
        "lookup_package",
        {"ecosystem": "PyPI", "name": "x", "version": "1"},
        lambda r: httpx.Response(503),
    )
    assert "HTTP 503" in text(down)

    def timeout(request):
        raise httpx.ReadTimeout("slow", request=request)

    slow = await call("get_vulnerability", {"vuln_id": "CVE-2099-0001"}, timeout)
    assert "too long" in text(slow)
    odd = await call(
        "lookup_package",
        {"ecosystem": "PyPI", "name": "x", "version": "1"},
        lambda r: httpx.Response(200, json=[1]),
    )
    assert "unexpected" in text(odd)


async def test_an_advisory_without_an_id_is_refused():
    result = await call(
        "lookup_package",
        {"ecosystem": "PyPI", "name": "x", "version": "1"},
        lambda r: httpx.Response(200, json={"vulns": [{"summary": "no id"}]}),
    )
    assert result.is_error and "without an id" in text(result)
