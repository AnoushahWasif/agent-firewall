import httpx2 as httpx
import pytest
from mcp import Client

from agent_firewall.tools.web import MAX_BYTES, build_server, html_to_text

pytestmark = pytest.mark.anyio

PUBLIC = {"example.com": ["93.184.215.14"], "other.example": ["93.184.215.15"]}


def resolver(table):
    def resolve(host):
        return table.get(host, [])

    return resolve


def text(result):
    return "\n".join(block.text for block in result.content)


async def call(url, handler, table=PUBLIC):
    server = build_server(resolve=resolver(table), transport=httpx.MockTransport(handler))
    async with Client(server) as c:
        return await c.call_tool("fetch_page", {"url": url})


async def test_fetches_text_from_html():
    seen = []

    def handler(request):
        seen.append(request)
        html = "<html><style>x{}</style><h1>Advisory</h1><script>evil()</script><p>Patch</p>"
        return httpx.Response(200, html=html)

    result = await call("https://example.com/advisory", handler)
    assert text(result) == "Advisory\nPatch"
    # Sent to the checked address, but as the real host, with TLS checked against its name.
    [request] = seen
    assert request.url.host == "93.184.215.14"
    assert request.headers["host"] == "example.com"
    assert request.extensions["sni_hostname"] == "example.com"


@pytest.mark.parametrize(
    ("url", "table", "message"),
    [
        ("http://169.254.169.254/latest/meta-data/", {"169.254.169.254": ["169.254.169.254"]},
         "private or local"),
        ("http://localhost/", {"localhost": ["127.0.0.1"]}, "private or local"),
        ("http://intranet/", {"intranet": ["10.0.0.5"]}, "private or local"),
        ("http://v6.example/", {"v6.example": ["::1"]}, "private or local"),
        ("http://mapped.example/", {"mapped.example": ["::ffff:127.0.0.1"]}, "private or local"),
        # One private address among public ones is enough to refuse.
        ("http://mixed.example/", {"mixed.example": ["93.184.215.14", "192.168.1.1"]},
         "private or local"),
        ("file:///etc/passwd", PUBLIC, "Only http and https"),
        ("ftp://example.com/x", PUBLIC, "Only http and https"),
        ("http://user:pw@example.com/", PUBLIC, "user name or password"),
        ("http://example.com:8080/", PUBLIC, "default web ports"),
        ("http://nowhere.example/", PUBLIC, "Could not find"),
    ],
)  # fmt: skip
async def test_refused_before_any_request(url, table, message):
    def handler(request):
        raise AssertionError("no request should be sent")

    result = await call(url, handler, table)
    assert result.is_error and message in text(result)


async def test_a_redirect_to_a_private_address_is_refused():
    table = {**PUBLIC, "internal.example": ["10.1.2.3"]}

    def handler(request):
        if request.headers["host"] == "example.com":
            return httpx.Response(302, headers={"location": "http://internal.example/admin"})
        raise AssertionError("the redirect target must not be fetched")

    result = await call("https://example.com/", handler, table)
    assert result.is_error and "private or local" in text(result)


async def test_public_redirects_are_followed_but_not_forever():
    def to_other(request):
        if request.headers["host"] == "example.com":
            return httpx.Response(301, headers={"location": "https://other.example/page"})
        return httpx.Response(200, text="moved here")

    assert text(await call("https://example.com/", to_other)) == "moved here"

    def loop(request):
        return httpx.Response(302, headers={"location": "/again"})

    result = await call("https://example.com/", loop)
    assert result.is_error and "Too many redirects" in text(result)


async def test_large_binary_and_failed_pages():
    big = await call(
        "https://example.com/", lambda r: httpx.Response(200, text="x" * (MAX_BYTES + 1))
    )
    assert big.is_error and "too large" in text(big)
    image = await call(
        "https://example.com/",
        lambda r: httpx.Response(200, content=b"\x89PNG", headers={"content-type": "image/png"}),
    )
    assert image.is_error and "isn't text" in text(image)
    missing = await call("https://example.com/", lambda r: httpx.Response(404, text="no"))
    assert missing.is_error and "HTTP 404" in text(missing)


async def test_timeouts_and_connection_errors_are_plain_messages():
    def slow(request):
        raise httpx.ReadTimeout("slow", request=request)

    def down(request):
        raise httpx.ConnectError("refused", request=request)

    assert "too long" in text(await call("https://example.com/", slow))
    assert "Could not connect" in text(await call("https://example.com/", down))


def test_html_to_text_drops_hidden_parts():
    html = "<div>Visible<template><p>hidden</p></template><noscript>no</noscript></div>"
    assert html_to_text(html) == "Visible"
