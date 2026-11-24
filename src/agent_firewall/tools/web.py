"""Fetch a public web page as plain text.

The model chooses the URL, so this is an SSRF target: a page or a log line can ask the agent to
fetch http://169.254.169.254/ (cloud credentials) or something on localhost. So:

- only http and https, on the default ports;
- the host is resolved first and every address must be public;
- the request goes to that checked address, with the TLS certificate still checked against the
  host name, so the name can't be re-pointed (DNS rebinding) between the check and the request;
- redirects are followed by hand, each one checked again, at most MAX_REDIRECTS;
- size and time are capped, and only text types are read.
"""

import ipaddress
import socket
from collections.abc import Callable
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx2 as httpx
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

MAX_BYTES = 1_000_000
MAX_TEXT_CHARS = 20_000
MAX_REDIRECTS = 3
TIMEOUT_SECONDS = 10.0
TEXT_TYPES = ("text/html", "text/plain", "application/json", "application/xhtml+xml")

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ToolError("Could not find that host") from exc
    return sorted({info[4][0] for info in infos})


def check_url(url: str, resolve: Resolver) -> tuple[str, str]:
    """(host, address) to connect to, or ToolError. Every resolved address must be public."""
    if len(url) > 2000:
        raise ToolError("URL is too long")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ToolError("Only http and https URLs can be fetched")
    if parts.username or parts.password:
        raise ToolError("URLs with a user name or password are refused")
    host = parts.hostname
    if not host:
        raise ToolError("URL has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise ToolError("URL has an invalid port") from exc
    if port not in (None, 80, 443):
        raise ToolError("Only the default web ports are allowed")
    addresses = resolve(host)
    if not addresses:
        raise ToolError("Could not find that host")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise ToolError("That host is on a private or local network")
    return host, addresses[0]


class _TextOnly(HTMLParser):
    SKIP = {"script", "style", "noscript", "template", "svg"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skipping = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skipping += 1

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skipping:
            self._skipping -= 1

    def handle_data(self, data):
        if not self._skipping and data.strip():
            self.parts.append(data.strip())


def html_to_text(html: str) -> str:
    parser = _TextOnly()
    parser.feed(html)
    return "\n".join(parser.parts)


def _pinned(url: str, host: str, address: str) -> tuple[str, dict, dict]:
    """The URL rewritten to the checked address, plus the Host header and TLS name to keep."""
    parts = urlsplit(url)
    literal = f"[{address}]" if ":" in address else address
    netloc = literal + (f":{parts.port}" if parts.port else "")
    pinned = parts._replace(netloc=netloc).geturl()
    return pinned, {"host": parts.netloc.rsplit("@", 1)[-1]}, {"sni_hostname": host}


async def fetch(url: str, resolve: Resolver, transport: httpx.AsyncBaseTransport | None) -> str:
    async with httpx.AsyncClient(
        transport=transport, timeout=TIMEOUT_SECONDS, follow_redirects=False
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            host, address = check_url(url, resolve)
            pinned, headers, extensions = _pinned(url, host, address)
            request = client.build_request("GET", pinned, headers=headers, extensions=extensions)
            try:
                response = await client.send(request, stream=True)
            except httpx.TimeoutException as exc:
                raise ToolError("The site took too long to answer") from exc
            except httpx.TransportError as exc:
                raise ToolError("Could not connect to the site") from exc
            try:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise ToolError("Redirect without a location")
                    url = urljoin(url, location)
                    continue
                if response.status_code >= 400:
                    raise ToolError(f"The site answered HTTP {response.status_code}")
                kind = response.headers.get("content-type", "").split(";")[0].strip().lower()
                if kind not in TEXT_TYPES:
                    raise ToolError("That page isn't text")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_BYTES:
                        raise ToolError("That page is too large")
            finally:
                await response.aclose()
            text = body.decode(response.encoding or "utf-8", errors="replace")
            if kind in ("text/html", "application/xhtml+xml"):
                text = html_to_text(text)
            if len(text) > MAX_TEXT_CHARS:
                text = text[:MAX_TEXT_CHARS] + "\n[cut: page is longer]"
            return text
    raise ToolError("Too many redirects")


def build_server(
    resolve: Resolver = system_resolver, transport: httpx.AsyncBaseTransport | None = None
) -> MCPServer:
    server = MCPServer("web")

    @server.tool()
    async def fetch_page(url: str) -> str:
        """Fetch a public web page and return its text (no scripts or styles)."""
        return await fetch(url, resolve, transport)

    return server
