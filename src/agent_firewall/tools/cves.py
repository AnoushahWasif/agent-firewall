"""Known vulnerabilities from OSV.dev: by package version, or by advisory id.

The host is fixed, so the model can't point this anywhere else. What it can choose (names,
versions, ids) is checked before it goes into a request.
"""

import re
from typing import Literal

import httpx2 as httpx
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel

OSV = "https://api.osv.dev"
TIMEOUT_SECONDS = 15.0
MAX_PAGES = 3
MAX_RESULTS = 50
MAX_DETAILS_CHARS = 4_000
MAX_REFERENCES = 10

Ecosystem = Literal["PyPI", "npm", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist"]
VULN_ID = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{2,63}$")


class VulnSummary(BaseModel):
    id: str
    aliases: list[str]
    summary: str
    severity: str | None


class Advisory(VulnSummary):
    details: str
    published: str | None
    references: list[str]


def _severity(vuln: dict) -> str | None:
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        return label.upper()
    for entry in vuln.get("severity") or []:
        if isinstance(entry, dict) and isinstance(entry.get("score"), str):
            return entry["score"]
    return None


def _summary(vuln: dict) -> dict:
    if not isinstance(vuln.get("id"), str):
        raise ToolError("OSV sent an advisory without an id")
    return {
        "id": vuln["id"],
        "aliases": [a for a in vuln.get("aliases") or [] if isinstance(a, str)][:10],
        "summary": str(vuln.get("summary") or "")[:300],
        "severity": _severity(vuln),
    }


async def _post(client: httpx.AsyncClient, path: str, body: dict) -> dict:
    try:
        response = await client.post(path, json=body)
    except httpx.TimeoutException as exc:
        raise ToolError("OSV took too long to answer") from exc
    except httpx.TransportError as exc:
        raise ToolError("Could not reach OSV") from exc
    if response.status_code >= 400:
        raise ToolError(f"OSV answered HTTP {response.status_code}")
    data = response.json()
    if not isinstance(data, dict):
        raise ToolError("OSV sent an unexpected answer")
    return data


def build_server(transport: httpx.AsyncBaseTransport | None = None) -> MCPServer:
    server = MCPServer("cves")

    def client() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=OSV, transport=transport, timeout=TIMEOUT_SECONDS, follow_redirects=False
        )

    @server.tool()
    async def lookup_package(ecosystem: Ecosystem, name: str, version: str) -> list[VulnSummary]:
        """Known vulnerabilities affecting one exact version of a package."""
        if not 1 <= len(name) <= 200 or not 1 <= len(version) <= 100:
            raise ToolError("Package name or version has an invalid length")
        query: dict = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        found: list[VulnSummary] = []
        async with client() as c:
            for _ in range(MAX_PAGES):
                data = await _post(c, "/v1/query", query)
                found += [
                    VulnSummary(**_summary(v))
                    for v in data.get("vulns") or []
                    if isinstance(v, dict)
                ]
                token = data.get("next_page_token")
                if not token or len(found) >= MAX_RESULTS:
                    break
                query["page_token"] = token
        return found[:MAX_RESULTS]

    @server.tool()
    async def get_vulnerability(vuln_id: str) -> Advisory:
        """One advisory by id (GHSA-..., CVE-..., PYSEC-...): summary, details and references."""
        if not VULN_ID.fullmatch(vuln_id):
            raise ToolError("That doesn't look like an advisory id")
        async with client() as c:
            try:
                response = await c.get(f"/v1/vulns/{vuln_id}")
            except httpx.TimeoutException as exc:
                raise ToolError("OSV took too long to answer") from exc
            except httpx.TransportError as exc:
                raise ToolError("Could not reach OSV") from exc
        if response.status_code == 404:
            raise ToolError("No advisory with that id")
        if response.status_code >= 400:
            raise ToolError(f"OSV answered HTTP {response.status_code}")
        vuln = response.json()
        if not isinstance(vuln, dict):
            raise ToolError("OSV sent an unexpected answer")
        details = (vuln.get("details") or "")[:MAX_DETAILS_CHARS]
        references = [
            r["url"]
            for r in vuln.get("references") or []
            if isinstance(r, dict) and isinstance(r.get("url"), str)
        ][:MAX_REFERENCES]
        published = vuln.get("published")
        return Advisory(
            **_summary(vuln),
            details=str(details),
            published=published if isinstance(published, str) else None,
            references=references,
        )

    return server
