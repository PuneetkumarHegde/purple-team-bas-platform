"""
Web Spider & JavaScript Endpoint Extractor
Crawls HTML and parses JavaScript script tags and bundles to discover hidden/undocumented API routes.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

# Patterns that indicate API endpoint calls in JS bundles (e.g. fetch('/api/...'), axios.get('/v1/...'))
ENDPOINT_REGEX = re.compile(
    r"""(?:["'`])((?:/api|/v[0-9]+|/graphql|/rest|/auth|/user|/admin|/data)[a-zA-Z0-9_\-/\.]+)(?:["'`])""",
    re.IGNORECASE
)

SCRIPT_TAG_REGEX = re.compile(
    r"""<script[^>]+src=["']([^"']+)["']""",
    re.IGNORECASE
)

HREF_REGEX = re.compile(
    r"""(?:href|action)=["']([^"']+)["']""",
    re.IGNORECASE
)


class WebSpider:
    """
    Crawls web applications and scrapes client-side JavaScript bundles to extract API routes.
    """

    @classmethod
    async def crawl_site(
        cls,
        target_url: str,
        max_depth: int = 2,
        client: httpx.AsyncClient | None = None
    ) -> dict[str, Any]:
        """
        Crawls the target site and extracts all discovered API routes.
        """
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True)
            should_close = True

        discovered_endpoints: set[str] = set()
        crawled_scripts: set[str] = set()

        try:
            parsed = urlparse(target_url)
            root_url = f"{parsed.scheme}://{parsed.netloc}"

            # Fetch the root HTML page
            try:
                res = await client.get(target_url)
                if res.status_code != 200:
                    return {
                        "discovered_count": 0,
                        "endpoints": [],
                        "error": f"Target returned status code {res.status_code}"
                    }
                html = res.text
            except Exception as e:
                return {
                    "discovered_count": 0,
                    "endpoints": [],
                    "error": str(e)
                }

            # 1. Search HTML for direct API strings
            for match in ENDPOINT_REGEX.findall(html):
                if not match.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico")):
                    discovered_endpoints.add(match)

            # 2. Extract and inspect all script tags
            script_srcs = SCRIPT_TAG_REGEX.findall(html)
            for src in script_srcs[:10]:  # Limit to first 10 scripts
                script_url = urljoin(root_url, src)
                if script_url in crawled_scripts:
                    continue
                crawled_scripts.add(script_url)

                try:
                    s_res = await client.get(script_url)
                    if s_res.status_code == 200:
                        js_code = s_res.text
                        for match in ENDPOINT_REGEX.findall(js_code):
                            if not match.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico")):
                                discovered_endpoints.add(match)
                except Exception:
                    continue

            formatted_endpoints = []
            for path in sorted(discovered_endpoints):
                formatted_endpoints.append({
                    "path": path,
                    "method": "GET",  # Default inferred method
                    "summary": f"Discovered API route: {path}",
                    "tags": ["Spider Discovery"],
                    "target_url": urljoin(root_url, path),
                    "parameters": [],
                    "requires_auth": True if any(k in path.lower() for k in ["admin", "auth", "user", "secret"]) else False
                })

            return {
                "discovered_count": len(formatted_endpoints),
                "endpoints": formatted_endpoints,
                "scripts_analyzed": len(crawled_scripts)
            }
        finally:
            if should_close:
                await client.aclose()

