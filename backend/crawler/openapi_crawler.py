"""
OpenAPI v2 (Swagger) and v3 Specification Crawler & Parser
Extracts all API endpoints, HTTP methods, parameter schemas, and request bodies.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

COMMON_SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/v2/api-docs",
    "/docs/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
]


class OpenAPICrawler:
    """
    Crawls and parses OpenAPI 2.0 / 3.0 / 3.1 specifications.
    Can discover specs automatically from a base URL or ingest a direct spec URL/JSON.
    """

    @classmethod
    async def discover_and_crawl(cls, base_url: str, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
        """
        Attempt to automatically discover and parse an OpenAPI specification from a base URL.
        """
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True)
            should_close = True

        try:
            parsed = urlparse(base_url)
            root_url = f"{parsed.scheme}://{parsed.netloc}"

            # If user provided a direct link to a JSON/YAML spec
            if base_url.endswith((".json", ".yaml", ".yml")):
                try:
                    res = await client.get(base_url)
                    if res.status_code == 200:
                        spec = res.json()
                        return cls.parse_spec(spec, base_url=root_url)
                except Exception as e:
                    logger.debug(f"Direct spec fetch failed: {e}")

            # Probe common OpenAPI spec endpoints
            for path in COMMON_SPEC_PATHS:
                test_url = urljoin(root_url, path)
                try:
                    res = await client.get(test_url)
                    if res.status_code == 200 and "application/json" in res.headers.get("content-type", ""):
                        spec = res.json()
                        if "openapi" in spec or "swagger" in spec or "paths" in spec:
                            return cls.parse_spec(spec, base_url=root_url, spec_url=test_url)
                except Exception:
                    continue

            return {
                "discovered": False,
                "endpoints_count": 0,
                "endpoints": [],
                "message": "No OpenAPI/Swagger specification found at common paths."
            }
        finally:
            if should_close:
                await client.aclose()

    @classmethod
    def parse_spec(cls, spec: dict[str, Any], base_url: str = "", spec_url: str = "") -> dict[str, Any]:
        """
        Parse OpenAPI/Swagger JSON dictionary into normalized endpoint representations.
        """
        version = spec.get("openapi") or spec.get("swagger") or "unknown"
        title = spec.get("info", {}).get("title", "API Specification")
        description = spec.get("info", {}).get("description", "")
        paths = spec.get("paths", {})

        endpoints = []
        http_methods = ["get", "post", "put", "patch", "delete", "options", "head"]

        # Determine API server base path
        server_prefix = ""
        if "servers" in spec and spec["servers"]:
            server_prefix = spec["servers"][0].get("url", "")
        elif "basePath" in spec:
            server_prefix = spec.get("basePath", "")

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method in http_methods:
                if method in path_item:
                    op = path_item[method]
                    tags = op.get("tags", ["General"])
                    summary = op.get("summary") or op.get("description") or f"{method.upper()} {path_str}"
                    params = op.get("parameters", [])

                    extracted_params = []
                    for p in params:
                        if isinstance(p, dict):
                            extracted_params.append({
                                "name": p.get("name"),
                                "in": p.get("in"),  # query, path, header, cookie
                                "required": p.get("required", False),
                                "type": p.get("schema", {}).get("type", "string") if "schema" in p else p.get("type", "string")
                            })

                    # Construct full target URL
                    if server_prefix.startswith("http"):
                        full_target = urljoin(server_prefix, path_str.lstrip("/"))
                    elif base_url:
                        full_target = urljoin(base_url, (server_prefix + path_str).lstrip("/"))
                    else:
                        full_target = path_str

                    endpoints.append({
                        "path": path_str,
                        "method": method.upper(),
                        "summary": summary,
                        "tags": tags,
                        "parameters": extracted_params,
                        "target_url": full_target,
                        "operation_id": op.get("operationId", f"{method}_{path_str}"),
                        "requires_auth": "security" in op or "security" in spec
                    })

        return {
            "discovered": True,
            "version": version,
            "title": title,
            "description": description,
            "spec_url": spec_url,
            "endpoints_count": len(endpoints),
            "endpoints": endpoints
        }

