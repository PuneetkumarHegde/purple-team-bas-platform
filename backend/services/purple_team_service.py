"""
Purple-Team Breach & Attack Simulation (BAS) Service
Coordinates automated crawling, multi-endpoint vulnerability scanning, WAF detection, Dual-Token BOLA, and AI threat detection evaluation.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from ai_engine.threat_scorer import AIThreatEngine
from crawler.openapi_crawler import OpenAPICrawler
from crawler.web_spider import WebSpider
from core.enums import TestType
from scanners.bola_engine import DualTokenBOLAEngine
from scanners.waf_scanner import WAFAndHeaderScanner
from services.report_generator import ReportGenerator
from schemas.scan_schemas import (
    CrawlRequest,
    CrawlResponse,
    DiscoveredEndpoint,
    PurpleTeamRequest,
    PurpleTeamResponse,
    PurpleTeamTelemetry,
)

logger = logging.getLogger(__name__)


class PurpleTeamService:
    """
    Coordinates crawler discovery, perimeter WAF inspection, and closed-loop offensive vs. AI defensive evaluation.
    """

    @classmethod
    async def crawl(cls, request: CrawlRequest) -> CrawlResponse:
        """
        Discover endpoints via OpenAPI or Web Spider.
        """
        target_url = request.target_url.strip()

        # 1. Try OpenAPI Discovery first
        if request.crawl_mode in ["auto", "openapi"]:
            try:
                openapi_res = await OpenAPICrawler.discover_and_crawl(target_url)
                if openapi_res.get("discovered") and openapi_res.get("endpoints_count", 0) > 0:
                    endpoints = [
                        DiscoveredEndpoint(
                            path=ep["path"],
                            method=ep["method"],
                            summary=ep.get("summary", ""),
                            target_url=ep["target_url"],
                            parameters=ep.get("parameters", []),
                            requires_auth=ep.get("requires_auth", False),
                            tags=ep.get("tags", []),
                        )
                        for ep in openapi_res["endpoints"]
                    ]
                    return CrawlResponse(
                        discovered=True,
                        endpoints_count=len(endpoints),
                        endpoints=endpoints,
                        source="OpenAPI Spec",
                        spec_url=openapi_res.get("spec_url"),
                        title=openapi_res.get("title", "Discovered API"),
                        message=f"Successfully extracted {len(endpoints)} endpoints from OpenAPI specification."
                    )
            except Exception as e:
                logger.warning(f"OpenAPI discovery encountered error: {e}")

        # 2. Try Web Spider fallback
        if request.crawl_mode in ["auto", "spider"]:
            try:
                spider_res = await WebSpider.crawl_site(target_url)
                if spider_res.get("discovered_count", 0) > 0:
                    endpoints = [
                        DiscoveredEndpoint(
                            path=ep["path"],
                            method=ep["method"],
                            summary=ep.get("summary", ""),
                            target_url=ep["target_url"],
                            parameters=[],
                            requires_auth=ep.get("requires_auth", False),
                            tags=ep.get("tags", []),
                        )
                        for ep in spider_res["endpoints"]
                    ]
                    return CrawlResponse(
                        discovered=True,
                        endpoints_count=len(endpoints),
                        endpoints=endpoints,
                        source="JavaScript Web Spider",
                        title="Web Scraped API Endpoints",
                        message=f"Discovered {len(endpoints)} endpoints from HTML/JavaScript bundles."
                    )
            except Exception as e:
                logger.warning(f"Web spider encountered error: {e}")

        # Fallback: Treat the target URL itself as the single endpoint
        return CrawlResponse(
            discovered=True,
            endpoints_count=1,
            endpoints=[
                DiscoveredEndpoint(
                    path=target_url,
                    method="GET",
                    summary="Target Endpoint",
                    target_url=target_url,
                )
            ],
            source="Single URL Target",
            message="No automatic spec discovered; target initialized as primary endpoint."
        )

    @classmethod
    async def execute_purple_team_audit(
        cls,
        request: PurpleTeamRequest,
    ) -> PurpleTeamResponse:
        """
        Execute fast, asynchronous attack fuzzing across endpoints and evaluate with AI Threat Engine.
        """
        telemetry: list[PurpleTeamTelemetry] = []
        vulnerabilities_found = 0
        ai_detected_count = 0
        ai_bypassed_count = 0

        # 1. Inspect Perimeter WAF & CORS configuration
        try:
            waf_info = await WAFAndHeaderScanner.analyze(request.base_url)
        except Exception:
            waf_info = {
                "detected_waf": "Direct Origin / No WAF",
                "cors_status": {"vulnerable": False, "details": "CORS check skipped"},
                "security_rating": "B"
            }

        # Sample test vectors for AI telemetry
        sample_payloads = {
            TestType.SQLI: "' OR 1=1--",
            TestType.AUTH: "Bearer invalid_tampered_token.none_alg",
            TestType.RATE_LIMIT: "[Burst 10 req/s concurrency]",
            TestType.IDOR: "/records/1042?user_id=2",
        }

        # Cap at 10 endpoints for fast real-time interactive execution
        selected_endpoints = request.endpoints[:10]

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
            for ep in selected_endpoints:
                target_url = ep.target_url

                # Normalize headers
                auth_header = {}
                if request.auth_token:
                    t_val = request.auth_token if request.auth_token.startswith("Bearer ") else f"Bearer {request.auth_token}"
                    auth_header = {"Authorization": t_val}

                for test_type in request.tests_to_run:
                    payload_sample = sample_payloads.get(test_type, "")
                    vuln_status = "safe"
                    severity = "INFO"

                    try:
                        # Test A: SQL Injection
                        if test_type == TestType.SQLI:
                            payload_sample = "' OR 1=1--"
                            sep = "&" if "?" in target_url else "?"
                            probe_url = f"{target_url}{sep}query={payload_sample}"
                            res = await client.get(probe_url, headers=auth_header)
                            body_lower = res.text.lower()
                            if any(sig in body_lower for sig in ["syntax error", "sql syntax", "pg_", "ora-", "mysql_"]):
                                vuln_status = "vulnerable"
                                severity = "HIGH"

                        # Test B: Authentication
                        elif test_type == TestType.AUTH:
                            payload_sample = "Bearer invalid.token.none_alg"
                            res = await client.get(target_url, headers={"Authorization": payload_sample})
                            if ep.requires_auth and res.status_code == 200:
                                vuln_status = "vulnerable"
                                severity = "CRITICAL"

                        # Test C: Rate Limiting (Fast burst of 10 async requests)
                        elif test_type == TestType.RATE_LIMIT:
                            payload_sample = "[Burst 10 requests]"
                            burst_tasks = [client.get(target_url, headers=auth_header) for _ in range(10)]
                            responses = await asyncio.gather(*burst_tasks, return_exceptions=True)
                            valid_res = [r for r in responses if isinstance(r, httpx.Response)]
                            has_429 = any(r.status_code == 429 for r in valid_res)
                            has_ratelimit_header = any(
                                any("ratelimit" in k.lower() for k in r.headers.keys()) for r in valid_res
                            )
                            if not has_429 and not has_ratelimit_header and len(valid_res) >= 8:
                                vuln_status = "vulnerable"
                                severity = "MEDIUM"

                        # Test D: IDOR / BOLA (Dual Token or Sequential Probe)
                        elif test_type == TestType.IDOR:
                            if request.auth_token and request.token_attacker:
                                bola_result = await DualTokenBOLAEngine.test_bola(
                                    target_url,
                                    request.auth_token,
                                    request.token_attacker,
                                    client=client
                                )
                                vuln_status = bola_result.get("status", "safe")
                                severity = bola_result.get("severity", "INFO")
                                payload_sample = f"User B Replay -> {target_url}"
                            else:
                                payload_sample = "IDOR Probe (?id=2)"
                                sep = "&" if "?" in target_url else "?"
                                res = await client.get(f"{target_url}{sep}id=2", headers=auth_header)
                                if res.status_code == 200 and ep.requires_auth and not request.auth_token:
                                    vuln_status = "vulnerable"
                                    severity = "HIGH"

                    except Exception as e:
                        logger.debug(f"Test {test_type} on {target_url} exception: {e}")
                        vuln_status = "safe"
                        severity = "INFO"

                    if vuln_status == "vulnerable":
                        vulnerabilities_found += 1

                    # 2. Evaluate attack with AI Defensive Threat Engine
                    defense_eval = AIThreatEngine.evaluate(
                        uri=ep.path,
                        payload=payload_sample,
                        test_type=test_type.value,
                        is_attack=True
                    )

                    if defense_eval.defense_verdict == "CAUGHT_BY_AI":
                        ai_detected_count += 1
                    elif defense_eval.defense_verdict == "STEALTH_BYPASS":
                        ai_bypassed_count += 1

                    telemetry.append(
                        PurpleTeamTelemetry(
                            endpoint=ep.path,
                            method=ep.method,
                            test_name=test_type.value.upper(),
                            payload_sample=payload_sample,
                            vulnerability_status=vuln_status,
                            severity=severity.upper(),
                            ai_threat_score=defense_eval.threat_score,
                            ai_matched_rules=defense_eval.matched_rules,
                            defense_verdict=defense_eval.defense_verdict,
                            remediation_patch=defense_eval.remediation_patch,
                        )
                    )

        total_attacks = len(telemetry)
        if total_attacks > 0:
            coverage_pct = round((ai_detected_count / total_attacks) * 100, 1)
        else:
            coverage_pct = 0.0

        return PurpleTeamResponse(
            target_url=request.base_url,
            scan_date=datetime.utcnow(),
            total_endpoints_scanned=len(selected_endpoints),
            total_attacks_simulated=total_attacks,
            vulnerabilities_found=vulnerabilities_found,
            ai_detected_count=ai_detected_count,
            ai_bypassed_count=ai_bypassed_count,
            defense_coverage_percent=coverage_pct,
            waf_info=waf_info,
            telemetry=telemetry,
        )

    @classmethod
    def generate_html_report(cls, data: dict[str, Any]) -> str:
        """
        Generate standalone HTML report from audit results.
        """
        return ReportGenerator.generate_html_report(
            target_url=data.get("target_url", "API Audit"),
            waf_info=data.get("waf_info", {}),
            telemetry=data.get("telemetry", []),
            stats={
                "total_endpoints": data.get("total_endpoints_scanned", 0),
                "vulnerabilities_found": data.get("vulnerabilities_found", 0),
                "defense_coverage_percent": data.get("defense_coverage_percent", 0),
            }
        )
