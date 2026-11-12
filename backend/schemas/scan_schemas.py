"""
ⒸAngelaMos | 2025
Scan model API validation and serialization
Extended with OpenAPI Crawler and AI Purple-Team Simulation Schemas
"""

from __future__ import annotations

from typing import Any
from datetime import datetime
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
)

from config import settings
from core.enums import TestType
from .test_result_schemas import TestResultResponse


class ScanRequest(BaseModel):
    """
    Schema for creating a new security scan
    """
    target_url: HttpUrl = Field(max_length=settings.URL_MAX_LENGTH)
    auth_token: str | None = None
    tests_to_run: list[TestType] = Field(min_length=1)
    max_requests: int = Field(
        default=settings.DEFAULT_MAX_REQUESTS,
        ge=1,
        le=settings.SCANNER_MAX_CONCURRENT_REQUESTS,
    )


class ScanResponse(BaseModel):
    """
    Schema for scan data in API responses
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    target_url: str
    scan_date: datetime
    created_at: datetime
    test_results: list[TestResultResponse] = []

    @property
    def total_tests(self) -> int:
        return len(self.test_results)

    @property
    def vulnerabilities_found(self) -> int:
        return sum(1 for r in self.test_results if r.status == "vulnerable")


# =========================================================================
# OpenAPI Crawler & Purple-Team BAS Schemas
# =========================================================================

class CrawlRequest(BaseModel):
    """
    Request to crawl a website or API documentation for endpoints
    """
    target_url: str = Field(description="Base URL or direct OpenAPI JSON link")
    crawl_mode: str = Field(default="auto", description="'auto', 'openapi', or 'spider'")


class DiscoveredEndpoint(BaseModel):
    path: str
    method: str = "GET"
    summary: str = ""
    target_url: str
    parameters: list[dict[str, Any]] = []
    requires_auth: bool = False
    tags: list[str] = []


class CrawlResponse(BaseModel):
    discovered: bool
    endpoints_count: int
    endpoints: list[DiscoveredEndpoint] = []
    source: str = "OpenAPI Spec"
    spec_url: str | None = None
    title: str = ""
    message: str = ""


class PurpleTeamRequest(BaseModel):
    base_url: str
    endpoints: list[DiscoveredEndpoint]
    tests_to_run: list[TestType] = [TestType.AUTH, TestType.SQLI, TestType.RATE_LIMIT, TestType.IDOR]
    auth_token: str | None = None
    token_attacker: str | None = None  # User B token for Dual-Token BOLA testing


class PurpleTeamTelemetry(BaseModel):
    endpoint: str
    method: str
    test_name: str
    payload_sample: str = ""
    vulnerability_status: str  # safe, vulnerable, error
    severity: str              # INFO, LOW, MEDIUM, HIGH, CRITICAL
    ai_threat_score: float
    ai_matched_rules: list[str] = []
    defense_verdict: str       # CAUGHT_BY_AI, STEALTH_BYPASS, BENIGN_TRAFFIC
    remediation_patch: str = ""


class PurpleTeamResponse(BaseModel):
    target_url: str
    scan_date: datetime
    total_endpoints_scanned: int
    total_attacks_simulated: int
    vulnerabilities_found: int
    ai_detected_count: int
    ai_bypassed_count: int
    defense_coverage_percent: float
    waf_info: dict[str, Any] = {}
    telemetry: list[PurpleTeamTelemetry] = []

