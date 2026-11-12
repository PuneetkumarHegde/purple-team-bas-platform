"""
©AngelaMos | 2025
Scan routes - create, retrieve, manage security scans, automated crawling, and purple-team BAS
"""

from fastapi import (
    APIRouter,
    Depends,
    Request,
    status,
)
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from config import settings
from core.database import get_db
from core.dependencies import get_current_user
from fastapi.responses import HTMLResponse
from schemas.scan_schemas import (
    CrawlRequest,
    CrawlResponse,
    PurpleTeamRequest,
    PurpleTeamResponse,
    ScanRequest,
    ScanResponse,
)
from schemas.user_schemas import UserResponse
from services.purple_team_service import PurpleTeamService
from services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["scans"])
limiter = Limiter(key_func=get_remote_address)


# =========================================================================
# Crawler & Purple-Team Endpoints
# =========================================================================

@router.post(
    "/crawl",
    response_model=CrawlResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("30/minute")
async def crawl_api(
    request: Request,
    crawl_request: CrawlRequest,
    current_user: UserResponse = Depends(get_current_user),
) -> CrawlResponse:
    """
    Auto-discover API endpoints from an OpenAPI spec or JavaScript web scraping.
    """
    return await PurpleTeamService.crawl(crawl_request)


@router.post(
    "/purple-team",
    response_model=PurpleTeamResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("20/minute")
async def execute_purple_team(
    request: Request,
    purple_request: PurpleTeamRequest,
    current_user: UserResponse = Depends(get_current_user),
) -> PurpleTeamResponse:
    """
    Execute closed-loop offensive attack fuzzing, perimeter WAF inspection, and AI threat detection.
    """
    return await PurpleTeamService.execute_purple_team_audit(purple_request)


@router.post(
    "/report/generate",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("30/minute")
async def generate_audit_report(
    request: Request,
    report_data: dict,
    current_user: UserResponse = Depends(get_current_user),
) -> HTMLResponse:
    """
    Generate downloadable/printable executive HTML audit report.
    """
    html_content = PurpleTeamService.generate_html_report(report_data)
    return HTMLResponse(content=html_content)


# =========================================================================
# Traditional Single Scan Endpoints
# =========================================================================

@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(settings.API_RATE_LIMIT_SCAN)
async def create_scan(
    request: Request,
    scan_request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
) -> ScanResponse:
    """
    Create and execute a new security scan
    """
    return ScanService.run_scan(db, current_user.id, scan_request)


@router.get(
    "/",
    response_model=list[ScanResponse],
    status_code=status.HTTP_200_OK,
)
@limiter.limit(settings.API_RATE_LIMIT_DEFAULT)
async def get_user_scans(
    request: Request,
    skip: int = 0,
    limit: int | None = None,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
) -> list[ScanResponse]:
    """
    Get all scans for the authenticated user
    """
    return ScanService.get_user_scans(db, current_user.id, skip, limit)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit(settings.API_RATE_LIMIT_DEFAULT)
async def get_scan(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
) -> ScanResponse:
    """
    Get a specific scan by ID
    """
    return ScanService.get_scan_by_id(db, scan_id, current_user.id)


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
@limiter.limit(settings.API_RATE_LIMIT_DEFAULT)
async def delete_scan(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
) -> None:
    """
    Delete a scan by ID
    """
    ScanService.delete_scan(db, scan_id, current_user.id)
