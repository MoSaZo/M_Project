"""
URL analysis API endpoints.
"""

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import database_session
from app.schemas.requests import URLRequest
from app.schemas.responses import URLAnalysisResponse
from app.services.analyzer_service import (
    analyze_and_save,
)
from app.services.report_service import ReportService

router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"],
)


@router.post(
    "",
    response_model=URLAnalysisResponse,
)
def analyze_url_endpoint(
    request: URLRequest,
    db: Session = Depends(
        database_session,
    ),
) -> URLAnalysisResponse:
    """
    Analyze a URL and save the result.
    """

    try:
        result = analyze_and_save(
            db=db,
            url=request.url,
        )

        return ReportService.to_response(result)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc