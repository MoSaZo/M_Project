"""
Report API endpoints.
"""

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.api.dependencies import database_session
from app.services.history_service import get_analysis
from app.services.report_service import ReportService

router = APIRouter(
    prefix="/report",
    tags=["Report"],
)


@router.get(
    "/{scan_id}",
    response_class=PlainTextResponse,
)
def get_report(
    scan_id: int,
    db: Session = Depends(database_session),
) -> str:
    """
    Return a plain-text report for one analysis.
    """

    scan = get_analysis(
        db=db,
        scan_id=scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return ReportService.build_text_report(
        scan,
    )