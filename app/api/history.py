"""
URL analysis history API endpoints.
"""

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import database_session
from app.schemas.database import ScanResponse
from app.services.history_service import (
    get_analysis,
    get_history,
)


router = APIRouter(
    prefix="/history",
    tags=["History"],
)


@router.get(
    "",
    response_model=list[ScanResponse],
)
def get_history_endpoint(
    limit: int = 50,
    db: Session = Depends(
        database_session,
    ),
) -> list[ScanResponse]:
    """
    Return recent URL analysis history.
    """

    if limit < 1:
        raise HTTPException(
            status_code=400,
            detail="Limit must be greater than 0.",
        )

    if limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit cannot exceed 100.",
        )

    return get_history(
        db=db,
        limit=limit,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
)
def get_history_item(
    scan_id: int,
    db: Session = Depends(
        database_session,
    ),
) -> ScanResponse:
    """
    Return a single URL analysis from history.
    """

    if scan_id < 1:
        raise HTTPException(
            status_code=400,
            detail="Scan ID must be greater than 0.",
        )

    scan = get_analysis(
        db=db,
        scan_id=scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found.",
        )

    return scan