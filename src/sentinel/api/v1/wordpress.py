from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status

from sentinel.api.dependencies import (
    GetWordPressIncidentReport,
    GetWordPressInventory,
    RequireApiKey,
    VerifyWordPressCoreChecksums,
)
from sentinel.api.schemas.common import Envelope, ResponseMeta
from sentinel.api.schemas.wordpress import (
    CoreFileVerificationResponse,
    WordPressIncidentReportResponse,
    WordPressInventoryResponse,
)
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError

router = APIRouter(prefix="/wp", tags=["wordpress"])


@router.get(
    "/installations/{installation_id}/inventory",
    response_model=Envelope[WordPressInventoryResponse],
)
async def get_installation_inventory(
    request: Request,
    _: RequireApiKey,
    installation_id: UUID,
    query: GetWordPressInventory,
) -> Envelope[WordPressInventoryResponse]:
    try:
        report = await query.execute(installation_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return Envelope(
        data=WordPressInventoryResponse.from_report(report),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )


@router.get(
    "/installations/{installation_id}/integrity",
    response_model=Envelope[list[CoreFileVerificationResponse]],
)
async def get_installation_integrity(
    request: Request,
    _: RequireApiKey,
    installation_id: UUID,
    use_case: VerifyWordPressCoreChecksums,
) -> Envelope[list[CoreFileVerificationResponse]]:
    try:
        verifications = await use_case.execute(installation_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return Envelope(
        data=[CoreFileVerificationResponse.from_report(v) for v in verifications],
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )


@router.get(
    "/incidents/{incident_id}/report",
    response_model=Envelope[WordPressIncidentReportResponse],
)
async def get_incident_report(
    request: Request,
    _: RequireApiKey,
    incident_id: UUID,
    query: GetWordPressIncidentReport,
) -> Envelope[WordPressIncidentReportResponse]:
    try:
        report = await query.execute(incident_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return Envelope(
        data=WordPressIncidentReportResponse.from_report(report),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )
