from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status

from sentinel.api.dependencies import (
    GetIncident,
    ListIncidentEvidence,
    ListIncidents,
    ListIncidentTimeline,
)
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.web.dependencies import RequireAdminSession, templates

router = APIRouter(prefix="/incidents", tags=["dashboard-incidents"])


@router.get("")
async def list_incidents(
    request: Request,
    query: ListIncidents,
    admin_user: RequireAdminSession,
) -> Response:
    incidents = await query.execute(limit=100, offset=0)

    return templates.TemplateResponse(
        request,
        "incidents.html",
        {"admin_user": admin_user, "incidents": incidents},
    )


@router.get("/{incident_id}")
async def get_incident(
    request: Request,
    incident_id: UUID,
    get_incident_query: GetIncident,
    list_timeline_query: ListIncidentTimeline,
    list_evidence_query: ListIncidentEvidence,
    admin_user: RequireAdminSession,
) -> Response:
    try:
        incident = await get_incident_query.execute(incident_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    timeline = await list_timeline_query.execute(incident_id)
    evidence = await list_evidence_query.execute(incident_id)

    return templates.TemplateResponse(
        request,
        "incident_detail.html",
        {
            "admin_user": admin_user,
            "incident": incident,
            "timeline": timeline,
            "evidence": evidence,
        },
    )
