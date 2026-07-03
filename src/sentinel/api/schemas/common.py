from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel

TData = TypeVar("TData")


class ResponseMeta(BaseModel):
    request_id: str
    timestamp: datetime
    version: str = "1.0.0"


class Envelope(BaseModel, Generic[TData]):
    success: bool = True
    data: TData
    meta: ResponseMeta


class ErrorDetail(BaseModel):
    code: str
    message: str
    detail: dict[str, object] | None = None


class ErrorEnvelope(BaseModel):
    success: bool = False
    error: ErrorDetail
    meta: ResponseMeta


class PaginationInfo(BaseModel):
    cursor_next: str | None = None
    cursor_prev: str | None = None
    has_next: bool = False
    has_prev: bool = False
    limit: int
    total_count: int | None = None


class PaginatedEnvelope(BaseModel, Generic[TData]):
    success: bool = True
    data: list[TData]
    pagination: PaginationInfo
    meta: ResponseMeta
