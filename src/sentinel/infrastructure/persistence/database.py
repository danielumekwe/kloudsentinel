from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from sentinel.config import Settings


class Base(DeclarativeBase):
    """Declarative base shared by every ORM model. A single ``MetaData``
    instance here is what lets Alembic's ``target_metadata`` see every table
    across all bounded contexts without each one registering itself
    separately.
    """


def _enable_sqlite_pragmas(
    dbapi_connection: sqlite3.Connection, _connection_record: object
) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


def create_engine(settings: Settings) -> AsyncEngine:
    engine = create_async_engine(settings.database_url, echo=settings.database_echo)
    if engine.dialect.name == "sqlite":
        event.listen(engine.sync_engine, "connect", _enable_sqlite_pragmas)
    return engine


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


class Database:
    """Owns the engine and session-factory lifecycle for one process.

    Exactly one instance is created at application startup (see
    ``sentinel.bootstrap``) and handed out via dependency injection — nothing
    else in the codebase is permitted to call ``create_async_engine`` directly.
    """

    def __init__(self, settings: Settings) -> None:
        self.engine = create_engine(settings)
        self.session_factory = create_session_factory(self.engine)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session

    async def dispose(self) -> None:
        await self.engine.dispose()
