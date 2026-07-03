from __future__ import annotations

import hashlib
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.bootstrap import create_app
from sentinel.config import Settings
from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.persistence.database import Base, Database
from sentinel.infrastructure.persistence.models import ApiKeyModel


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    db_path = tmp_path / "test.db"
    return Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{db_path}",
        log_level="DEBUG",
    )


@pytest_asyncio.fixture
async def database(settings: Settings) -> AsyncIterator[Database]:
    db = Database(settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield db
    finally:
        await db.dispose()


@pytest_asyncio.fixture
async def db_session(database: Database) -> AsyncIterator[AsyncSession]:
    async with database.session() as session:
        yield session


@pytest_asyncio.fixture
async def api_key(database: Database) -> str:
    """Inserts an active API key row and returns the raw (pre-hash) key value
    so tests can send it as a real ``Authorization: Bearer`` header — exactly
    how a real client authenticates, rather than bypassing auth in tests."""
    raw_key = f"test-{uuid.uuid4().hex}"
    async with database.session() as session:
        session.add(
            ApiKeyModel(
                name="test-key",
                key_hash=hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
                key_prefix=raw_key[:8],
                is_active=True,
                created_at=utcnow(),
            )
        )
        await session.commit()
    return raw_key


@pytest.fixture
def client(settings: Settings, database: Database) -> Iterator[TestClient]:
    """`database` runs migrations (via ``create_all``) against the same SQLite
    file referenced by ``settings`` before the app boots its own engine in
    `create_app`'s lifespan — both point at the same on-disk file, so the
    app sees an already-migrated schema without the two engines needing to
    share a connection pool.
    """
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client
