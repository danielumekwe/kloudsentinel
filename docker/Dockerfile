# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /uvx /usr/local/bin/

WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev


FROM python:3.12-slim AS runtime

RUN groupadd --gid 1000 sentinel \
    && useradd --uid 1000 --gid sentinel --shell /usr/sbin/nologin --no-create-home sentinel

WORKDIR /app
COPY --from=builder /build/.venv /app/.venv
COPY --from=builder /build/src /app/src
COPY alembic.ini ./
COPY alembic ./alembic
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
RUN chmod +x /app/docker/entrypoint.sh

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONPATH="/app/src" \
    PYTHONUNBUFFERED=1

RUN mkdir -p /data && chown sentinel:sentinel /data

USER sentinel

EXPOSE 8443

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["api"]
