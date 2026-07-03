#!/usr/bin/env sh
set -e

case "$1" in
  migrate)
    exec alembic upgrade head
    ;;
  api)
    exec uvicorn sentinel.bootstrap:app --host 0.0.0.0 --port 8443
    ;;
  worker)
    exec python -m sentinel.worker
    ;;
  *)
    exec "$@"
    ;;
esac
