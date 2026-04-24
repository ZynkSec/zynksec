# zynksec-worker

Zynksec's Celery worker. Consumes the `scans` queue and executes
scan tasks.

## Status

Phase 0 Week 2: `scan.run` is a no-op that marks a scan `running`,
sleeps one second, then marks it `completed`. It proves the
end-to-end Celery pipe works. Week 3 replaces the sleep with a real
`ZapPlugin` run against a Juice Shop target.

## Running

Inside Docker Compose (the canonical dev path):

```
docker compose up -d worker
```

Standalone (requires DATABASE_URL + CELERY_BROKER_URL + CELERY_RESULT_BACKEND in env):

```
celery -A zynksec_worker.celery_app worker --loglevel=INFO --queues=scans
```
