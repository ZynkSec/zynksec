"""Celery task modules.  Imports register tasks with the Celery app."""

from zynksec_worker.tasks import scan, scan_group  # noqa: F401 — registers @task decorators

__all__ = ["scan", "scan_group"]
