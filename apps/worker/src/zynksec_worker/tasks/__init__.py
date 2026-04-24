"""Celery task modules.  Imports register tasks with the Celery app."""

from zynksec_worker.tasks import scan  # noqa: F401 — registers @task decorators

__all__ = ["scan"]
