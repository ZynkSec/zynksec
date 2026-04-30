"""Shallow-clone helpers for repo-scanner plugins.

Phase 3 Sprint 1 lands ``clone_shallow`` for gitleaks; later sprints
(semgrep, trivy, OSV, syft, grype) reuse the same primitive.  The
helper is intentionally tiny — it shells out to ``git`` rather than
pulling in pygit2 / dulwich, both to shrink the runtime dependency
surface and because every repo scanner already needs ``git`` on the
PATH for related operations (rev-parse, ls-tree, ...).
"""

from zynksec_scanners.repo.cloner import (
    CloneError,
    RepoHandle,
    clone_shallow,
    validate_clone_url,
)

__all__ = ["CloneError", "RepoHandle", "clone_shallow", "validate_clone_url"]
