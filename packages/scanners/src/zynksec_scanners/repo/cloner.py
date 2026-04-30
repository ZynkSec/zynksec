"""Shallow git clone with a strict URL allowlist.

Security boundary (CLAUDE.md §6, §10):

  * Hard-deny ``ssh://``, ``git://``, ``file://``, and any scheme
    not on the configured allow-list.  ``ssh`` would let a clone
    pull in a deploy-key context the worker shouldn't have;
    ``git`` is unauthenticated TCP and fails the TLS-everywhere
    rule; ``file`` would expose the worker FS as a clone target
    (sandbox escape).  These three are denied unconditionally —
    no env var loosens them.

  * Allow-list of HOSTS for production: github.com / gitlab.com /
    bitbucket.org by default.  Operators can extend this via
    ``ZYNKSEC_CLONE_ALLOWED_HOSTS`` (comma-separated) so an
    on-prem GitLab works without code changes.

  * Allow-list of SCHEMES, defaulting to ``https`` only in
    production.  Tests that run against an in-network HTTP fixture
    server set ``ZYNKSEC_CLONE_ALLOWED_SCHEMES=http,https`` so the
    fixture is reachable WITHOUT relaxing the production default.

  * URL length cap (2048 chars — same as the DB column) to keep
    pathological inputs from reaching git itself.

The clone happens via ``subprocess.run`` in list-form (no
``shell=True``, no string interpolation — CLAUDE.md §6).  Working
directories live under ``/tmp/zynksec-scans/<scan_id>/`` so a
process restart and an ``rm -rf /tmp/zynksec-scans`` is the only
cleanup operators ever need.

The ``RepoHandle`` is a context manager so the worker's normal
``with clone_shallow(...) as handle:`` flow handles cleanup even
when the scanner crashes mid-run.  The temporary directory is the
plugin's responsibility — :class:`GitleaksPlugin` owns the lifecycle.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess  # noqa: S404 — controlled, list-form only
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import structlog

_log = structlog.get_logger(__name__)


_DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset({"github.com", "gitlab.com", "bitbucket.org"})
_DEFAULT_ALLOWED_SCHEMES: frozenset[str] = frozenset({"https"})
_DENIED_SCHEMES: frozenset[str] = frozenset({"ssh", "git", "file"})

#: Control characters that must never appear in a clone URL.
#: Pre-merge security review BLOCKER #4: a URL like
#: ``https://github.com/owner/repo.git\necho pwned`` parsed by
#: ``urlsplit`` extracts host=``github.com`` (the newline is in the
#: path, not the netloc) and survives the existing scheme/host
#: checks.  When git's stderr echoes the URL into the cloner's
#: error message, the embedded newline fragments the message via
#: ``splitlines()[-1]`` extraction, letting an attacker control
#: the trailing line that ends up in ``Scan.failure_reason`` and
#: structured-log lines.  Reject the whole printable-ASCII control
#: range upfront.
_FORBIDDEN_URL_CODEPOINTS: frozenset[str] = frozenset(chr(c) for c in range(0x00, 0x20)) | {
    chr(0x7F)
}

_MAX_URL_LENGTH: int = 2048
_DEFAULT_CLONE_TIMEOUT_S: int = 60


class CloneError(RuntimeError):
    """Raised when a clone is rejected by the allow-list or fails on disk."""


@dataclass(frozen=True)
class RepoHandle:
    """A successfully-cloned repo on local disk.

    ``path`` is the working tree root.  Plugins read from it and
    must not mutate it.  Cleanup is driven by the surrounding
    ``with clone_shallow(...) as handle:`` block.
    """

    path: Path
    git_url: str


def _allowed_hosts() -> frozenset[str]:
    """Production hosts + any extras from the env var."""
    extra = os.environ.get("ZYNKSEC_CLONE_ALLOWED_HOSTS", "").strip()
    if not extra:
        return _DEFAULT_ALLOWED_HOSTS
    return _DEFAULT_ALLOWED_HOSTS | {h.strip().lower() for h in extra.split(",") if h.strip()}


def _allowed_schemes() -> frozenset[str]:
    """Production scheme set + any extras from the env var.

    Hard-denied schemes (``ssh``, ``git``, ``file``) cannot be
    re-added even if the env var lists them.  The denylist wins.
    """
    extra = os.environ.get("ZYNKSEC_CLONE_ALLOWED_SCHEMES", "").strip()
    if not extra:
        return _DEFAULT_ALLOWED_SCHEMES
    user = {s.strip().lower() for s in extra.split(",") if s.strip()}
    return (_DEFAULT_ALLOWED_SCHEMES | user) - _DENIED_SCHEMES


def _host_is_ip_literal(host: str) -> bool:
    """True if ``host`` is an IPv4 / IPv6 literal address.

    Bracketed IPv6 hosts (``[::1]``) come out of ``urlsplit`` with
    the brackets stripped, so the literal portion is what
    :func:`ipaddress.ip_address` parses.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _path_has_traversal(path: str) -> bool:
    """True if any path segment is exactly ``..``.

    Doesn't match substrings like ``..foo`` (legitimate filenames
    in some forks) — segments only.  Both raw ``..`` and the
    percent-encoded ``%2e%2e`` (case-insensitive) count.
    """
    lowered = path.lower().replace("%2e", ".")
    return any(seg == ".." for seg in lowered.split("/"))


def validate_clone_url(git_url: str) -> tuple[str, str]:
    """Reject anything outside the allow-list; return (scheme, host).

    Raises :class:`CloneError` with a message safe to surface to
    the caller (no secrets, no internal paths) — the URL itself
    is not echoed back since it could carry a userinfo segment
    (``https://token@github.com/...``) we'd rather not leak.

    Public so the API request-validation layer (Pydantic
    ``model_validator`` on ``TargetCreate``) can apply the same
    allow-list at write-time, before a bad URL is persisted.  One
    source of truth — API and cloner share allow-list semantics
    so a Target that survives validation is one the cloner will
    accept at scan-time.

    Phase 3 Sprint 1 pre-merge security review BLOCKER #4: extends
    the validator to reject (in order) control characters,
    percent-encoded null bytes, raw IP literal hosts (SSRF surface
    to localhost / RFC1918 / link-local / IPv6 loopback), and
    ``..`` path-traversal segments.  See the per-block comments
    below for the threat each one closes.
    """
    if not git_url or len(git_url) > _MAX_URL_LENGTH:
        raise CloneError(
            f"clone URL is empty or longer than {_MAX_URL_LENGTH} characters",
        )

    # Control-character rejection.  Newline / carriage return / tab /
    # null / etc. in a URL bypass urlsplit's host parser (they end
    # up in the path) and can poison structured logs and
    # Scan.failure_reason via the cloner's stderr-tail extraction.
    # See _FORBIDDEN_URL_CODEPOINTS for the full threat description.
    if any(ch in _FORBIDDEN_URL_CODEPOINTS for ch in git_url):
        raise CloneError("clone URL contains a forbidden control character")
    # Percent-encoded null byte — git decodes %XX at request time;
    # we'd rather it never reach git's URL parser.
    if "%00" in git_url.lower():
        raise CloneError("clone URL contains a percent-encoded null byte")

    parts = urlsplit(git_url)
    scheme = parts.scheme.lower()
    host = parts.hostname  # already lowercased by urlsplit, no userinfo

    if scheme in _DENIED_SCHEMES:
        raise CloneError(f"clone scheme {scheme!r} is denied")
    if scheme not in _allowed_schemes():
        raise CloneError(f"clone scheme {scheme!r} is not on the allow-list")
    if host is None or host == "":
        raise CloneError("clone URL has no host")
    # Reject IP-literal hosts outright.  An attacker who can post a
    # Target URL like ``https://169.254.169.254/...`` (AWS metadata),
    # ``https://10.0.0.1/...`` (RFC1918), ``https://127.0.0.1/...``
    # or ``https://[::1]/...`` would otherwise SSRF the worker into
    # the local network.  The host allow-list already rejects these
    # by name, but defence in depth: ANY raw IP literal is wrong
    # for a code-host URL.  Operators extending
    # ``ZYNKSEC_CLONE_ALLOWED_HOSTS`` can only add named hosts,
    # never bare IPs.
    if _host_is_ip_literal(host):
        raise CloneError(f"clone host {host!r} is a raw IP literal (use a hostname)")
    if host.lower() not in _allowed_hosts():
        raise CloneError(f"clone host {host!r} is not on the allow-list")
    # Reject ``userinfo`` outright — credentials should arrive via
    # a configured token store (Phase 3 Sprint 4+), not embedded
    # in a URL the API persists.
    if parts.username is not None or parts.password is not None:
        raise CloneError("clone URL must not include userinfo (username/password)")
    # Path-traversal segments would cause git to walk above the
    # repo root on some servers (e.g. ``../../../etc/passwd``).
    # Modern git+github reject this server-side, but defence in
    # depth says: don't even try.
    if _path_has_traversal(parts.path or ""):
        raise CloneError("clone URL path contains '..' traversal segments")

    return scheme, host.lower()


def _scan_root(scan_id: str) -> Path:
    """Per-scan temp directory under ``/tmp/zynksec-scans/<scan_id>``.

    Single root for every scan — cleanup, monitoring, and incident
    response can target one prefix.  Both the per-scan dir AND its
    ``zynksec-scans/`` parent are forced to ``0o700``: ``mkdir(mode=...)``
    only applies the mode to the LAST directory it creates, so the
    parent would otherwise inherit the system umask (typically 0755 →
    world-readable).  On a multi-process container, a 0755 parent
    lets any other UID list the in-flight scan UUIDs (metadata leak,
    even though the per-scan contents stay protected by the leaf
    0o700).  Forcing the parent on every call closes that gap.

    Idempotent: ``Path.chmod`` on an already-0o700 directory is a
    no-op.  Cheap enough to run on every clone rather than once at
    startup — keeps the security invariant local to the function
    that needs it, no module-import side effects.
    """
    parent = Path(tempfile.gettempdir()) / "zynksec-scans"
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    root = parent / scan_id
    root.mkdir(exist_ok=True, mode=0o700)
    return root


@contextmanager
def clone_shallow(
    git_url: str,
    scan_id: str,
    *,
    timeout_s: int = _DEFAULT_CLONE_TIMEOUT_S,
) -> Iterator[RepoHandle]:
    """Shallow-clone ``git_url`` into a per-scan temp dir.

    Always uses ``--depth 1`` (no commit history beyond the tip),
    ``--single-branch`` (one ref only — saves bandwidth + dodges
    branches that contain accidentally-pushed secrets we don't
    own), ``--no-tags``, and ``--no-recurse-submodules`` (a
    submodule pointing at a hostile repo would defeat every
    allow-list above).  Anything else this sprint needs to scan
    (commit history, branch coverage) is a future-sprint scope.

    Failure surface:
      * ``CloneError`` for allow-list rejections (raised before the
        subprocess call so an attacker doesn't get to time the git
        binary).
      * ``CloneError`` wrapping ``CalledProcessError`` /
        ``TimeoutExpired`` for git-side failures (network, auth,
        ref-not-found).  The wrapping strips stderr down to the
        last line so we don't leak whatever git printed verbatim.
    """
    validate_clone_url(git_url)

    root = _scan_root(scan_id)
    target = root / "repo"
    if target.exists():
        # A retried scan collides on the same scan_id.  Wipe the
        # previous tree and start fresh; gitleaks doesn't do
        # incremental scans on a retry, so the clean slate is
        # the right behaviour.  We also nuke any sibling files at
        # ``root/`` (e.g. a stale ``gitleaks.json`` left by an
        # earlier run on this scan_id) so the post-teardown
        # invariant "nothing under ``root/`` outlives the scan"
        # holds across retries.
        shutil.rmtree(root, ignore_errors=True)
        root = _scan_root(scan_id)

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        git_url,
        str(target),
    ]

    _log.info(
        "repo.clone.start",
        scan_id=scan_id,
        # URL is intentionally NOT logged — see ``_validate_clone_url``.
        host=urlsplit(git_url).hostname,
    )
    try:
        subprocess.run(  # noqa: S603 — list-form, validated URL
            cmd,
            check=True,
            timeout=timeout_s,
            capture_output=True,
            text=True,
            env={
                # Keep git from prompting for credentials — any
                # auth-required clone in Sprint 1 is a misconfig,
                # not something to wait on a TTY for.  ``terminal.prompt``
                # silences the credential helper too.
                "GIT_TERMINAL_PROMPT": "0",
                "PATH": os.environ.get("PATH", ""),
                # ``HOME`` defaults to ``tempfile.gettempdir()`` rather
                # than the bare ``/tmp`` literal — same effective path
                # on POSIX, but keeps Bandit's S108 "/tmp insecure"
                # check from firing on what is actually a deliberate
                # use of the system temp dir.
                "HOME": os.environ.get("HOME", tempfile.gettempdir()),
            },
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise CloneError(f"git clone timed out after {timeout_s}s") from exc
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(root, ignore_errors=True)
        # Last line of stderr is usually git's own "fatal: ..." —
        # informative without including the full transport noise.
        last = (exc.stderr or "").strip().splitlines()
        tail = last[-1] if last else "git clone failed"
        raise CloneError(f"git clone failed: {tail}") from exc

    _log.info("repo.clone.done", scan_id=scan_id, path=str(target))
    handle = RepoHandle(path=target, git_url=git_url)
    try:
        yield handle
    finally:
        # Nuke the entire per-scan root, not just the cloned-repo
        # subdirectory.  Sibling files written under ``root/`` —
        # most notably the ``gitleaks.json`` report the plugin drops
        # at ``root/gitleaks.json`` — contain plaintext ``Match`` /
        # ``Secret`` fields and would otherwise persist forever in
        # ``/tmp/zynksec-scans/<scan_id>/`` after the scan completes.
        # Removing ``root`` is the single source of truth for "this
        # scan is done, drop everything."
        #
        # Best-effort: a teardown crash is logged but swallowed —
        # failing the scan over an rmtree blip would mask an
        # otherwise-successful scan.  Operators can always
        # ``rm -rf /tmp/zynksec-scans`` between runs.
        try:
            shutil.rmtree(root, ignore_errors=True)
        except Exception as exc:  # noqa: BLE001 — best-effort cleanup
            _log.warning("repo.clone.teardown_failed", error=str(exc), path=str(root))
