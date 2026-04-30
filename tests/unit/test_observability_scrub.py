"""Unit tests for the Sentry ``_before_send`` scrubber.

Pre-merge security review BLOCKER #3 regression guard.

Sentry's default ``include_local_variables=True`` ships every frame's
local variables along with exception events.  In the worker, an
exception fired during the gitleaks find-persistence loop would
upload ``GitleaksFinding(raw_secret=...)`` plaintext to the
configured DSN.  Two-layer fix:

1. ``sentry_sdk.init(include_local_variables=False)`` — kills the
   surface at the source.  Tested elsewhere (the kwarg's presence is
   asserted by reading the source; a true integration test would
   require firing a real Sentry capture, which needs a live DSN).
2. ``_before_send`` walks the event payload and redacts any frame
   ``var`` whose key matches a secret-naming fragment (``secret``,
   ``password``, ``token``, etc.) — defence in depth so a future
   config flip that re-enables locals doesn't silently re-open the
   leak path.

This test file covers (2): synthesised event payloads with frame
``vars`` dicts go through ``_before_send`` and the assertions check
the post-scrub state.

The test runs against BOTH copies of ``observability.py`` (worker +
api) since they're hand-maintained mirrors and the user spec
explicitly calls for the scrub on both — a regression in just one
would still leak.
"""

from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture(params=["api", "worker"], ids=["api", "worker"])
def before_send(request: pytest.FixtureRequest):  # type: ignore[no-untyped-def]
    """Yield each app's ``_before_send`` so the same test exercises both."""
    if request.param == "api":
        from zynksec_api.observability import _before_send  # noqa: PLC0415
    else:
        from zynksec_worker.observability import _before_send  # noqa: PLC0415
    return _before_send


def _make_exception_event(frame_vars: dict[str, Any]) -> dict[str, Any]:
    """Build an event payload shaped like what sentry-sdk emits."""
    return {
        "exception": {
            "values": [
                {
                    "type": "RuntimeError",
                    "value": "synthetic for test",
                    "stacktrace": {
                        "frames": [
                            {
                                "filename": "execute_scan.py",
                                "function": "execute_scan",
                                "lineno": 327,
                                "vars": frame_vars,
                            }
                        ]
                    },
                }
            ]
        }
    }


def _frame_vars_after(before_send, frame_vars: dict[str, Any]) -> dict[str, Any]:
    """Pass an event through before_send and pull the scrubbed vars back."""
    event = _make_exception_event(frame_vars)
    out = before_send(event, hint={})
    assert out is not None
    return out["exception"]["values"][0]["stacktrace"]["frames"][0]["vars"]


@pytest.mark.parametrize(
    "secret_key",
    [
        "raw_secret",
        "secret",
        "Secret",  # case-insensitive
        "password",
        "PASSWORD",
        "passwd",
        "user_token",
        "token",
        "API_KEY",
        "api_key",
        "apikey",
        "match",  # gitleaks JSON Match field
        "Match",
        "MyApiKey",  # substring match
        "auth_token",
    ],
)
def test_before_send_scrubs_secret_named_keys(before_send, secret_key: str) -> None:
    """Any frame var whose key contains a secret fragment is replaced."""
    after = _frame_vars_after(
        before_send,
        {
            secret_key: "AKIAREALSECRETVALUEHERE",
            "boring_var": "definitely fine",
        },
    )
    assert (
        after[secret_key] == "[Filtered]"
    ), f"key {secret_key!r} should be scrubbed but was {after[secret_key]!r}"
    assert (
        after["boring_var"] == "definitely fine"
    ), f"non-secret key was incorrectly scrubbed: {after['boring_var']!r}"


def test_before_send_leaves_non_secret_vars_alone(before_send) -> None:
    """Variables with safe names must pass through unchanged."""
    after = _frame_vars_after(
        before_send,
        {
            "scan_id": "abc-123",
            "count": 42,
            "url_host": "github.com",
        },
    )
    assert after == {
        "scan_id": "abc-123",
        "count": 42,
        "url_host": "github.com",
    }


def test_before_send_handles_event_without_exception(before_send) -> None:
    """Non-exception events (info-level breadcrumbs) must not crash."""
    event = {"message": "hello", "level": "info"}
    out = before_send(event, hint={})
    assert out == {"message": "hello", "level": "info"}


def test_before_send_handles_exception_without_frames(before_send) -> None:
    """A skinny event with no stacktrace must pass through cleanly."""
    event = {"exception": {"values": [{"type": "RuntimeError", "value": "x"}]}}
    out = before_send(event, hint={})
    assert out is not None
    # No crash, payload preserved.
    assert out["exception"]["values"][0]["type"] == "RuntimeError"


def test_before_send_scrubs_threads_section_too(before_send) -> None:
    """Sentry's threading integration emits frames under ``threads.values``;
    the scrubber must walk that path too.
    """
    event = {
        "threads": {
            "values": [
                {
                    "stacktrace": {
                        "frames": [
                            {
                                "filename": "x.py",
                                "function": "f",
                                "vars": {
                                    "secret_token": "DROP_THIS",
                                    "ok": "keep",
                                },
                            }
                        ]
                    }
                }
            ]
        }
    }
    out = before_send(event, hint={})
    assert out is not None
    frame = out["threads"]["values"][0]["stacktrace"]["frames"][0]
    assert frame["vars"]["secret_token"] == "[Filtered]"  # noqa: S105 — assertion
    assert frame["vars"]["ok"] == "keep"


def test_before_send_includes_local_variables_disabled_in_init() -> None:
    """Belt-and-braces: read both observability sources and assert
    ``include_local_variables=False`` is present in the init call.

    Pure source-text inspection rather than instantiating a real
    Sentry SDK (which would need a live DSN).  A regression that
    drops the kwarg silently re-opens the entire leak path.
    """
    from pathlib import Path  # noqa: PLC0415

    repo_root = Path(__file__).resolve().parents[2]
    for relpath in (
        "apps/api/src/zynksec_api/observability.py",
        "apps/worker/src/zynksec_worker/observability.py",
    ):
        source = (repo_root / relpath).read_text()
        assert "include_local_variables=False" in source, (
            f"{relpath} is missing include_local_variables=False in "
            "sentry_sdk.init — the locals-leak surface is open"
        )
