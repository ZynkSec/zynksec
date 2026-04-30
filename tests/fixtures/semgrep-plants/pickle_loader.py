"""Semgrep plant — pickle.loads on untrusted input."""

import pickle


def load_user_data(blob: bytes) -> object:
    # Semgrep's ``avoid-pickle`` rule (WARNING) flags any
    # ``pickle.loads()`` on data from outside the trust boundary
    # — a malicious pickle blob can execute arbitrary code at
    # deserialisation time via ``__reduce__``.
    return pickle.loads(blob)  # noqa: S301 — intentional Semgrep plant
