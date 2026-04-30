"""Semgrep plant — eval() on user-controlled input."""


def handler(user_input: str) -> object:
    # Semgrep's ``eval-detected`` rule (WARNING) flags any direct
    # ``eval()`` call.  In a real codebase this is a remote-code-
    # execution vector when ``user_input`` comes from a request
    # body / query string.
    return eval(user_input)  # noqa: S307 — intentional Semgrep plant
