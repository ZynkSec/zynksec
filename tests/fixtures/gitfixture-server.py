"""Tiny smart-HTTP git server for the Phase 3 Sprint 1 fixture.

The cloner uses ``git clone --depth 1`` (shallow), which the dumb
HTTP transport doesn't support — git itself errors out with
``fatal: dumb http transport does not support shallow capabilities``.
Smart HTTP works with shallow because the server-side
``git-http-backend`` advertises the ``shallow`` capability via
service discovery.

This module implements smart HTTP by piping each request directly
into ``git-http-backend`` as a CGI process — no ``CGIHTTPRequestHandler``
indirection (which fights us over PATH_INFO when the script path
isn't part of the URL).  The flow is:

  1. Inbound HTTP request arrives at ``/<repo>.git/<path>``.
  2. We spawn ``git-http-backend`` with PATH_INFO=``/<repo>.git/<path>``,
     GIT_PROJECT_ROOT=``/srv``, GIT_HTTP_EXPORT_ALL=1.
  3. Pipe the request body into the backend's stdin.
  4. Parse the backend's response: leading headers (``Status:``,
     ``Content-Type:``, ...) followed by a blank line, then body.
  5. Stream that back to the HTTP client.

This is test-only code — the production flow clones from
github / gitlab / bitbucket directly.  Kept under
``tests/fixtures/`` so its purely-test nature is unambiguous.
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404 — fixed-arg list-form, test-only
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Debian's git package installs the backend at ``/usr/lib/git-core``;
# RHEL-family distros use ``/usr/libexec/git-core``.  We're on
# debian:bookworm-slim per the Dockerfile, so the lib path is the
# right hardcode — switching distros would need this updated.
_GIT_HTTP_BACKEND = "/usr/lib/git-core/git-http-backend"
_PROJECT_ROOT = "/srv"


class _GitSmartHTTPHandler(BaseHTTPRequestHandler):
    """Pipe every request into ``git-http-backend`` as CGI.

    Both GET and POST do the same thing — the backend reads the
    request method from the ``REQUEST_METHOD`` env var and decides
    internally whether to read stdin (POST) or not (GET).
    """

    def _serve(self) -> None:
        path, _, query = self.path.partition("?")
        body_len = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(body_len) if body_len > 0 else b""

        env = {
            "GIT_PROJECT_ROOT": _PROJECT_ROOT,
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(body_len),
            "REMOTE_ADDR": self.client_address[0],
            "PATH": os.environ.get("PATH", ""),
        }

        proc = subprocess.run(  # noqa: S603 — list-form, fixed binary
            [_GIT_HTTP_BACKEND],
            input=body,
            capture_output=True,
            env=env,
            check=False,
        )

        # CGI response = headers + blank line + body.  Parse out
        # ``Status:`` if present (it's optional; default 200).
        head, sep, payload = proc.stdout.partition(b"\r\n\r\n")
        if not sep:
            head, sep, payload = proc.stdout.partition(b"\n\n")

        status_code = 200
        status_msg = "OK"
        out_headers: list[tuple[str, str]] = []
        for raw_line in head.splitlines():
            line = raw_line.decode("iso-8859-1", errors="replace")
            if not line:
                continue
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key.lower() == "status":
                # ``Status: 200 OK`` — split into code + message.
                code_part, _, msg_part = val.partition(" ")
                try:
                    status_code = int(code_part)
                except ValueError:
                    status_code = 200
                status_msg = msg_part or status_msg
            else:
                out_headers.append((key, val))

        self.send_response(status_code, status_msg)
        for k, v in out_headers:
            self.send_header(k, v)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

        if proc.returncode != 0 and proc.stderr:
            # Helpful for debugging — gitfixture is test-only.
            self.log_message(
                "git-http-backend exit=%d stderr=%s",
                proc.returncode,
                proc.stderr.decode("utf-8", errors="replace").strip(),
            )

    # ``do_<METHOD>`` is BaseHTTPRequestHandler's dispatch contract;
    # the names HAVE to be mixed-case to match what the framework
    # looks up — ruff's N815 rule doesn't apply.
    do_GET = _serve  # type: ignore[assignment]  # noqa: N815
    do_POST = _serve  # type: ignore[assignment]  # noqa: N815
    do_HEAD = _serve  # type: ignore[assignment]  # noqa: N815


def _ensure_backend_exists() -> None:
    """Fail fast at startup if the git-http-backend binary is missing."""
    if not os.path.isfile(_GIT_HTTP_BACKEND):
        raise SystemExit(f"git-http-backend not found at {_GIT_HTTP_BACKEND!r}")


def main() -> None:
    _ensure_backend_exists()
    # 0.0.0.0 is intentional — the server runs inside a test-only
    # gitfixture container that only exposes port 80 to the
    # ``zynksec-core + zynksec-scan`` Docker networks.  Binding to a
    # specific interface inside the container would mean guessing the
    # in-container IP at startup time.  S104 doesn't apply.
    server = ThreadingHTTPServer(("0.0.0.0", 80), _GitSmartHTTPHandler)  # noqa: S104
    print(f"gitfixture serving smart-HTTP from {_PROJECT_ROOT} on :80", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
