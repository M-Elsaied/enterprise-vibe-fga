"""Friendly OpenFGA reachability check for the launchers.

Turns the raw urllib3/requests SSL/connection tracebacks (the classic
"https:// against a plain-HTTP OpenFGA -> WRONG_VERSION_NUMBER", or a stack that
was never started) into a single actionable line, printed BEFORE the server
starts, so a first-timer sees guidance instead of a wall of traceback.

Call it at the top of a launcher's __main__, before uvicorn.run / serve_forever.
"""

import sys

import requests


def assert_openfga_reachable(url: str, timeout: float = 5.0) -> None:
    """Probe <url>/healthz. On failure print a targeted hint and exit(1).

    requests raises SSLError (a subclass of ConnectionError) for the scheme
    mismatch, so it is caught first; a plain ConnectionError means nothing is
    listening.
    """
    probe = f"{url.rstrip('/')}/healthz"
    try:
        requests.get(probe, timeout=timeout)
        return
    except requests.exceptions.SSLError:
        http_url = url.replace("https://", "http://", 1)
        _die(url, [
            "TLS handshake failed - you are using https:// but OpenFGA speaks plain HTTP.",
            f"Fix: set FGA_API_URL to http://  ->  {http_url}",
        ])
    except requests.exceptions.ConnectionError:
        _die(url, [
            "Nothing is listening there. Is OpenFGA running, and does FGA_API_URL point at it?",
            "Local dev: start the stack first in a separate window -",
            "    powershell -ExecutionPolicy Bypass -File authz\\run_e2e.ps1 -KeepUp   (Windows)",
            "    ./authz/run_e2e.sh --keep-up                                          (macOS/Linux)",
            "Default local URL is http://127.0.0.1:18080.",
        ])
    except requests.exceptions.RequestException as err:
        _die(url, [f"Unexpected error reaching OpenFGA: {err}"])


def _die(url: str, lines) -> None:
    print(f"\nCannot reach OpenFGA at {url}", file=sys.stderr)
    for line in lines:
        print(f"  -> {line}", file=sys.stderr)
    print("", file=sys.stderr)
    sys.exit(1)
