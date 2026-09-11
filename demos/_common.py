"""Terminal formatting and HTTP helpers shared by the three demo scripts.

The demos are meant to be watched, and one of them gets recorded as a GIF, so
output width is fixed at 92 columns and every column is padded rather than
tab-separated. Color is used for exactly three things: green for allowed, red
for refused, dim for detail you are not meant to read closely. If stdout is not
a TTY, or NO_COLOR is set, every escape sequence disappears and the transcript
stays readable in a log file.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from typing import Any, Iterable

import httpx

WIDTH = 92

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")
IDP_URL = os.environ.get("IDP_URL", "http://localhost:8081")

# Identifiers, not addresses. They must match docker-compose.yml exactly.
GATEWAY_RESOURCE = os.environ.get("GATEWAY_RESOURCE", "https://gateway.corp.internal")
CONTRACTS_RESOURCE = os.environ.get("CONTRACTS_RESOURCE", "https://mcp.corp.internal/contracts")
TICKETS_RESOURCE = os.environ.get("TICKETS_RESOURCE", "https://mcp.corp.internal/tickets")

# DEMO_SPEED=0 removes every pause, which is what CI and `make test` want.
SPEED = float(os.environ.get("DEMO_SPEED", "1"))

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

_CODES = {
    "green": "\033[32m",
    "red": "\033[31m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}


def paint(text: str, style: str) -> str:
    if not _COLOR:
        return text
    return f"{_CODES[style]}{text}\033[0m"


def green(t: str) -> str:
    return paint(t, "green")


def red(t: str) -> str:
    return paint(t, "red")


def dim(t: str) -> str:
    return paint(t, "dim")


def bold(t: str) -> str:
    return paint(t, "bold")


def pause(units: float = 1.0) -> None:
    if SPEED > 0:
        time.sleep(units * SPEED)


def title(text: str, subtitle: str = "") -> None:
    print()
    print(bold("=" * WIDTH))
    print(bold(f"  {text}"))
    if subtitle:
        print(dim(f"  {subtitle}"))
    print(bold("=" * WIDTH))
    pause(0.6)


def section(label: str) -> None:
    print()
    print(bold(f"-- {label} " + "-" * max(0, WIDTH - len(label) - 4)))
    print()
    pause(0.4)


def say(text: str = "") -> None:
    """Narration. One short line at a time so the GIF stays legible."""
    print(text)
    pause(0.25)


def kv(key: str, value: Any, key_width: int = 22) -> None:
    print(f"  {key:<{key_width}} {value}")


def rule() -> None:
    print(dim("." * WIDTH))


# ---------------------------------------------------------------------------
# Token helpers. Deliberately hand-rolled so the demos need only httpx, and so
# you can see that reading a JWT payload requires no key and proves nothing.
# ---------------------------------------------------------------------------


def wrap(text: str, width: int, indent: str = "") -> list[str]:
    """Greedy wrap to `width`, prefixing continuation lines with `indent`."""
    lines: list[str] = []
    current = ""
    for word in str(text).split():
        candidate = (current + " " + word).strip()
        if len(candidate) + len(indent) > width and current:
            lines.append(indent + current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(indent + current)
    return lines or [indent]


def jwt_claims(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def login(username: str, password: str = "demo") -> str:
    r = httpx.post(f"{IDP_URL}/login", json={"username": username, "password": password}, timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]


def exchange(subject_token: str, resource: str, scope: str) -> httpx.Response:
    """RFC 8693 token exchange. Returns the raw response so a demo can show a refusal."""
    return httpx.post(
        f"{IDP_URL}/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "resource": resource,
            "scope": scope,
        },
        timeout=15,
    )


# ---------------------------------------------------------------------------
# Gateway helpers
# ---------------------------------------------------------------------------


def ask(user: str, question: str, virtual_key: str) -> dict[str, Any]:
    r = httpx.post(
        f"{GATEWAY_URL}/v1/ask",
        json={"user": user, "question": question},
        headers={"X-Virtual-Key": virtual_key},
        timeout=180,
    )
    r.raise_for_status()
    return r.json()


def ask_with_audit(user: str, question: str, virtual_key: str) -> dict[str, Any]:
    """Ask, and capture the audit records that ask produced.

    The gateway pins the shape of /v1/ask but not the interior of a tool call,
    so the demos read the response and the matching audit slice together and let
    the helpers below find the fields wherever they ended up.
    """
    before = len(audit())
    payload = ask(user, question, virtual_key)
    records = audit()[before:]
    return {"response": payload, "records": records}


def replay(
    token: str,
    target: str,
    tool: str,
    args: dict[str, Any],
    virtual_key: str = "vk-legal-demo",
) -> dict[str, Any]:
    """Call an MCP server with a caller-supplied token, skipping the exchange.

    The virtual key is still required: /v1/replay is a misuse endpoint for the
    demo, not an open relay. Without it the gateway rejects the call at the door
    and beat 2 would report a refusal that has nothing to do with the audience
    check it is trying to demonstrate.
    """
    r = httpx.post(
        f"{GATEWAY_URL}/v1/replay",
        json={"token": token, "target": target, "tool": tool, "args": args},
        headers={"X-Virtual-Key": virtual_key},
        timeout=60,
    )
    return r.json()


def audit(limit: int | None = None) -> list[dict[str, Any]]:
    r = httpx.get(f"{GATEWAY_URL}/audit", timeout=15)
    r.raise_for_status()
    records = r.json()["records"]
    return records[-limit:] if limit else records


# ---------------------------------------------------------------------------
# Response shape helpers. The gateway pins the top level of /v1/ask but not the
# interior of a tool call, so the demos read defensively rather than assuming
# one spelling.
# ---------------------------------------------------------------------------


def walk(obj: Any) -> Iterable[dict[str, Any]]:
    """Yield every dict nested anywhere inside obj, outermost first."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def hits(payload: Any) -> list[dict[str, Any]]:
    """Every contract hit anywhere in a gateway response, de-duplicated by id."""
    found: dict[str, dict[str, Any]] = {}
    for d in walk(payload):
        cid = d.get("contract_id")
        if isinstance(cid, str) and cid not in found:
            found[cid] = d
    return list(found.values())


def denied_count(payload: Any) -> int:
    """Withheld-match count under either of its two spellings."""
    total = 0
    for d in walk(payload):
        for key in ("denied_count", "truncated_by_permission"):
            v = d.get(key)
            if isinstance(v, int):
                total = max(total, v)
    return total


def tool_calls(payload: Any) -> list[tuple[str, dict[str, Any]]]:
    """Normalize tool calls to (name, args) across the plausible spellings."""
    out: list[tuple[str, dict[str, Any]]] = []
    for entry in payload.get("tool_calls") or []:
        out.append(normalize_call(entry))
    return out


def normalize_call(entry: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(entry, dict):
        return (str(entry), {})
    fn = entry.get("function") if isinstance(entry.get("function"), dict) else {}
    name = entry.get("tool") or entry.get("name") or entry.get("tool_name") or fn.get("name") or "?"
    args = (
        entry.get("args")
        or entry.get("arguments")
        or entry.get("input")
        or entry.get("params")
        or fn.get("arguments")
        or {}
    )
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {"raw": args}
    return (str(name), args if isinstance(args, dict) else {"value": args})


def reason_of(entry: Any) -> str:
    if not isinstance(entry, dict):
        return str(entry)
    for key in ("reason", "detail", "error", "message", "why", "decision"):
        v = entry.get(key)
        if isinstance(v, str) and v:
            return v
    return json.dumps(entry, default=str)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def require_stack() -> None:
    """Fail with an instruction, not a traceback, when the stack is not up."""
    for url in (f"{IDP_URL}/healthz", f"{GATEWAY_URL}/healthz"):
        try:
            httpx.get(url, timeout=3).raise_for_status()
        except Exception:
            print(red(f"Cannot reach {url}"))
            print()
            print("Start the stack first:")
            print(bold("    docker compose up -d --wait"))
            sys.exit(1)


def wait_for(url: str, timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(url, timeout=3).raise_for_status()
            return True
        except Exception:
            time.sleep(1.5)
    return False
