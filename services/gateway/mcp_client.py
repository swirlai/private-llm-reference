"""MCP invocation.

## How the bearer token is attached (read the SDK, don't guess)

`mcp==2.2.0` has no `FastMCP` and no `session.initialize()`. `mcp.Client` accepts a URL
string, but `Client.__post_init__` turns a `str` into `streamable_http_client(url)` with no
way to pass HTTP options through - so a URL string alone cannot carry a bearer token:

    # mcp/client/client.py
    elif isinstance(srv, str):
        self._connect = _connect_transport(streamable_http_client(srv))

`Client.server` is also typed to accept a `Transport`, and `Transport` is just
"async context manager yielding (read_stream, write_stream)" (`mcp/client/_transport.py`).
`streamable_http_client` is an `@asynccontextmanager` that takes a pre-configured
`httpx2.AsyncClient`:

    # mcp/client/streamable_http.py
    @asynccontextmanager
    async def streamable_http_client(url, *, http_client: httpx2.AsyncClient | None = None, ...)
        # "To configure headers, authentication, or other HTTP settings, create an
        #  httpx2.AsyncClient and pass it here."

So the clean path is: build the transport ourselves with an `httpx2.AsyncClient` whose
default headers carry `Authorization: Bearer <delegated token>`, and hand that transport to
`Client`. No raw JSON-RPC needed for the normal path, and each call gets its own client so
one tool's token can never leak into another tool's request.

Note the SDK's HTTP transport is built on `httpx2`; the rest of the gateway uses `httpx`.
That split is the SDK's, not ours.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import CallToolResult

_TIMEOUT = httpx2.Timeout(30.0, read=120.0)

ResponseHook = Callable[[httpx2.Response], Awaitable[None]]


class ToolInvocationError(Exception):
    """The MCP call did not produce a usable result (transport, auth, or tool error)."""


def _bearer_http_client(token: str, on_response: ResponseHook | None = None) -> httpx2.AsyncClient:
    hooks = {"response": [on_response]} if on_response is not None else None
    return httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=_TIMEOUT,
        event_hooks=hooks,
    )


@asynccontextmanager
async def _connected(url: str, token: str, on_response: ResponseHook | None = None) -> AsyncIterator[Client]:
    async with _bearer_http_client(token, on_response) as http_client:
        transport = streamable_http_client(url, http_client=http_client)
        async with Client(transport) as client:
            yield client


def _result_payload(result: CallToolResult) -> dict[str, Any]:
    """Prefer the structured result; fall back to concatenated text content."""
    if result.structured_content is not None:
        return dict(result.structured_content)
    text = "\n".join(getattr(block, "text", "") for block in (result.content or []))
    return {"text": text}


async def call_tool(url: str, token: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Invoke one MCP tool with a token audienced to that server alone.

    The returned dict is UNTRUSTED. It is retrieved content that will be fed back to the
    model, and the whole premise of the injection beat is that an attacker controls it.
    Nothing here treats it as instructions; the caller re-runs policy on whatever the model
    does next.
    """
    try:
        async with _connected(url, token) as client:
            result = await client.call_tool(tool, args)
    except Exception as exc:  # noqa: BLE001
        # A downstream refusal (wrong audience, missing scope, expired token) must become a
        # recorded, model-visible "no", not a 500 out of the gateway.
        raise ToolInvocationError(f"{tool} against {url} failed: {_flatten(exc)}") from exc

    # `call_tool` is typed to return CallToolResult; an InputRequiredResult would mean the
    # server asked for elicitation, which this demo does not use. Fail loudly if it happens.
    if not isinstance(result, CallToolResult):  # pragma: no cover - defensive
        raise ToolInvocationError(
            f"{tool} returned {type(result).__name__}; this gateway does not support elicitation"
        )
    if result.is_error:
        raise ToolInvocationError(f"{tool} returned an error: {_result_payload(result)}")
    return _result_payload(result)


async def replay_raw(url: str, token: str, tool: str, args: dict[str, Any]) -> tuple[bool, int, str]:
    """Call an MCP server with a caller-supplied token, bypassing the token exchange.

    This is the deliberate-misuse endpoint. It exists so the demo can take a token minted
    for the contracts server, aim it at the tickets server, and show it being refused -
    and then show the same replay succeeding once `VALIDATE_TOKEN_RESOURCE=false`.

    We keep the SDK on this path (so a *valid* token really does execute the tool) but hang
    an httpx response hook off the transport, because the interesting part of a refusal is
    the raw HTTP status and `WWW-Authenticate` challenge the resource server chose - which
    the SDK, correctly, abstracts away behind a transport error.
    """
    refusals: list[tuple[int, str]] = []
    statuses: list[int] = []

    async def _capture(response: httpx2.Response) -> None:
        statuses.append(response.status_code)
        if response.status_code >= 400:
            refusals.append((response.status_code, response.headers.get("www-authenticate", "")))

    try:
        async with _connected(url, token, on_response=_capture) as client:
            result = await client.call_tool(tool, args)
    except Exception as exc:  # noqa: BLE001 - here, the failure IS the result
        if refusals:
            status, challenge = refusals[-1]
            detail = f"resource server refused the token with HTTP {status}"
            return False, status, f"{detail}; WWW-Authenticate: {challenge}" if challenge else detail
        return False, statuses[-1] if statuses else 0, _flatten(exc)

    if isinstance(result, CallToolResult) and result.is_error:
        return False, statuses[-1] if statuses else 200, f"tool reported an error: {_result_payload(result)}"
    return True, statuses[-1] if statuses else 200, f"accepted: {_result_payload(result)}"


def _flatten(exc: BaseException) -> str:
    """anyio task groups wrap the real cause; report the cause, not the wrapper."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return f"{type(exc).__name__}: {exc}"
