"""mcp_contracts - an MCP server that can only ever see what the caller can see.

There is no service account, no API key and no superuser credential in this file,
and that absence is the entire point of the demo. When `search_contracts` calls
contracts_api it forwards the *caller's own* access token, unchanged. This server
therefore cannot read a contract that the human on the other end could not read,
even if the model is talked into asking for one.

The only credential here is the HTTP Basic pair used to call the IdP's token
introspection endpoint. It authenticates this server to the IdP; it grants no
access to any contract.

Two checks guard the door, both supplied by the SDK once configured:
  * `required_scopes` - the token must carry `contracts.read`.
  * `validate_token_resource` - the token's RFC 8707 resource (its `aud`) must be
    CONTRACTS_RESOURCE. A token minted for the tickets server is refused here, and
    vice versa. That is beat 2.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Final

import httpx
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp_types import ToolAnnotations
from pydantic import AnyHttpUrl, BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse

SERVICE: Final = "mcp_contracts"
PORT: Final = 8092

ISSUER_URL: Final = os.getenv("ISSUER_URL", "http://idp:8081")
CONTRACTS_RESOURCE: Final = os.getenv("CONTRACTS_RESOURCE", "https://mcp.corp.internal/contracts")
CONTRACTS_API_URL: Final = os.getenv("CONTRACTS_API_URL", "http://contracts-api:8091")
VALIDATE_TOKEN_RESOURCE: Final = os.getenv("VALIDATE_TOKEN_RESOURCE", "true") == "true"

INTROSPECT_CLIENT_ID: Final = os.getenv("INTROSPECT_CLIENT_ID", "mcp-contracts")
INTROSPECT_CLIENT_SECRET: Final = os.getenv("INTROSPECT_CLIENT_SECRET", "demo-not-a-secret")


def audit(event: str, **fields: Any) -> None:
    """One structured line per security-relevant decision, on stdout."""
    print(json.dumps({"ts": time.time(), "service": SERVICE, "event": event, **fields}), flush=True)


class ContractHit(BaseModel):
    contract_id: str
    counterparty: str
    effective_date: str
    snippet: str
    url: str


class SearchResult(BaseModel):
    hits: list[ContractHit]
    total_matched: int = Field(description="Matches this caller is entitled to see.")
    truncated_by_permission: int = Field(
        description="Matches withheld because the caller is not entitled to them. A count only: "
        "no identifiers or text from withheld documents ever reach the model."
    )


class IntrospectionTokenVerifier(TokenVerifier):
    """Verifies bearer tokens against the IdP's RFC 7662 introspection endpoint.

    Introspection rather than local JWT validation because revocation must take
    effect immediately in the demo, and because it keeps every trust decision in
    one place - the IdP - rather than duplicating key handling in each server.
    """

    def __init__(self) -> None:
        self._http = httpx.AsyncClient(timeout=10.0)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            response = await self._http.post(
                f"{ISSUER_URL}/introspect",
                data={"token": token},
                auth=(INTROSPECT_CLIENT_ID, INTROSPECT_CLIENT_SECRET),
            )
            response.raise_for_status()
            claims: dict[str, Any] = response.json()
        except httpx.HTTPError as exc:
            # Fail closed. An unreachable IdP means no access, not open access.
            audit("introspection_failed", error=str(exc))
            return None

        if not claims.get("active"):
            audit("token_rejected", reason="inactive")
            return None

        aud = claims.get("aud")
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("sub") or "unknown"),
            scopes=str(claims.get("scope") or "").split(),
            expires_at=claims.get("exp"),
            # The SDK's bearer middleware compares this against `resource_server_url`
            # when `validate_token_resource` is on. Populating it from `aud` is what
            # makes wrong-audience replay detectable at all.
            resource=aud if isinstance(aud, str) else None,
            subject=str(claims.get("sub")) if claims.get("sub") else None,
            claims={"iss": claims.get("iss"), "act": claims.get("act"), "groups": claims.get("groups") or []},
        )


mcp = MCPServer(
    name="mcp-contracts",
    title="Contract Search",
    version="1.0.0",
    instructions=(
        "Search the corporate contract repository. Results are already trimmed to what the "
        "calling user is entitled to see; `truncated_by_permission` counts matches withheld."
    ),
    token_verifier=IntrospectionTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(ISSUER_URL),
        resource_server_url=AnyHttpUrl(CONTRACTS_RESOURCE),
        required_scopes=["contracts.read"],
        validate_token_resource=VALIDATE_TOKEN_RESOURCE,
    ),
)

_http = httpx.AsyncClient(timeout=15.0)


@mcp.tool(
    name="search_contracts",
    title="Search contracts",
    description="Search corporate contracts by free text, optionally filtered by counterparty.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def search_contracts(query: str, counterparty: str | None = None, limit: int = 10) -> SearchResult:
    """Search contracts as the calling user, never as this service."""
    token = get_access_token()
    if token is None:  # Unreachable behind RequireAuthMiddleware; a belt-and-braces guard.
        raise RuntimeError("no authenticated caller in context")

    # A model may propose any integer; clamp rather than let the backend 422 and
    # turn a harmless over-request into a tool error the model has to reason about.
    limit = max(1, min(limit, 50))

    # The caller's own token goes downstream verbatim. Nothing is substituted or
    # elevated here - contracts_api will independently introspect it and ACL-trim.
    response = await _http.post(
        f"{CONTRACTS_API_URL}/api/search",
        json={"q": query, "counterparty": counterparty, "limit": limit},
        headers={
            "Authorization": f"Bearer {token.token}",
            "X-On-Behalf-Of": token.subject or "",
        },
    )
    response.raise_for_status()
    payload = response.json()

    result = SearchResult(
        hits=[ContractHit(**hit) for hit in payload["hits"]],
        total_matched=payload["total"],
        truncated_by_permission=payload["denied_count"],
    )
    audit(
        "search_contracts",
        sub=token.subject,
        aud=token.resource,
        query=query,
        returned=len(result.hits),
        truncated_by_permission=result.truncated_by_permission,
        contract_ids=[h.contract_id for h in result.hits],
    )
    return result


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> JSONResponse:
    """Deliberately unauthenticated: container orchestration must not need a token."""
    return JSONResponse({"status": "ok", "service": SERVICE, "validate_token_resource": VALIDATE_TOKEN_RESOURCE})


if __name__ == "__main__":
    audit("startup", port=PORT, resource=CONTRACTS_RESOURCE, validate_token_resource=VALIDATE_TOKEN_RESOURCE)
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=PORT,
        streamable_http_path="/mcp",
        stateless_http=True,
    )
