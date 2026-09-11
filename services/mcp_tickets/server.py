"""mcp_tickets - the outbound side of the demo, and the thing that says no.

Two independent controls live here, and they fail in different ways on purpose:

  * Audience binding (beat 2). This server's resource identifier is
    TICKETS_RESOURCE. With `validate_token_resource` on, a token minted for the
    contracts server is refused at the door with HTTP 401 - the tool is never
    reached. Flip VALIDATE_TOKEN_RESOURCE to "false" and the same replayed token
    is accepted, which is exactly the failure mode the flag exists to prevent.

  * Recipient allowlist (beat 3). A refused recipient is *not* an exception. It is
    a successful tool call that returns `SendResult(sent=False, reason=...)`, so the
    model is told "no" in a way it can read, and the audit log records that the
    attempt was made. A crash would hide the attempt; this does not.
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

SERVICE: Final = "mcp_tickets"
PORT: Final = 8093

ISSUER_URL: Final = os.getenv("ISSUER_URL", "http://idp:8081")
TICKETS_RESOURCE: Final = os.getenv("TICKETS_RESOURCE", "https://mcp.corp.internal/tickets")
VALIDATE_TOKEN_RESOURCE: Final = os.getenv("VALIDATE_TOKEN_RESOURCE", "true") == "true"

# Comma-separated; every recipient domain outside this set is refused.
EMAIL_ALLOWED_DOMAINS: Final = tuple(
    d.strip().lower() for d in os.getenv("EMAIL_ALLOWED_DOMAINS", "corp.internal").split(",") if d.strip()
)

INTROSPECT_CLIENT_ID: Final = os.getenv("INTROSPECT_CLIENT_ID", "mcp-tickets")
INTROSPECT_CLIENT_SECRET: Final = os.getenv("INTROSPECT_CLIENT_SECRET", "demo-not-a-secret")


def audit(event: str, **fields: Any) -> None:
    """One structured line per security-relevant decision, on stdout."""
    print(json.dumps({"ts": time.time(), "service": SERVICE, "event": event, **fields}), flush=True)


class SendResult(BaseModel):
    sent: bool
    reason: str = Field(description="Why the message was or was not sent. Shown to the model verbatim.")


class IntrospectionTokenVerifier(TokenVerifier):
    """Verifies bearer tokens against the IdP's RFC 7662 introspection endpoint.

    `AccessToken.resource` is populated from the token's `aud` claim; without it the
    SDK has nothing to compare against `resource_server_url` and audience binding
    would silently do nothing.
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
            # Fail closed: an unreachable IdP means nothing gets sent.
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
            resource=aud if isinstance(aud, str) else None,
            subject=str(claims.get("sub")) if claims.get("sub") else None,
            claims={"iss": claims.get("iss"), "act": claims.get("act"), "groups": claims.get("groups") or []},
        )


mcp = MCPServer(
    name="mcp-tickets",
    title="Ticketing and Notifications",
    version="1.0.0",
    instructions=(
        "Send internal notification email. Recipients outside the corporate mail domains are "
        "refused; the refusal is returned as a result, not an error."
    ),
    token_verifier=IntrospectionTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(ISSUER_URL),
        resource_server_url=AnyHttpUrl(TICKETS_RESOURCE),
        required_scopes=["tickets.write"],
        validate_token_resource=VALIDATE_TOKEN_RESOURCE,
    ),
)


def recipient_domain(address: str) -> str | None:
    """The domain of a single RFC 5322-ish address, or None if it is not one."""
    local, separator, domain = address.strip().rpartition("@")
    if not separator or not local or not domain:
        return None
    return domain.lower()


@mcp.tool(
    name="send_email",
    title="Send internal email",
    description="Send an email to an internal recipient. External recipients are refused.",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False),
)
async def send_email(to: str, subject: str, body: str) -> SendResult:
    """Send mail on behalf of the calling user, if the recipient is internal."""
    token = get_access_token()
    if token is None:  # Unreachable behind RequireAuthMiddleware; a belt-and-braces guard.
        raise RuntimeError("no authenticated caller in context")

    domain = recipient_domain(to)
    allowed = domain is not None and domain in EMAIL_ALLOWED_DOMAINS

    if not allowed:
        reason = (
            f"Refused: {to!r} is not a valid address."
            if domain is None
            else f"Refused: recipient domain {domain!r} is not in the allowlist {list(EMAIL_ALLOWED_DOMAINS)}."
        )
    else:
        # Demo deployment: no real MTA. The send is simulated, the refusal is not.
        reason = f"Sent to {to} via the internal relay."

    # Logged whether allowed or refused - a blocked exfiltration attempt is the
    # single most interesting line this service can produce.
    audit(
        "send_email",
        sub=token.subject,
        aud=token.resource,
        to=to,
        recipient_domain=domain,
        subject=subject,
        body_chars=len(body),
        sent=allowed,
        reason=reason,
    )
    return SendResult(sent=allowed, reason=reason)


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> JSONResponse:
    """Deliberately unauthenticated: container orchestration must not need a token."""
    return JSONResponse(
        {
            "status": "ok",
            "service": SERVICE,
            "validate_token_resource": VALIDATE_TOKEN_RESOURCE,
            "allowed_domains": list(EMAIL_ALLOWED_DOMAINS),
        }
    )


if __name__ == "__main__":
    audit(
        "startup",
        port=PORT,
        resource=TICKETS_RESOURCE,
        validate_token_resource=VALIDATE_TOKEN_RESOURCE,
        allowed_domains=list(EMAIL_ALLOWED_DOMAINS),
    )
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=PORT,
        streamable_http_path="/mcp",
        stateless_http=True,
    )
