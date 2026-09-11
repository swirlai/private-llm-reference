"""Demo OAuth 2.1-style authorization server for the private-LLM reference stack.

What this exists to prove
-------------------------
The gateway never hands a downstream tool the user's own token. It performs an
RFC 8693 token exchange and receives a NEW token whose audience is exactly one
resource server. That is what makes the "wrong-audience token" beat of the demo
possible: a token minted for the contracts MCP server simply is not valid at the
tickets MCP server, because this service refuses to mint anything broader.

The two security-relevant refusals live in `token_exchange` below and are
deliberately written so a reviewer skimming the file can find them:

  1. the subject token must be addressed to the gateway (`aud == GATEWAY_RESOURCE`);
  2. the requested `resource` must be one this deployment knows about.

NOT production code. Passwords are plaintext in a dict, any client credentials
are accepted at the introspection endpoint, and the signing key is regenerated
every time the process starts. Those shortcuts are called out at each site.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Final

import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

# The service runs both from the repo root (`make dev`) and from /app in its
# container, where `common/` sits next to `services/`. Resolving the repo root
# relative to this file makes `common.jwt_tools` importable in both layouts.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from common.jwt_tools import decode_unverified_claims, encode, verify  # noqa: E402

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# These are IDENTIFIERS, not addresses. Nothing here is ever fetched.
ISSUER: Final[str] = os.getenv("ISSUER_URL", "http://idp:8081")
GATEWAY_RESOURCE: Final[str] = os.getenv("GATEWAY_RESOURCE", "https://gateway.corp.internal")
CONTRACTS_RESOURCE: Final[str] = os.getenv("CONTRACTS_RESOURCE", "https://mcp.corp.internal/contracts")
TICKETS_RESOURCE: Final[str] = os.getenv("TICKETS_RESOURCE", "https://mcp.corp.internal/tickets")

# An allowlist, not a suggestion. An exchange for anything else is refused, so a
# compromised gateway cannot mint a token for a resource server nobody declared.
KNOWN_RESOURCES: Final[frozenset[str]] = frozenset(
    {GATEWAY_RESOURCE, CONTRACTS_RESOURCE, TICKETS_RESOURCE}
)

TOKEN_EXCHANGE_GRANT: Final[str] = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE: Final[str] = "urn:ietf:params:oauth:token-type:access_token"

# A login token is a session credential, so it lives for an hour. An exchanged
# token is handed to a downstream tool for one call, so it lives for minutes:
# short lifetimes are the cheap half of "least privilege", the audience pin is
# the other half.
LOGIN_TTL_SECONDS: Final[int] = 3600
EXCHANGE_TTL_SECONDS: Final[int] = 300


class User(BaseModel):
    """A seeded demo user. `scopes` is the full grant; exchange can only narrow it."""

    password: str
    groups: list[str]
    scopes: list[str]


# DEMO ONLY: plaintext passwords, no user store, no lockout. Alice and Bob have
# identical scopes on purpose -- the confused-deputy beat turns on `groups`, not
# on scopes, so the two users must be indistinguishable at the OAuth layer.
USERS: Final[dict[str, User]] = {
    "alice": User(password="demo", groups=["legal", "all"], scopes=["contracts.read", "tickets.write"]),
    "bob": User(password="demo", groups=["sales", "all"], scopes=["contracts.read", "tickets.write"]),
}


# --------------------------------------------------------------------------- #
# Signing key (generated at startup, never written to disk)
# --------------------------------------------------------------------------- #


class SigningKey:
    """The process-lifetime RSA keypair, plus its JWKS representation."""

    def __init__(self) -> None:
        # Generated in memory so the repo can never contain key material. A
        # restart invalidates every outstanding token, which is fine for a demo
        # and is loudly wrong for production.
        self._private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid: str = uuid.uuid4().hex

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        return self._private

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._private.public_key()

    def jwks(self) -> dict[str, Any]:
        numbers = self.public_key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.kid,
                    "n": _b64u_uint(numbers.n),
                    "e": _b64u_uint(numbers.e),
                }
            ]
        }


def _b64u_uint(value: int) -> str:
    """Big-endian base64url of an unsigned integer, per RFC 7518 section 2."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


KEY: SigningKey


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


def audit(
    event: str,
    *,
    sub: str | None = None,
    aud: str | None = None,
    scope: str | None = None,
    reason: str | None = None,
) -> None:
    """One JSON line per issued or refused token, on stdout.

    Fixed key set (`ts`, `event`, `sub`, `aud`, `scope`, `reason`) across every
    service in the stack, so `docker compose logs | jq` reads as one timeline.
    `event` is one of: login, exchange, introspect, refused.
    """
    print(
        json.dumps(
            {
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "service": "idp",
                "event": event,
                "sub": sub,
                "aud": aud,
                "scope": scope,
                "reason": reason,
            }
        ),
        flush=True,
    )


# --------------------------------------------------------------------------- #
# Token minting / validation
# --------------------------------------------------------------------------- #


def mint_token(
    *,
    sub: str,
    aud: str,
    scopes: list[str],
    groups: list[str],
    ttl: int,
    act: dict[str, str] | None = None,
) -> tuple[str, int]:
    """Sign an access token. Returns (jwt, expires_in)."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": sub,
        # Single-string audience, always. A list-valued `aud` would let one
        # token be valid at two resource servers, which is exactly the property
        # this demo exists to argue against.
        "aud": aud,
        "scope": " ".join(scopes),
        "groups": groups,
        "iat": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
    }
    if act is not None:
        # RFC 8693 `act`: names the party acting on the user's behalf. Present
        # only on exchanged tokens, so a resource server can tell a delegated
        # call from a direct one.
        claims["act"] = act
    return encode(claims, KEY.private_key, KEY.kid), ttl


def decode_own_token(token: str, *, audience: str | None) -> dict[str, Any]:
    """Validate a token this service issued. Raises `jwt.PyJWTError` on failure.

    `audience=None` skips the audience check, which is correct ONLY for
    introspection: RFC 7662 asks "is this token live and what is in it", and the
    answer includes the audience rather than being conditioned on it. Every
    authorization decision in this stack passes a real audience.
    """
    if audience is None:
        return jwt.decode(
            token,
            KEY.public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            leeway=30,  # see common.jwt_tools.CLOCK_SKEW_SECONDS
            options={"verify_aud": False, "require": ["exp", "iat", "iss", "sub"]},
        )
    return verify(token, KEY.public_key, audience=audience, issuer=ISSUER)


def oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    """RFC 6749 section 5.2 error body."""
    return JSONResponse(status_code=status_code, content={"error": error, "error_description": description})


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global KEY
    KEY = SigningKey()
    # Not an audit line -- audit() is reserved for the fixed token event set.
    print(f"idp: generated RSA-2048 signing key kid={KEY.kid}", file=sys.stderr, flush=True)
    yield


app = FastAPI(
    title="Demo IdP",
    version="1.0.0",
    description="RFC 8693 token exchange for the private-LLM reference architecture. Demo only.",
    lifespan=lifespan,
)

basic_auth = HTTPBasic(auto_error=False)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


@app.post("/login")
async def login(body: LoginRequest) -> JSONResponse:
    """Password login. Issues the SUBJECT token: `aud = GATEWAY_RESOURCE`, no `act`.

    This token is only ever good at the gateway. It is not accepted by any MCP
    server, so a user who copies it out of a browser gains nothing downstream.
    """
    user = USERS.get(body.username)
    # Constant-ish time is beside the point here (plaintext demo passwords), but
    # the refusal must be indistinguishable between "no such user" and "wrong
    # password" so the endpoint is not a user enumerator.
    if user is None or user.password != body.password:
        audit("refused", sub=body.username, reason="invalid_credentials")
        return oauth_error("invalid_grant", "Invalid username or password", status_code=401)

    token, expires_in = mint_token(
        sub=body.username,
        aud=GATEWAY_RESOURCE,
        scopes=user.scopes,
        groups=user.groups,
        ttl=LOGIN_TTL_SECONDS,
    )
    audit("login", sub=body.username, aud=GATEWAY_RESOURCE, scope=" ".join(user.scopes))
    return JSONResponse({"access_token": token, "token_type": "Bearer", "expires_in": expires_in})


@app.post("/token")
async def token_exchange(
    grant_type: str = Form(...),
    subject_token: str = Form(...),
    subject_token_type: str = Form(...),
    resource: str = Form(...),
    scope: str | None = Form(default=None),
) -> JSONResponse:
    """RFC 8693 token exchange: gateway token in, single-audience token out.

    Everything the demo's security story rests on happens here, in this order:

      1. unknown `resource`            -> invalid_target
      2. subject token not for the gateway -> invalid_target
      3. expired / forged subject token    -> invalid_grant
      4. issued token: aud = resource, sub preserved, act = {"sub": "gateway"},
         groups preserved, scope narrowed to requested INTERSECT granted.
    """
    if grant_type != TOKEN_EXCHANGE_GRANT:
        audit("refused", reason=f"unsupported_grant_type:{grant_type}")
        return oauth_error("unsupported_grant_type", f"Only {TOKEN_EXCHANGE_GRANT} is supported")

    if subject_token_type != ACCESS_TOKEN_TYPE:
        audit("refused", reason=f"unsupported_subject_token_type:{subject_token_type}")
        return oauth_error("invalid_request", f"subject_token_type must be {ACCESS_TOKEN_TYPE}")

    # (1) Refuse to mint a token for a resource server this deployment does not
    # know. Without this, "resource" is an open redirect for credentials.
    if resource not in KNOWN_RESOURCES:
        audit("refused", aud=resource, reason="unknown_resource")
        return oauth_error("invalid_target", f"Unknown resource identifier: {resource}")

    # (2) and (3). The subject token must have been minted FOR THE GATEWAY. An
    # already-exchanged token (aud = some MCP server) cannot be exchanged again,
    # so a downstream tool cannot walk a token sideways to another tool.
    try:
        claims = decode_own_token(subject_token, audience=GATEWAY_RESOURCE)
    except jwt.InvalidAudienceError:
        # Named separately from the generic failure below: wrong audience is a
        # targeting error, not a credential error, and the demo asserts on it.
        wrong_aud = _peek(subject_token, "aud")
        audit(
            "refused",
            sub=_peek(subject_token, "sub"),
            aud=resource,
            reason=f"subject_token_aud={wrong_aud} expected={GATEWAY_RESOURCE}",
        )
        return oauth_error(
            "invalid_target",
            f"subject_token audience is {wrong_aud!r}, expected {GATEWAY_RESOURCE!r}",
        )
    except jwt.PyJWTError as exc:
        audit("refused", sub=_peek(subject_token, "sub"), aud=resource, reason=f"invalid_subject_token:{type(exc).__name__}")
        return oauth_error("invalid_grant", f"subject_token rejected: {exc}")

    granted: list[str] = str(claims.get("scope", "")).split()
    requested: list[str] = scope.split() if scope else granted
    # (4) Downscoping only ever removes. Order follows the request so the issued
    # `scope` string reads the way the caller asked for it.
    narrowed = [s for s in requested if s in granted]
    if not narrowed:
        audit("refused", sub=claims["sub"], aud=resource, scope=scope, reason="no_granted_scope_requested")
        return oauth_error("invalid_scope", f"None of the requested scopes are granted to {claims['sub']!r}")

    token, expires_in = mint_token(
        sub=claims["sub"],  # identity is PRESERVED; the gateway is not the subject
        aud=resource,
        scopes=narrowed,
        groups=list(claims.get("groups", [])),
        ttl=EXCHANGE_TTL_SECONDS,
        act={"sub": "gateway"},
    )
    audit("exchange", sub=claims["sub"], aud=resource, scope=" ".join(narrowed))
    return JSONResponse(
        {
            "access_token": token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": expires_in,
        }
    )


@app.post("/introspect")
async def introspect(
    token: str = Form(...),
    credentials: HTTPBasicCredentials | None = Depends(basic_auth),
) -> JSONResponse:
    """RFC 7662 introspection. Resource servers call this to check a token.

    DEMO ONLY: any non-empty client_id/client_secret pair is accepted. A real
    deployment registers clients and checks the secret; the point being made
    here is that introspection is authenticated at all, not how.
    """
    if credentials is None or not credentials.username or not credentials.password:
        audit("refused", reason="introspect_unauthenticated")
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "HTTP Basic client credentials required"},
            headers={"WWW-Authenticate": 'Basic realm="introspection"'},
        )

    try:
        claims = decode_own_token(token, audience=None)
    except jwt.PyJWTError as exc:
        # RFC 7662: an invalid token is not an error, it is `active: false`. No
        # claims are echoed back -- a caller must not learn anything from a
        # token it could not present validly.
        audit("introspect", sub=_peek(token, "sub"), reason=f"inactive:{type(exc).__name__}")
        return JSONResponse({"active": False})

    audit("introspect", sub=claims["sub"], aud=claims.get("aud"), scope=claims.get("scope"), reason="active")
    return JSONResponse(
        {
            "active": True,
            "sub": claims["sub"],
            "aud": claims.get("aud"),
            "scope": claims.get("scope", ""),
            "exp": claims.get("exp"),
            "iss": claims.get("iss"),
            "act": claims.get("act"),
            "client_id": credentials.username,
            "groups": claims.get("groups", []),
        }
    )


@app.get("/.well-known/jwks.json")
async def jwks() -> dict[str, Any]:
    """Public half of the signing key, so resource servers verify offline."""
    return KEY.jwks()


@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata(request: Request) -> dict[str, Any]:
    """Minimal RFC 8414 metadata, so a client can discover the endpoints.

    Endpoint URLs are built from `ISSUER_URL` (the in-network address of this
    service), not from the request Host header, which a caller controls.
    """
    return {
        "issuer": ISSUER,
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "token_endpoint": f"{ISSUER}/token",
        "introspection_endpoint": f"{ISSUER}/introspect",
        "grant_types_supported": [TOKEN_EXCHANGE_GRANT],
        "response_types_supported": [],
        "token_endpoint_auth_methods_supported": ["none"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
        "scopes_supported": ["contracts.read", "tickets.write"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        # RFC 8707: this server pins every issued token to exactly one resource.
        "authorization_response_iss_parameter_supported": True,
    }


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "idp", "kid": KEY.kid}


def _peek(token: str, claim: str) -> Any:
    """Best-effort unverified claim read, for audit lines about refused tokens."""
    try:
        return decode_unverified_claims(token).get(claim)
    except Exception:  # noqa: BLE001 - a malformed token still deserves an audit line
        return None


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8081")))
