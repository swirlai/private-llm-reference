"""Shared RS256 JWT helpers for the private-LLM reference demo.

Exported functions:

    encode(claims, private_key, kid)              -> str   (sign an RS256 JWT)
    decode_unverified_claims(token)               -> dict  (peek, NEVER trust)
    verify(token, jwks_url_or_key, audience, issuer) -> dict  (full validation)

Design notes for reviewers:

* Every service in this demo validates tokens the same way, through `verify`.
  Having exactly one code path means the audience check that beat 2 of the demo
  depends on cannot quietly differ between the gateway and an MCP server.
* `audience` and `issuer` are REQUIRED arguments rather than optional kwargs.
  An audience check you can forget to pass is an audience check that eventually
  is not performed -- which is precisely the confused-deputy bug this repo is
  about.
* The demo tolerates 30 seconds of clock skew (`CLOCK_SKEW_SECONDS`). Containers
  started by `docker compose up` can disagree with the host clock by a second or
  two, and a demo that fails with "token expired" on a laptop that slept teaches
  the wrong lesson. Thirty seconds is a demo convenience, not a recommendation.
* Dependency-light on purpose: PyJWT (with the `crypto` extra) and nothing else.
"""

from __future__ import annotations

from typing import Any

import jwt
from jwt import PyJWKClient

__all__ = ["encode", "decode_unverified_claims", "verify", "CLOCK_SKEW_SECONDS"]

ALGORITHM = "RS256"

# See module docstring: demo convenience, deliberately generous.
CLOCK_SKEW_SECONDS = 30

# PyJWKClient keeps an in-process cache of the signing keys it fetched. One
# client per JWKS URL, so a busy gateway does not re-fetch the key set on every
# single request.
_jwks_clients: dict[str, PyJWKClient] = {}


def encode(claims: dict[str, Any], private_key: Any, kid: str) -> str:
    """Sign `claims` as an RS256 JWT carrying `kid` in the header.

    `private_key` is anything PyJWT accepts: a cryptography private key object
    or a PEM string. The `kid` lets a verifier pick the right key out of the
    published JWKS.
    """
    return jwt.encode(claims, private_key, algorithm=ALGORITHM, headers={"kid": kid})


def decode_unverified_claims(token: str) -> dict[str, Any]:
    """Read the claims WITHOUT verifying the signature.

    Only ever for logging, routing and error messages -- for example, naming the
    `sub` in an audit line for a token we are about to refuse. Never make an
    authorization decision on the result; use `verify` for that.
    """
    return jwt.decode(token, options={"verify_signature": False})


def _resolve_key(token: str, jwks_url_or_key: Any) -> Any:
    """Return the verification key: fetch from JWKS if given a URL, else use as-is."""
    if isinstance(jwks_url_or_key, str) and jwks_url_or_key.startswith(("http://", "https://")):
        client = _jwks_clients.get(jwks_url_or_key)
        if client is None:
            client = PyJWKClient(jwks_url_or_key, cache_keys=True)
            _jwks_clients[jwks_url_or_key] = client
        return client.get_signing_key_from_jwt(token).key
    return jwks_url_or_key


def verify(
    token: str,
    jwks_url_or_key: Any,
    audience: str,
    issuer: str,
) -> dict[str, Any]:
    """Fully validate `token` and return its claims.

    `jwks_url_or_key` is either a JWKS URL (fetched and cached) or a public key
    / PEM the caller already holds.

    Raises `jwt.PyJWTError` (`ExpiredSignatureError`, `InvalidAudienceError`,
    `InvalidSignatureError`, ...) on any failure. Callers translate that into
    their own protocol's refusal, and MUST NOT fall back to the unverified
    claims.

    The audience check is the load-bearing one: a token minted for
    `https://mcp.corp.internal/contracts` must not validate at the tickets
    server. That is beat 2 of the demo.
    """
    key = _resolve_key(token, jwks_url_or_key)
    return jwt.decode(
        token,
        key,
        algorithms=[ALGORITHM],
        audience=audience,
        issuer=issuer,
        leeway=CLOCK_SKEW_SECONDS,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
