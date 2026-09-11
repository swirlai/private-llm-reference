"""Identity propagation - the central claim of the article.

`ollama run` has one identity: the process. This gateway has two, and keeps them apart:

  1. The **subject token**, minted by the IdP when the end user logs in. Its audience is
     the gateway and nothing else. It never leaves this process.
  2. A **delegated token per downstream resource**, obtained by RFC 8693 token exchange.
     Its `sub` is still the human, its `act.sub` is the gateway, its `aud` is exactly one
     MCP server, and its scope is the minimum that one tool needs.

The practical consequence is that a token stolen from - or replayed out of - the contracts
server is worthless against the tickets server. `POST /v1/replay` exists to demonstrate
precisely that.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import jwt

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def describe_token(access_token: str) -> dict[str, Any]:
    """Best-effort, unverified read of a token's identity claims, for audit labelling only.

    Used by the replay endpoint, where the token is caller-supplied and possibly bogus -
    which is the point. Verification is the resource server's job, not ours.
    """
    try:
        claims: dict[str, Any] = jwt.decode(
            access_token, options={"verify_signature": False, "verify_aud": False}
        )
    except Exception:  # noqa: BLE001 - an unparseable token is a legitimate replay input
        return {"sub": None, "aud": None, "act": None}
    act = claims.get("act") or {}
    return {
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
        "act": act.get("sub") if isinstance(act, dict) else None,
    }


class IdentityError(Exception):
    """The IdP refused to authenticate the user or to mint a delegated token."""


@dataclass(frozen=True)
class DelegatedToken:
    """A token audienced to exactly one downstream resource."""

    access_token: str
    resource: str
    scope: str
    subject: str | None
    actor: str | None

    @classmethod
    def from_jwt(cls, access_token: str, resource: str, scope: str) -> "DelegatedToken":
        # Decoded WITHOUT signature verification, and only to label audit records. The
        # gateway just received this token from the IdP over a trusted hop; the party that
        # must verify it cryptographically is the resource server that will be handed it.
        claims: dict[str, Any] = jwt.decode(
            access_token, options={"verify_signature": False, "verify_aud": False}
        )
        act = claims.get("act") or {}
        return cls(
            access_token=access_token,
            resource=resource,
            scope=scope,
            subject=claims.get("sub"),
            actor=act.get("sub") if isinstance(act, dict) else None,
        )


class IdentityBroker:
    """Talks to the IdP. Nothing else in the gateway holds a subject token."""

    def __init__(self, issuer_url: str, gateway_resource: str, timeout: float = 10.0) -> None:
        self._issuer_url = issuer_url.rstrip("/")
        self._gateway_resource = gateway_resource
        self._timeout = timeout

    async def login(self, username: str, password: str) -> str:
        """Authenticate the end user and return their subject token (aud = gateway)."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._issuer_url}/login", json={"username": username, "password": password}
            )
        if resp.status_code != 200:
            raise IdentityError(f"idp /login refused user {username!r}: HTTP {resp.status_code}")
        subject_token = str(resp.json()["access_token"])

        # Defence in depth: a subject token audienced to anything other than this gateway is
        # a token we were never meant to hold, and exchanging it would be the confused-deputy
        # bug this whole design exists to avoid.
        audience = describe_token(subject_token).get("aud")
        if audience != self._gateway_resource:
            raise IdentityError(
                f"subject token for {username!r} is audienced to {audience!r}, "
                f"expected {self._gateway_resource!r}"
            )
        return subject_token

    async def exchange(self, subject_token: str, resource: str, scope: str) -> DelegatedToken:
        """RFC 8693 exchange: subject token -> token for ONE downstream resource.

        `resource` is an identifier, never an address. Requesting the narrowest scope the
        tool needs is what stops a read tool from carrying a write capability around.
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._issuer_url}/token",
                data={
                    "grant_type": TOKEN_EXCHANGE_GRANT,
                    "subject_token": subject_token,
                    "subject_token_type": ACCESS_TOKEN_TYPE,
                    "resource": resource,
                    "scope": scope,
                },
            )
        if resp.status_code != 200:
            raise IdentityError(
                f"token exchange for resource {resource!r} failed: HTTP {resp.status_code} {resp.text[:200]}"
            )
        return DelegatedToken.from_jwt(str(resp.json()["access_token"]), resource, scope)


@dataclass(frozen=True)
class RequestIdentity:
    """Per-request identity bundle.

    Note what is NOT here: any way for the tool loop to reach the subject token. The loop
    is handed `delegated` and only `delegated`, so "never forward the subject token
    downstream" is enforced by the shape of the data, not by everyone remembering.
    """

    user: str
    delegated: dict[str, DelegatedToken]  # resource identifier -> token

    @property
    def actor(self) -> str | None:
        """The `act.sub` the IdP stamped on the delegated tokens - always the gateway."""
        return next((t.actor for t in self.delegated.values() if t.actor), None)

    def for_resource(self, resource: str) -> DelegatedToken:
        token = self.delegated.get(resource)
        if token is None:  # pragma: no cover - catalog and mint set are built together
            raise IdentityError(f"no delegated token was minted for resource {resource!r}")
        return token


async def mint_delegated_tokens(
    broker: IdentityBroker, username: str, password: str, wants: dict[str, str]
) -> RequestIdentity:
    """Log the user in once, then exchange once per downstream resource.

    `wants` maps resource identifier -> requested scope. One exchange per MCP server, each
    audienced to that server alone. The subject token is local to this function and is
    discarded when it returns.
    """
    subject_token = await broker.login(username, password)
    delegated = {
        resource: await broker.exchange(subject_token, resource, scope)
        for resource, scope in wants.items()
    }
    return RequestIdentity(user=username, delegated=delegated)
