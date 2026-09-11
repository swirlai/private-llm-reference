"""contracts_api - the system of record that mcp_contracts reads through.

Two things make this service worth reading:

1. It re-validates the bearer token itself, by introspection, instead of trusting
   whatever called it. An MCP server in front of it is not a trust boundary.
2. It trims results by the *token's* `groups` claim, and reports what it withheld
   as a bare count. `denied_count` is the only thing a caller learns about
   documents they are not entitled to - never an id, a counterparty, or a snippet.

The `X-On-Behalf-Of` header is carried for log correlation only. It is caller-
supplied, so it never influences an authorization decision; the token does.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Final

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from fixtures import CONTRACTS, Contract

SERVICE: Final = "contracts_api"

ISSUER_URL: Final = os.getenv("ISSUER_URL", "http://idp:8081")
CONTRACTS_RESOURCE: Final = os.getenv("CONTRACTS_RESOURCE", "https://mcp.corp.internal/contracts")
# One flag governs audience binding across the whole demo (beat 2). Turning it off
# here as well as at the MCP boundary keeps the "before/after" recording coherent.
VALIDATE_TOKEN_RESOURCE: Final = os.getenv("VALIDATE_TOKEN_RESOURCE", "true") == "true"
REQUIRED_SCOPE: Final = "contracts.read"

# Credentials for the RFC 7662 introspection endpoint. These authenticate this
# *service* to the IdP; they grant no access to any document. All document access
# is decided by the end user's token. The IdP accepts any non-empty pair in demo mode.
INTROSPECT_CLIENT_ID: Final = os.getenv("INTROSPECT_CLIENT_ID", "contracts-api")
INTROSPECT_CLIENT_SECRET: Final = os.getenv("INTROSPECT_CLIENT_SECRET", "demo-not-a-secret")

SNIPPET_CHARS: Final = 600

# Dropped from the query before matching so that a natural-language question does
# not match every document through its filler words.
STOPWORDS: Final = frozenset(
    {"a", "an", "and", "any", "are", "for", "in", "is", "me", "of", "on", "or",
     "our", "show", "that", "the", "to", "what", "which", "with"}
)

app = FastAPI(title="contracts_api", version="1.0.0")
_http = httpx.AsyncClient(timeout=10.0)


def audit(event: str, **fields: Any) -> None:
    """One structured line per security-relevant decision, on stdout."""
    print(json.dumps({"ts": time.time(), "service": SERVICE, "event": event, **fields}), flush=True)


class SearchRequest(BaseModel):
    q: str
    counterparty: str | None = None
    limit: int = Field(default=10, ge=1, le=50)


class Hit(BaseModel):
    contract_id: str
    counterparty: str
    effective_date: str
    snippet: str
    url: str


class SearchResponse(BaseModel):
    hits: list[Hit]
    total: int  # entitled matches only
    denied_count: int  # matches withheld from this caller; no other detail escapes


class Caller(BaseModel):
    """The authenticated end user, as the IdP describes them. Never caller-supplied."""

    sub: str
    groups: list[str]
    scopes: list[str]
    aud: str | None


async def authenticate(authorization: str | None) -> Caller:
    """Introspect the bearer token and turn it into a caller identity, or refuse."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer ") :]

    try:
        response = await _http.post(
            f"{ISSUER_URL}/introspect",
            data={"token": token},
            auth=(INTROSPECT_CLIENT_ID, INTROSPECT_CLIENT_SECRET),
        )
        response.raise_for_status()
        claims: dict[str, Any] = response.json()
    except httpx.HTTPError as exc:
        # Fail closed: if we cannot establish who is asking, nobody gets contracts.
        audit("introspection_failed", error=str(exc))
        raise HTTPException(status_code=503, detail="token introspection unavailable") from exc

    if not claims.get("active"):
        audit("token_rejected", reason="inactive")
        raise HTTPException(status_code=401, detail="token is not active")

    scopes = str(claims.get("scope") or "").split()
    if REQUIRED_SCOPE not in scopes:
        audit("token_rejected", reason="insufficient_scope", sub=claims.get("sub"), scopes=scopes)
        raise HTTPException(status_code=403, detail=f"required scope: {REQUIRED_SCOPE}")

    aud = claims.get("aud")
    if VALIDATE_TOKEN_RESOURCE and aud != CONTRACTS_RESOURCE:
        # RFC 8707 audience binding: a token minted for some other resource is not
        # currency here, even though it is a perfectly valid token.
        audit("token_rejected", reason="wrong_audience", sub=claims.get("sub"), aud=aud)
        raise HTTPException(status_code=403, detail="token was not issued for this resource")

    return Caller(
        sub=str(claims.get("sub") or ""),
        groups=list(claims.get("groups") or []),
        scopes=scopes,
        aud=aud if isinstance(aud, str) else None,
    )


def query_terms(q: str) -> list[str]:
    """Content-bearing terms from a query, in order, de-duplicated."""
    seen: list[str] = []
    for t in re.findall(r"[a-z0-9]+", q.lower()):
        if t not in STOPWORDS and t not in seen:
            seen.append(t)
    return seen


def score(contract: Contract, request: SearchRequest) -> int:
    """How many distinct query terms this contract contains.

    Deliberately NOT an AND over every term. A model, or a person, asks
    "Which contracts mention termination for convenience?", and requiring
    every content word would drop "mention" on the floor and return nothing.
    Partial-match scoring is both what a real search backend does and what
    keeps the demo working when a live model rephrases the query.
    """
    haystack = f"{contract.contract_id} {contract.counterparty} {contract.body}".lower()
    return sum(1 for term in query_terms(request.q) if term in haystack)


def matches(contract: Contract, request: SearchRequest) -> bool:
    """A contract matches on a relevance floor, after the counterparty filter.

    The floor is two terms once the query has two or more to offer, which keeps
    a single incidental word (every agreement contains "agreement") from
    dragging in the whole corpus.
    """
    if request.counterparty and request.counterparty.lower() not in contract.counterparty.lower():
        return False
    terms = query_terms(request.q)
    if not terms:
        return True
    return score(contract, request) >= (2 if len(terms) >= 2 else 1)


def snippet_for(contract: Contract, request: SearchRequest) -> str:
    """A window of the body centred on the first matching term.

    For C-4471 this lands on "Section 12. Termination for convenience." and the
    window is wide enough to carry the injected block with it - which is the whole
    point of beat 3. Redacting it here would make the demo dishonest.
    """
    body = contract.body
    if len(body) <= SNIPPET_CHARS:
        return body
    positions = [p for p in (body.lower().find(t) for t in query_terms(request.q)) if p >= 0]
    centre = min(positions) if positions else 0
    start = max(0, centre - SNIPPET_CHARS // 3)
    return body[start : start + SNIPPET_CHARS]


@app.post("/api/search", response_model=SearchResponse)
async def search(
    request: SearchRequest,
    authorization: str | None = Header(default=None),
    x_on_behalf_of: str | None = Header(default=None),
) -> SearchResponse:
    caller = await authenticate(authorization)

    matched = sorted(
        (c for c in CONTRACTS if matches(c, request)),
        key=lambda c: (-score(c, request), c.contract_id),
    )
    # The single ACL decision in this service. Everything above it is plumbing.
    entitled = [c for c in matched if set(c.allowed_groups) & set(caller.groups)]
    denied_count = len(matched) - len(entitled)

    hits = [
        Hit(
            contract_id=c.contract_id,
            counterparty=c.counterparty,
            effective_date=c.effective_date,
            snippet=snippet_for(c, request),
            url=c.url,
        )
        for c in entitled[: request.limit]
    ]

    audit(
        "search",
        sub=caller.sub,
        on_behalf_of_header=x_on_behalf_of,
        groups=caller.groups,
        query=request.q,
        matched=len(matched),
        returned=len(hits),
        denied_count=denied_count,
        contract_ids=[h.contract_id for h in hits],
    )
    return SearchResponse(hits=hits, total=len(entitled), denied_count=denied_count)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8091")), log_level="info")
