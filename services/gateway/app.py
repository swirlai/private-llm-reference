"""Gateway - the security boundary.

Everything a caller can reach goes through here, and everything that leaves here carries a
token minted for one human, for one downstream resource, with one scope. The model runs
behind this line, not in front of it.

Routes:
  POST /v1/ask     ask a question; identity is propagated, tools are policed
  POST /v1/replay  deliberate misuse: call an MCP server with a token you supply
  GET  /audit      last 200 audit records, newest last
  GET  /healthz
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from audit import AUDIT
from config import SETTINGS
from identity import IdentityBroker, IdentityError, describe_token
from keys import KEYS, BudgetExceeded, UnknownKey
from loop import run_ask
from mcp_client import replay_raw
from models import build_backend
from tools import target_resource, target_url

app = FastAPI(
    title="Private LLM Gateway",
    description="Identity-propagating, policy-enforcing gateway in front of a private model.",
    version="0.1.0",
)

BACKEND = build_backend(SETTINGS.model_backend, SETTINGS.model_base_url, SETTINGS.model_name)
BROKER = IdentityBroker(SETTINGS.issuer_url, SETTINGS.gateway_resource)


class AskRequest(BaseModel):
    user: str
    question: str


class ReplayRequest(BaseModel):
    token: str
    target: Literal["contracts", "tickets"]
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class ReplayResponse(BaseModel):
    ok: bool
    status: int
    detail: str


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "model_backend": SETTINGS.model_backend, "model": BACKEND.name}


@app.get("/audit")
async def audit() -> dict[str, Any]:
    return {"records": AUDIT.records()}


@app.post("/v1/ask")
async def ask(
    body: AskRequest, x_virtual_key: str | None = Header(default=None, alias="X-Virtual-Key")
) -> dict[str, Any]:
    # The virtual key authenticates the CALLER. It says nothing about the end user, and it
    # is never forwarded anywhere.
    try:
        vk = KEYS.authenticate(x_virtual_key)
    except UnknownKey as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except BudgetExceeded as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc

    request_id = uuid.uuid4().hex[:12]
    try:
        result = await run_ask(
            question=body.question,
            user=body.user,
            vk=vk,
            request_id=request_id,
            settings=SETTINGS,
            backend=BACKEND,
            broker=BROKER,
            keys=KEYS,
            audit=AUDIT,
        )
    except IdentityError as exc:
        AUDIT.record(
            request_id=request_id,
            team=vk.team,
            model=BACKEND.name,
            decision="error",
            reason=str(exc)[:400],
            user=body.user,
        )
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "answer": result.answer,
        "tool_calls": result.tool_calls,
        "audit": result.audit,
        "blocked": result.blocked,
    }


@app.post("/v1/replay", response_model=ReplayResponse)
async def replay(
    body: ReplayRequest, x_virtual_key: str | None = Header(default=None, alias="X-Virtual-Key")
) -> ReplayResponse:
    """Replay a caller-supplied token against a named MCP server.

    This endpoint deliberately SKIPS the token exchange. Hand it a token minted for the
    contracts server, point it at the tickets server, and watch the tickets server refuse
    it on audience grounds (`validate_token_resource=True`). Set that flag to false on the
    resource server and the same call goes through - which is the point.

    It is still behind the virtual key, so "misuse endpoint" does not mean "open relay".
    """
    try:
        vk = KEYS.authenticate(x_virtual_key)
    except UnknownKey as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except BudgetExceeded as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc

    request_id = uuid.uuid4().hex[:12]
    # Label the audit record with whose token was replayed. Read without verifying: this
    # token is the *subject of the experiment*, and we are about to let the resource server
    # be the one that judges it.
    replayed = describe_token(body.token)
    ok, status, detail = await replay_raw(
        target_url(body.target), body.token, body.tool, body.args
    )
    AUDIT.record(
        request_id=request_id,
        team=vk.team,
        model=BACKEND.name,
        decision="allowed" if ok else "refused",
        reason=(
            f"replay against {body.target} without token exchange; token was minted for "
            f"aud={replayed.get('aud')!r}: HTTP {status} - {detail[:240]}"
        ),
        user=replayed.get("sub"),
        actor=replayed.get("act"),
        tool=body.tool,
        target_resource=target_resource(body.target),
    )
    return ReplayResponse(ok=ok, status=status, detail=detail)


# Convenience entrypoint so `python services/gateway/app.py` works for bare local
# runs (`make dev`). Containers use the uvicorn CMD in the Dockerfile instead.
if __name__ == "__main__":  # pragma: no cover
    import os

    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
