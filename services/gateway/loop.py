"""The tool loop.

model -> tool calls -> policy -> MCP -> results -> model -> ... -> answer, capped.

Two rules govern this file:

  * **Policy runs between the model and every tool**, with no path around it. The model
    proposes; the gateway disposes.
  * **Everything coming back from a tool is untrusted input.** Retrieved documents are
    attacker-controlled in the threat model this demo exists to illustrate. They are
    inserted into the transcript as data and are never given any authority over what the
    gateway does next; the next turn's tool calls are re-checked from scratch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from audit import AuditLog
from config import Settings
from identity import IdentityBroker, RequestIdentity, mint_delegated_tokens
from keys import KeyStore, VirtualKey
from mcp_client import ToolInvocationError, call_tool
from models import SYSTEM_PROMPT, ModelBackend, ToolCall
from policy import evaluate
from tools import TOOLS, openai_tool_schemas


@dataclass
class AskResult:
    answer: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    blocked: list[dict[str, Any]] = field(default_factory=list)


def _wanted_resources() -> dict[str, str]:
    """Resource identifier -> the union of the minimum scopes its tools need.

    One token per downstream server, each carrying only what the tools on that server use.
    """
    wants: dict[str, set[str]] = {}
    for spec in TOOLS.values():
        wants.setdefault(spec.resource, set()).add(spec.scope)
    return {resource: " ".join(sorted(scopes)) for resource, scopes in wants.items()}


async def run_ask(
    *,
    question: str,
    user: str,
    vk: VirtualKey,
    request_id: str,
    settings: Settings,
    backend: ModelBackend,
    broker: IdentityBroker,
    keys: KeyStore,
    audit: AuditLog,
) -> AskResult:
    # Identity first. If we cannot prove who is asking, we do not get to call anything on
    # their behalf - so this happens before the model is even consulted.
    identity: RequestIdentity = await mint_delegated_tokens(
        broker, user, settings.demo_password, _wanted_resources()
    )

    schemas = openai_tool_schemas()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": question},
    ]

    result = AskResult(answer="")
    total_in = total_out = 0

    for _ in range(settings.max_tool_iterations):
        turn = await backend.complete(messages, schemas)
        total_in += turn.tokens_in
        total_out += turn.tokens_out

        if not turn.tool_calls:
            result.answer = turn.content or ""
            break

        messages.append(
            {
                "role": "assistant",
                "content": turn.content,
                "tool_calls": [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                    }
                    for c in turn.tool_calls
                ],
            }
        )

        for call in turn.tool_calls:
            observation = await _handle_tool_call(
                call=call,
                identity=identity,
                vk=vk,
                request_id=request_id,
                settings=settings,
                backend=backend,
                audit=audit,
                result=result,
            )
            # Untrusted by construction: whatever this string contains, it is only ever a
            # `tool` message in the transcript.
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.name,
                    "content": observation,
                }
            )
    else:
        result.answer = (
            f"Stopped after {settings.max_tool_iterations} tool iterations without a final "
            "answer. The iteration cap is a safety control, not a bug."
        )
        audit.record(
            request_id=request_id,
            team=vk.team,
            model=backend.name,
            decision="error",
            reason=f"tool loop hit the {settings.max_tool_iterations}-iteration cap",
            user=identity.user,
            actor=identity.actor,
            tokens_in=total_in,
            tokens_out=total_out,
        )

    cost = keys.charge(vk, total_in, total_out)
    final = audit.record(
        request_id=request_id,
        team=vk.team,
        model=backend.name,
        decision="allowed",
        reason=f"answer returned; estimated cost ${cost:.6f}",
        user=identity.user,
        actor=identity.actor,
        tokens_in=total_in,
        tokens_out=total_out,
    )
    result.audit.append(final.as_dict())
    return result


async def _handle_tool_call(
    *,
    call: ToolCall,
    identity: RequestIdentity,
    vk: VirtualKey,
    request_id: str,
    settings: Settings,
    backend: ModelBackend,
    audit: AuditLog,
    result: AskResult,
) -> str:
    """Validate, then maybe execute, one proposed tool call. Never raises."""
    spec = TOOLS.get(call.name)
    if spec is None:
        reason = f"tool {call.name!r} is not in the gateway's catalog"
        rec = audit.record(
            request_id=request_id,
            team=vk.team,
            model=backend.name,
            decision="refused",
            reason=reason,
            user=identity.user,
            actor=identity.actor,
            tool=call.name,
        )
        result.audit.append(rec.as_dict())
        result.blocked.append({"tool": call.name, "arguments": call.arguments, "reason": reason})
        return json.dumps({"error": reason})

    token = identity.for_resource(spec.resource)

    decision = evaluate(call.name, call.arguments, settings.email_allowed_domains)
    if not decision.allowed:
        rec = audit.record(
            request_id=request_id,
            team=vk.team,
            model=backend.name,
            decision="refused",
            reason=decision.reason,
            user=token.subject or identity.user,
            actor=token.actor,
            tool=call.name,
            target_resource=spec.resource,
        )
        result.audit.append(rec.as_dict())
        result.blocked.append(
            {
                "tool": call.name,
                "arguments": call.arguments,  # the originating call, kept verbatim
                "reason": decision.reason,
                "target_resource": spec.resource,
            }
        )
        result.tool_calls.append(
            {
                "id": call.id,
                "tool": call.name,
                "arguments": call.arguments,
                "target_resource": spec.resource,
                "decision": "refused",
                "reason": decision.reason,
            }
        )
        # Tell the model "no" instead of crashing: the demo needs to show it being refused.
        return json.dumps({"refused": True, "reason": decision.reason})

    try:
        payload = await call_tool(spec.server_url, token.access_token, call.name, call.arguments)
    except ToolInvocationError as exc:
        rec = audit.record(
            request_id=request_id,
            team=vk.team,
            model=backend.name,
            decision="error",
            reason=str(exc)[:400],
            user=token.subject or identity.user,
            actor=token.actor,
            tool=call.name,
            target_resource=spec.resource,
        )
        result.audit.append(rec.as_dict())
        result.tool_calls.append(
            {
                "id": call.id,
                "tool": call.name,
                "arguments": call.arguments,
                "target_resource": spec.resource,
                "decision": "error",
                "reason": str(exc)[:400],
            }
        )
        return json.dumps({"error": str(exc)[:400]})

    rec = audit.record(
        request_id=request_id,
        team=vk.team,
        model=backend.name,
        decision="allowed",
        reason=decision.reason,
        user=token.subject or identity.user,
        actor=token.actor,
        tool=call.name,
        target_resource=spec.resource,
    )
    result.audit.append(rec.as_dict())
    result.tool_calls.append(
        {
            "id": call.id,
            "tool": call.name,
            "arguments": call.arguments,
            "target_resource": spec.resource,
            "decision": "allowed",
            "result": payload,
        }
    )
    return json.dumps(payload, default=str)
