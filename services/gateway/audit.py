"""Audit trail: one record per security-relevant decision.

An audit record is written for every tool call the gateway *allows*, every one it
*refuses*, and every one that *errors*. Refusals matter more than successes here: beat 3
of the demo is only convincing if you can point at the record that says "the model asked,
the architecture said no, and here is the tool call it asked with".

Records go to stdout as one JSON line (so `docker compose logs` is a usable audit stream)
and into a bounded in-memory ring buffer served at `GET /audit`.
"""

from __future__ import annotations

import json
import sys
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Deque, Literal

AUDIT_RING_SIZE = 200

Decision = Literal["allowed", "refused", "error"]


@dataclass(frozen=True)
class AuditRecord:
    ts: str
    request_id: str
    user: str | None  # JWT `sub` - the human the request is on behalf of
    actor: str | None  # JWT `act.sub` - who is acting for them (always "gateway" here)
    team: str  # from the virtual key, not from the token
    model: str
    tool: str | None
    target_resource: str | None  # RFC 8707 resource identifier the token was audienced to
    decision: Decision
    reason: str
    tokens_in: int
    tokens_out: int

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class AuditLog:
    """Newest-last ring buffer of the most recent `AUDIT_RING_SIZE` records."""

    def __init__(self, size: int = AUDIT_RING_SIZE) -> None:
        self._records: Deque[AuditRecord] = deque(maxlen=size)

    def record(
        self,
        *,
        request_id: str,
        team: str,
        model: str,
        decision: Decision,
        reason: str,
        user: str | None = None,
        actor: str | None = None,
        tool: str | None = None,
        target_resource: str | None = None,
        tokens_in: int = 0,
        tokens_out: int = 0,
    ) -> AuditRecord:
        rec = AuditRecord(
            ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            request_id=request_id,
            user=user,
            actor=actor,
            team=team,
            model=model,
            tool=tool,
            target_resource=target_resource,
            decision=decision,
            reason=reason,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
        )
        self._records.append(rec)
        # stdout is a first-class sink: a reviewer should not need the HTTP API to audit this.
        print(json.dumps({"audit": rec.as_dict()}, separators=(",", ":")), file=sys.stdout, flush=True)
        return rec

    def records(self) -> list[dict[str, object]]:
        return [r.as_dict() for r in self._records]


AUDIT = AuditLog()
