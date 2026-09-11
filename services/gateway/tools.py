"""The tool catalog.

Each entry binds a tool name to exactly three things the security model depends on:

  * which MCP server hosts it (an address),
  * which RFC 8707 resource identifier a token for it must be audienced to,
  * the *minimum* scope that tool needs.

Keeping these together is what makes least-privilege auditable: you can read off, in one
place, that `send_email` can only ever be reached with a `tickets.write` token audienced
to the tickets server - and that a token minted for it is useless against contracts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from config import SETTINGS

Target = Literal["contracts", "tickets"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    target: Target
    resource: str  # RFC 8707 resource identifier -> becomes the exchanged token's `aud`
    scope: str  # minimum scope requested at exchange time
    server_url: str
    description: str
    parameters: dict[str, Any]  # JSON Schema, handed verbatim to the model

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


TOOLS: dict[str, ToolSpec] = {
    "search_contracts": ToolSpec(
        name="search_contracts",
        target="contracts",
        resource=SETTINGS.contracts_resource,
        scope="contracts.read",
        server_url=SETTINGS.mcp_contracts_url,
        description="Search the corporate contract repository. Results are trimmed to what "
        "the end user is entitled to see.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Free-text search query."},
                "counterparty": {"type": ["string", "null"], "description": "Optional counterparty filter."},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    ),
    "send_email": ToolSpec(
        name="send_email",
        target="tickets",
        resource=SETTINGS.tickets_resource,
        scope="tickets.write",
        server_url=SETTINGS.mcp_tickets_url,
        description="Send an internal email. Recipients outside the allowed corporate "
        "domains are refused.",
        parameters={
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address."},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    ),
}


def openai_tool_schemas() -> list[dict[str, Any]]:
    return [t.openai_schema() for t in TOOLS.values()]


def target_url(target: Target) -> str:
    return SETTINGS.mcp_contracts_url if target == "contracts" else SETTINGS.mcp_tickets_url


def target_resource(target: Target) -> str:
    return SETTINGS.contracts_resource if target == "contracts" else SETTINGS.tickets_resource
