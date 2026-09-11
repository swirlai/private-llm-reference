"""Gateway configuration.

Every value here is an *identifier* or a *URL*, and the two are deliberately not
interchangeable. `*_RESOURCE` values are RFC 8707 resource identifiers that appear as the
`aud` claim of a token; they are never fetched. `*_URL` values are network addresses.
Conflating the two is how audience restriction quietly stops working.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _csv(name: str, default: str) -> tuple[str, ...]:
    return tuple(p.strip().lower() for p in _env(name, default).split(",") if p.strip())


@dataclass(frozen=True)
class Settings:
    # --- identity -------------------------------------------------------------------
    issuer_url: str = field(default_factory=lambda: _env("ISSUER_URL", "http://idp:8081"))
    gateway_resource: str = field(
        default_factory=lambda: _env("GATEWAY_RESOURCE", "https://gateway.corp.internal")
    )
    contracts_resource: str = field(
        default_factory=lambda: _env("CONTRACTS_RESOURCE", "https://mcp.corp.internal/contracts")
    )
    tickets_resource: str = field(
        default_factory=lambda: _env("TICKETS_RESOURCE", "https://mcp.corp.internal/tickets")
    )

    # --- downstream addresses -------------------------------------------------------
    mcp_contracts_url: str = field(
        default_factory=lambda: _env("MCP_CONTRACTS_URL", "http://mcp-contracts:8092/mcp")
    )
    mcp_tickets_url: str = field(
        default_factory=lambda: _env("MCP_TICKETS_URL", "http://mcp-tickets:8093/mcp")
    )

    # --- model ----------------------------------------------------------------------
    model_backend: str = field(default_factory=lambda: _env("MODEL_BACKEND", "ollama"))
    model_base_url: str = field(
        default_factory=lambda: _env("MODEL_BASE_URL", "http://host.docker.internal:11434/v1")
    )
    model_name: str = field(default_factory=lambda: _env("MODEL_NAME", "qwen3:8b"))

    # --- policy ---------------------------------------------------------------------
    # The allowlist is the whole point of beat 3: the model can be talked into anything,
    # the allowlist cannot.
    email_allowed_domains: tuple[str, ...] = field(
        default_factory=lambda: _csv("EMAIL_ALLOWED_DOMAINS", "corp.internal")
    )

    # The demo IdP issues every seeded user the same password; there is no password here
    # to leak because there is no real credential in this repo at all.
    demo_password: str = field(default_factory=lambda: _env("DEMO_PASSWORD", "demo"))

    # Hard cap on model<->tool round trips. Without it, a prompt-injected model will happily
    # loop forever on a refused tool call.
    max_tool_iterations: int = 4


SETTINGS = Settings()
