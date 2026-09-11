"""Policy layer - the part that holds when the model does not.

Beat 3 of the demo assumes the prompt injection *works*: a retrieved contract tells the
model to exfiltrate contract IDs to an external address, and the model obeys. The model is
not the control. These two checks are:

  1. **Argument allowlist** - `send_email` recipients must sit in `EMAIL_ALLOWED_DOMAINS`.
  2. **Egress policy** - no tool argument may carry a URL or email address pointing
     outside the allowlist, whatever the argument is called.

Both run *before* the tool executes, both produce an audit record on refusal, and both
return a refusal *to the model* rather than raising. A crash would end the demo; a refusal
lets you watch the model be told "no" and try something else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit

# Loose on purpose: policy should over-match rather than under-match. A false positive
# costs a refused tool call; a false negative costs the data.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_URL_RE = re.compile(r"\b(?:https?|ftp|gopher|ws|wss)://[^\s\"'<>\)\]]+", re.IGNORECASE)

# Loopback and the compose service names are internal by construction.
_ALWAYS_INTERNAL_HOSTS = frozenset(
    {"localhost", "127.0.0.1", "::1", "idp", "gateway", "contracts-api", "mcp-contracts", "mcp-tickets"}
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str

    @staticmethod
    def allow(reason: str = "policy checks passed") -> "PolicyDecision":
        return PolicyDecision(True, reason)

    @staticmethod
    def refuse(reason: str) -> "PolicyDecision":
        return PolicyDecision(False, reason)


def _host_is_allowed(host: str, allowed_domains: Iterable[str]) -> bool:
    host = host.lower().strip().rstrip(".")
    if host in _ALWAYS_INTERNAL_HOSTS:
        return True
    return any(host == d or host.endswith("." + d) for d in allowed_domains)


def _walk_strings(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    """Yield (argument path, string) for every string anywhere in the arguments.

    Nested, because a model that has been told to exfiltrate will happily put the address
    in a list, a dict, or the body of an unrelated field.
    """
    if isinstance(value, str):
        yield path or "<root>", value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _walk_strings(v, f"{path}[{i}]")


def check_recipient_allowlist(
    tool: str, args: dict[str, Any], allowed_domains: tuple[str, ...]
) -> PolicyDecision:
    """Check 1: `send_email` may only address the corporate domains."""
    if tool != "send_email":
        return PolicyDecision.allow("no recipient allowlist applies to this tool")
    recipient = str(args.get("to", "")).strip()
    match = _EMAIL_RE.fullmatch(recipient)
    if match is None:
        return PolicyDecision.refuse(f"recipient {recipient!r} is not a well-formed email address")
    domain = match.group(1).lower()
    if not _host_is_allowed(domain, allowed_domains):
        # Name the full recipient, not just the domain. An auditor investigating an
        # exfiltration attempt needs the address that was targeted, and a refusal you
        # cannot attribute to a destination is a detection you half-lost.
        return PolicyDecision.refuse(
            f"recipient {recipient!r} refused: domain {domain!r} is not in "
            f"EMAIL_ALLOWED_DOMAINS ({', '.join(allowed_domains)})"
        )
    return PolicyDecision.allow(f"recipient domain {domain!r} is allowlisted")


def check_egress(tool: str, args: dict[str, Any], allowed_domains: tuple[str, ...]) -> PolicyDecision:
    """Check 2: no argument may name an external destination.

    This is the check that survives a rename. An injection that avoids the `to` field by
    hiding `archive@evil.example` in `body`, or an external webhook in some future tool's
    `callback_url`, is refused by the same rule.
    """
    for arg_path, text in _walk_strings(args):
        for url in _URL_RE.findall(text):
            host = urlsplit(url).hostname or ""
            if not _host_is_allowed(host, allowed_domains):
                return PolicyDecision.refuse(
                    f"argument {arg_path!r} contains external URL host {host!r}, "
                    f"which is not on the egress allowlist"
                )
        for domain in _EMAIL_RE.findall(text):
            if not _host_is_allowed(domain, allowed_domains):
                return PolicyDecision.refuse(
                    f"argument {arg_path!r} contains external address at {domain!r}, "
                    f"which is not on the egress allowlist"
                )
    return PolicyDecision.allow("no external destinations in arguments")


def evaluate(tool: str, args: dict[str, Any], allowed_domains: tuple[str, ...]) -> PolicyDecision:
    """Run every check. First refusal wins and carries the reason into the audit trail."""
    for check in (check_recipient_allowlist, check_egress):
        decision = check(tool, args, allowed_domains)
        if not decision.allowed:
            return decision
    return PolicyDecision.allow()
