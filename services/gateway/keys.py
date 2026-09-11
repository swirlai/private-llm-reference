"""Virtual keys and budgets.

A virtual key is the *caller's* credential (an app, a script, a notebook). It is NOT the
end user's identity and it never travels downstream - the whole point of the gateway is
that downstream services see a token minted for the human, not the app's API key.

Budgets are held in memory: this is a demo, and a demo that pretends to have durable
accounting is a demo that lies.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Cost is an ESTIMATE. We do not have real per-token billing for a locally hosted model,
# and pretending otherwise would be dishonest. The numbers below are placeholder rates
# chosen so a demo budget is exhaustible; every audit consumer should read spend as
# "estimated spend".
ESTIMATED_USD_PER_1K_INPUT_TOKENS = 0.0015
ESTIMATED_USD_PER_1K_OUTPUT_TOKENS = 0.0060


class UnknownKey(Exception):
    """No such virtual key -> HTTP 401."""


class BudgetExceeded(Exception):
    """Virtual key is over its budget -> HTTP 402."""


@dataclass
class VirtualKey:
    key: str
    team: str
    budget_usd: float
    estimated_spend_usd: float = field(default=0.0)

    @property
    def remaining_usd(self) -> float:
        return self.budget_usd - self.estimated_spend_usd


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 characters per token).

    Deliberately crude and deliberately labelled: the gateway needs *a* number to meter on,
    and a local model's tokenizer is not always reachable from here.
    """
    return max(1, len(text) // 4)


def estimate_cost_usd(tokens_in: int, tokens_out: int) -> float:
    return (
        tokens_in / 1000.0 * ESTIMATED_USD_PER_1K_INPUT_TOKENS
        + tokens_out / 1000.0 * ESTIMATED_USD_PER_1K_OUTPUT_TOKENS
    )


class KeyStore:
    def __init__(self, keys: list[VirtualKey]) -> None:
        self._keys = {k.key: k for k in keys}

    def authenticate(self, key: str | None) -> VirtualKey:
        """Resolve a virtual key, or refuse.

        Unknown key -> 401 (you are not a caller we know).
        Known but over budget -> 402 (you are a caller we know, and you are done for now).
        These are different failures and the demo shows them as different failures.
        """
        vk = self._keys.get(key or "")
        if vk is None:
            raise UnknownKey("unknown virtual key")
        if vk.remaining_usd <= 0:
            raise BudgetExceeded(
                f"virtual key {vk.key} has exhausted its estimated budget "
                f"(${vk.budget_usd:.2f})"
            )
        return vk

    def charge(self, vk: VirtualKey, tokens_in: int, tokens_out: int) -> float:
        cost = estimate_cost_usd(tokens_in, tokens_out)
        vk.estimated_spend_usd += cost
        return cost


# Seeded per SPEC. In-memory on purpose.
KEYS = KeyStore(
    [
        VirtualKey(key="vk-legal-demo", team="legal", budget_usd=5.00),
        VirtualKey(key="vk-sales-demo", team="sales", budget_usd=5.00),
    ]
)
