#!/usr/bin/env python3
"""Beat 1: the same question, asked by two people, returns two different worlds.

Nothing about the prompt changes. Nothing about the model changes. The only
difference is whose identity the gateway propagated to the contracts server.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import (  # noqa: E402
    WIDTH,
    ask_with_audit,
    bold,
    denied_count,
    dim,
    green,
    hits,
    kv,
    pause,
    red,
    require_stack,
    rule,
    say,
    section,
    title,
    walk,
)

QUESTION = "Which contracts mention termination for convenience?"

USERS = [
    ("alice", "vk-legal-demo", "legal"),
    ("bob", "vk-sales-demo", "sales"),
]

COL = (WIDTH - 6) // 2

# Audit records name the human as `sub` or `user` and the gateway as `act` or
# `actor`, depending on whether you are reading a claim or a log field. Narrate
# whichever ones this stack emits, in this order.
AUDIT_FIELDS = (
    "sub",
    "user",
    "act",
    "actor",
    "team",
    "aud",
    "target_resource",
    "scope",
    "tool",
    "model",
    "decision",
    "reason",
)


def cell(items, index):
    """One row of one column, plain text, truncated to the column width."""
    if index >= len(items):
        return ""
    hit = items[index]
    cid = str(hit.get("contract_id", "?"))
    party = str(hit.get("counterparty", ""))
    return (cid + "  " + party)[: COL - 1]


def plural(count, noun):
    return str(count) + " " + noun + ("" if count == 1 else "s")


def pad(text, width):
    """Pad first, color second. ANSI escapes have width on the wire, not on screen."""
    if not text:
        return dim("(nothing)".ljust(width))
    return text.ljust(width)


def audit_fields(record):
    """Pull the fields we narrate out of an audit record, whatever else it carries."""
    out = {}
    for node in walk(record):
        for key in AUDIT_FIELDS:
            if key in node and key not in out:
                out[key] = node[key]
    return out


def pick_search_record(records):
    for record in reversed(records):
        if "search_contracts" in str(record):
            return record
    return records[-1] if records else None


def main():
    require_stack()
    title(
        "BEAT 1  Confused deputy",
        "Same prompt, same model, same tool. Two users. Two answers.",
    )

    section("The question")
    say('  "' + QUESTION + '"')
    say()
    say(dim("  Asked twice, verbatim. The only variable is who is asking."))
    pause(1.5)

    results = {}
    for user, vkey, team in USERS:
        section("Asking as " + user + " (" + team + ")")
        kv("virtual key", vkey)
        kv("gateway call", "POST /v1/ask   user=" + user)
        seen = ask_with_audit(user, QUESTION, vkey)
        found = hits(seen)
        withheld = denied_count(seen)
        results[user] = {
            "hits": found,
            "withheld": withheld,
            "records": seen["records"],
        }
        kv("returned", plural(len(found), "contract") + ", " + str(withheld) + " withheld")
        pause(1.2)

    section("Side by side")
    alice = results["alice"]
    bob = results["bob"]
    print("  " + bold("alice / legal".ljust(COL)) + "  " + bold("bob / sales"))
    print("  " + dim("vk-legal-demo".ljust(COL)) + "  " + dim("vk-sales-demo"))
    print()

    rows = max(len(alice["hits"]), len(bob["hits"]), 1)
    for index in range(rows):
        left = pad(cell(alice["hits"], index), COL)
        right = pad(cell(bob["hits"], index), 0)
        print("  " + left + "  " + right)

    print()
    a_hits = plural(len(alice["hits"]), "hit")
    b_hits = plural(len(bob["hits"]), "hit")
    print("  " + green(a_hits.ljust(COL)) + "  " + red(b_hits))
    a_denied = str(alice["withheld"]) + " withheld"
    b_denied = str(bob["withheld"]) + " withheld"
    print("  " + dim(a_denied.ljust(COL)) + "  " + dim(b_denied))
    pause(2.0)

    section("What the audit says")
    for user, _vkey, team in USERS:
        record = pick_search_record(results[user]["records"])
        if record is None:
            print(red("  no audit record captured for " + user))
            continue
        fields = audit_fields(record)
        print(bold("  " + user + " (" + team + ")"))
        for key in AUDIT_FIELDS:
            if key in fields:
                kv(key, fields[key], key_width=16)
        kv("withheld", results[user]["withheld"], key_width=16)
        print()
        pause(0.8)

    rule()
    say()
    say(bold("  The prompt did not change. The model did not change."))
    say(bold("  The token did."))
    say()
    say(dim("  bob's token carries sub=bob and groups=[sales]. The contracts service"))
    say(dim("  trims on those groups before any text reaches the model, so the model"))
    say(dim("  never sees what bob is not entitled to see. It cannot leak what it was"))
    say(dim("  never given."))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
