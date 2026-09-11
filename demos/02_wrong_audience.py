#!/usr/bin/env python3
"""Beat 2: a valid token, sent to the wrong server, is refused.

The headline demo. We mint a token for the contracts MCP server through a
normal RFC 8693 exchange, then replay that same token against the tickets MCP
server. Nothing about the token is forged: correct issuer, correct signature,
live expiry, real user. The only thing wrong with it is the audience.

Run it once with VALIDATE_TOKEN_RESOURCE=true (the default) to see the refusal,
then follow the printed instructions to flip the flag and run it again to watch
the same replay succeed. Pass --auto-flip to do both halves in one take; the
script prints every command it runs.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import (  # noqa: E402
    CONTRACTS_RESOURCE,
    GATEWAY_RESOURCE,
    TICKETS_RESOURCE,
    WIDTH,
    bold,
    dim,
    exchange,
    green,
    jwt_claims,
    kv,
    login,
    pause,
    red,
    replay,
    require_stack,
    say,
    section,
    title,
    wait_for,
    wrap,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# How to restart the tickets server with a different VALIDATE_TOKEN_RESOURCE.
# Docker is the default. Set FLIP_CMD in the environment to override it, which is
# what a bare `make dev` stack needs since there is no compose project to recreate:
#   FLIP_CMD="./scripts/restart-tickets.sh" python demos/02_wrong_audience.py --auto-flip
FLIP_CMD = shlex.split(os.environ["FLIP_CMD"]) if os.environ.get("FLIP_CMD") else [
    "docker",
    "compose",
    "up",
    "-d",
    "--force-recreate",
    "--no-deps",
    "mcp-tickets",
]

EMAIL_ARGS = {
    # An allowlisted recipient on purpose. If this replay is refused, the only
    # thing that can have refused it is the audience check.
    "to": "ops@corp.internal",
    "subject": "replayed token",
    "body": "Sent with a token minted for the contracts server.",
}


def panel(headline, lines, color):
    paint = green if color == "green" else red
    print()
    print(paint("+" + "-" * (WIDTH - 2) + "+"))
    print(paint("| " + headline.ljust(WIDTH - 4) + " |"))
    print(paint("+" + "-" * (WIDTH - 2) + "+"))
    for line in lines:
        print(paint("| ") + line.ljust(WIDTH - 4) + paint(" |"))
    print(paint("+" + "-" * (WIDTH - 2) + "+"))
    print()


def show_claims(label, token):
    claims = jwt_claims(token)
    print(bold("  " + label))
    for key in ("iss", "sub", "aud", "scope", "act", "jti"):
        if key in claims:
            kv(key, claims[key], key_width=8)
    if "act" not in claims:
        kv("act", dim("(absent: this is the user's own token, not an exchanged one)"), key_width=8)
    print()
    pause(0.8)


def do_replay(token):
    """Replay the contracts token against the tickets server. Returns the result dict."""
    kv("POST", "/v1/replay")
    kv("target", "tickets   " + dim("(" + TICKETS_RESOURCE + ")"))
    kv("tool", "send_email")
    kv("token aud", CONTRACTS_RESOURCE + "   " + dim("<- minted for the other server"))
    kv("recipient", EMAIL_ARGS["to"] + "   " + dim("(allowlisted, so egress policy will not fire)"))
    print()
    pause(1.0)
    return replay(token, "tickets", "send_email", EMAIL_ARGS)


def detail_lines(result):
    """status and detail, wrapped so a long identifier is never cut in half."""
    lines = ["status  " + str(result.get("status"))]
    body = wrap(str(result.get("detail", "")), WIDTH - 12, "")
    lines.append("detail  " + (body[0] if body else ""))
    lines.extend("        " + line for line in body[1:])
    return lines


def refused_panel(result):
    panel(
        "REFUSED by the tickets MCP server",
        detail_lines(result)
        + [
            "",
            "The token is signed, unexpired and belongs to a real user.",
            "Its aud is " + CONTRACTS_RESOURCE + ".",
            "This server is " + TICKETS_RESOURCE + ". Not its token, not its problem.",
        ],
        "red",
    )


def accepted_panel(result):
    panel(
        "ACCEPTED by the tickets MCP server",
        detail_lines(result)
        + [
            "",
            "Same token. Same replay. One configuration flag turned off.",
            "A token for one server now acts on another. That is the",
            "confused deputy, and it is a one-line mistake.",
        ],
        "green",
    )


def flip_instructions(value):
    print(bold("  Run this, then run this script again:"))
    print()
    print("      VALIDATE_TOKEN_RESOURCE=" + value + " \\")
    print("        docker compose up -d --force-recreate --no-deps mcp-tickets")
    print("      python demos/02_wrong_audience.py")
    print()


def auto_flip(value):
    """Do exactly what the printed instructions say, and say so while doing it."""
    print(bold("  --auto-flip: running the command above"))
    print(dim("      VALIDATE_TOKEN_RESOURCE=" + value + " " + " ".join(FLIP_CMD)))
    print()
    env = dict(os.environ, VALIDATE_TOKEN_RESOURCE=value)
    try:
        subprocess.run(FLIP_CMD, cwd=REPO_ROOT, env=env, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(red("  could not run docker compose: " + str(exc)))
        return False
    if not wait_for("http://localhost:8093/healthz"):
        print(red("  mcp-tickets did not come back healthy"))
        return False
    print(dim("  mcp-tickets is healthy again with VALIDATE_TOKEN_RESOURCE=" + value))
    pause(1.0)
    return True


def main():
    require_stack()
    auto = "--auto-flip" in sys.argv

    title(
        "BEAT 2  Wrong audience",
        "One token, two servers. Only one of them should take it.",
    )

    section("1. alice signs in")
    subject_token = login("alice")
    kv("POST", "/login   username=alice")
    print()
    show_claims("subject token", subject_token)
    say(dim("  aud is the gateway (" + GATEWAY_RESOURCE + "). This token is good for"))
    say(dim("  talking to the gateway and nothing else."))
    pause(1.2)

    section("2. The gateway exchanges it for a contracts token")
    # Both scopes on purpose. A real gateway narrows scope per target, and this one
    # does. Here we deliberately do NOT, so that when the replay is refused the only
    # possible cause is the audience check. A scope-narrowed token would be refused
    # for insufficient_scope instead, which proves a different (also good) control.
    response = exchange(subject_token, CONTRACTS_RESOURCE, "contracts.read tickets.write")
    if response.status_code != 200:
        print(red("  exchange failed: " + str(response.status_code) + " " + response.text[:200]))
        return 1
    contracts_token = response.json()["access_token"]
    kv("POST", "/token   grant_type=token-exchange")
    kv("resource", CONTRACTS_RESOURCE)
    kv("scope", "contracts.read tickets.write   " + dim("(both, on purpose: see below)"))
    print()
    show_claims("exchanged token", contracts_token)
    say(dim("  sub is still alice. act says the gateway did the exchanging. aud is now"))
    say(dim("  the contracts server. This is a correct, boring, everyday token."))
    print()
    say(dim("  A real gateway narrows scope per target, and this one does on /v1/ask."))
    say(dim("  Here we deliberately keep both scopes, so that when the replay below is"))
    say(dim("  refused, the audience check is the only thing that can have refused it."))
    pause(1.5)

    section("3. Control: use the token where it belongs")
    control = replay(contracts_token, "contracts", "search_contracts", {"query": "termination"})
    if control.get("ok"):
        print("  " + green("contracts server accepted it") + dim("  status " + str(control.get("status"))))
    else:
        print("  " + red("contracts server refused it: " + str(control.get("detail"))[:60]))
        print(dim("  (that is unexpected: the rest of this demo assumes a working token)"))
    print()
    pause(1.2)

    section("4. The misuse: replay it against the tickets server")
    result = do_replay(contracts_token)

    if not result.get("ok"):
        refused_panel(result)
        pause(2.0)
        say(bold("  That is the property. Now break it deliberately."))
        say()
        say("  VALIDATE_TOKEN_RESOURCE=false tells the tickets server to accept any")
        say("  token this issuer signed, no matter who it was minted for.")
        print()
        if not auto:
            flip_instructions("false")
            return 0
        if not auto_flip("false"):
            return 1
        section("5. Same replay, validation off")
        result = do_replay(contracts_token)
        if result.get("ok"):
            accepted_panel(result)
        else:
            print(red("  still refused: " + str(result.get("detail"))[:120]))
        pause(2.0)
        print(bold("  Put it back:"))
        print()
        print("      VALIDATE_TOKEN_RESOURCE=true \\")
        print("        " + " ".join(FLIP_CMD))
        print()
    else:
        accepted_panel(result)
        say(dim("  This stack is running with VALIDATE_TOKEN_RESOURCE=false."))
        pause(1.5)
        flip_instructions("true")

    say(bold("  The model never entered this story."))
    say()
    say(dim("  No prompt, no system message and no amount of alignment can stop a"))
    say(dim("  token from being replayed. A one-line audience check can. That check"))
    say(dim("  lives in the resource server, not in the model and not in the client."))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
