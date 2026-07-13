#!/usr/bin/env python3
import hashlib
import hmac
import sys

DIGEST_LENGTH = 16
DEFAULT_PREFIX = "pbctf"
TICKET_CONTEXT = b"ticket:"


def verify_ticket(secret, ticket):
    try:
        account_id, sig = ticket.strip().split(".", 1)
    except ValueError:
        return None
    if not account_id.isdigit():
        return None
    expected = hmac.new(
        secret.encode(), TICKET_CONTEXT + account_id.encode(), hashlib.sha256
    ).hexdigest()[:DIGEST_LENGTH]
    if not hmac.compare_digest(expected, sig):
        return None
    return int(account_id)


def flag_for_ticket(secret, ticket, prefix=DEFAULT_PREFIX):
    account_id = verify_ticket(secret, ticket)
    if account_id is None:
        return None
    digest = hmac.new(
        secret.encode(), str(account_id).encode(), hashlib.sha256
    ).hexdigest()[:DIGEST_LENGTH]
    return "%s{%s}" % (prefix, digest)


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print("usage: verify_ticket.py <secret> <ticket> [prefix]", file=sys.stderr)
        sys.exit(1)
    flag = flag_for_ticket(*sys.argv[1:])
    if flag is None:
        print("invalid ticket", file=sys.stderr)
        sys.exit(1)
    print(flag)
