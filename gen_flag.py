#!/usr/bin/env python3
import hashlib
import hmac
import os
import sys

DIGEST_LENGTH = 16
DEFAULT_PREFIX = os.environ.get("HMAC_FLAG_PREFIX") or "pbctf"


def gen_flag(secret, account_id, prefix=DEFAULT_PREFIX):
    digest = hmac.new(
        secret.encode(), str(account_id).encode(), hashlib.sha256
    ).hexdigest()[:DIGEST_LENGTH]
    return "%s{%s}" % (prefix, digest)


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print("usage: gen_flag.py <secret> <account_id> [prefix]", file=sys.stderr)
        sys.exit(1)
    print(gen_flag(*sys.argv[1:]))
