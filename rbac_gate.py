"""Bounded offline RBAC evaluator. No identity, token, network, or production authorization."""
from __future__ import annotations

import json
import re
import sys
from typing import Any

MAX_BYTES = 65_536
MAX_ROLES = 128
MAX_SUBJECTS = 256
MAX_PERMISSIONS = 128
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,63}$")


class InvalidPolicy(ValueError):
    """Fail-closed invalid policy or request."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise InvalidPolicy("duplicate JSON key")
        obj[key] = value
    return obj


def _name(value: Any) -> bool:
    return type(value) is str and NAME.fullmatch(value) is not None


def _names(value: Any, limit: int = MAX_PERMISSIONS) -> bool:
    return (
        type(value) is list
        and len(value) <= limit
        and all(_name(v) for v in value)
        and len(set(value)) == len(value)
    )


def evaluate(document: Any) -> bool:
    """Return a bounded decision; invalid input raises InvalidPolicy (never allow)."""
    if type(document) is not dict or set(document) != {"roles", "subjects", "request"}:
        raise InvalidPolicy("invalid document schema")
    roles, subjects, request = document["roles"], document["subjects"], document["request"]
    if (type(roles) is not dict or len(roles) > MAX_ROLES or
            type(subjects) is not dict or len(subjects) > MAX_SUBJECTS or
            type(request) is not dict or set(request) != {"subject", "permission"}):
        raise InvalidPolicy("invalid policy schema")
    if not _name(request["subject"]) or not _name(request["permission"]):
        raise InvalidPolicy("invalid request")
    for role, definition in roles.items():
        if (not _name(role) or type(definition) is not dict or
                set(definition) != {"allow", "deny", "inherits"} or
                not all(_names(definition[k]) for k in ("allow", "deny", "inherits"))):
            raise InvalidPolicy("invalid role definition")
        if any(parent not in roles for parent in definition["inherits"]):
            raise InvalidPolicy("unknown inherited role")
    for subject, assignments in subjects.items():
        if not _name(subject) or not _names(assignments, MAX_ROLES):
            raise InvalidPolicy("invalid subject roles")
        if any(role not in roles for role in assignments):
            raise InvalidPolicy("unknown assigned role")
    # Reject cycles in the entire policy, not just those reachable by the request.
    done: set[str] = set()
    for root in roles:
        if root in done:
            continue
        active: set[str] = set()
        stack: list[tuple[str, bool]] = [(root, False)]
        while stack:
            role, exiting = stack.pop()
            if exiting:
                active.remove(role)
                done.add(role)
                continue
            if role in active:
                raise InvalidPolicy("cyclic role inheritance")
            if role in done:
                continue
            active.add(role)
            stack.append((role, True))
            stack.extend((parent, False) for parent in roles[role]["inherits"] if parent not in done)
    principal = request["subject"]
    permission = request["permission"]
    if principal not in subjects:
        return False
    pending = list(subjects[principal])
    visited: set[str] = set()
    allowed = False
    while pending:
        role = pending.pop()
        if role in visited:
            continue
        visited.add(role)
        rule = roles[role]
        if permission in rule["deny"]:
            return False
        if permission in rule["allow"]:
            allowed = True
        pending.extend(rule["inherits"])
    return allowed


def decide_bytes(data: bytes) -> bool:
    if len(data) > MAX_BYTES:
        raise InvalidPolicy("document too large")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs,
                              parse_constant=lambda _v: (_ for _ in ()).throw(InvalidPolicy("invalid numeric constant")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InvalidPolicy("invalid JSON") from exc
    return evaluate(document)


def main() -> int:
    try:
        authorized = decide_bytes(sys.stdin.buffer.read(MAX_BYTES + 1))
    except (InvalidPolicy, ValueError, TypeError, RecursionError):
        print('{"authorized":false,"error":"invalid policy or request"}')
        return 2
    print(json.dumps({"authorized": authorized}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
