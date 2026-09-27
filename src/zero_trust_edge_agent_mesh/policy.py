"""Signed delta-state policy CRDT for disconnected edge sites."""

from __future__ import annotations

import base64
import fnmatch
import json
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

Action = Literal["allow", "deny"]
Kind = Literal["rule", "remove", "scalar"]


@dataclass(frozen=True, order=True, slots=True)
class HybridLogicalClock:
    wall_ms: int
    counter: int
    node: str

    @classmethod
    def now(cls, node: str, previous: HybridLogicalClock | None = None) -> HybridLogicalClock:
        wall = int(time.time() * 1000)
        if previous is None or wall > previous.wall_ms:
            return cls(wall, 0, node)
        return cls(previous.wall_ms, previous.counter + 1, node)

    def tick(self) -> HybridLogicalClock:
        return HybridLogicalClock.now(self.node, self)

    def merge(self, other: HybridLogicalClock) -> HybridLogicalClock:
        wall = max(int(time.time() * 1000), self.wall_ms, other.wall_ms)
        if wall == self.wall_ms == other.wall_ms:
            counter = max(self.counter, other.counter) + 1
        elif wall == self.wall_ms:
            counter = self.counter + 1
        elif wall == other.wall_ms:
            counter = other.counter + 1
        else:
            counter = 0
        return HybridLogicalClock(wall, counter, self.node)

    def as_tuple(self) -> tuple[int, int, str]:
        return (self.wall_ms, self.counter, self.node)


@dataclass(frozen=True, slots=True)
class Operation:
    op_id: str
    kind: Kind
    subject_glob: str
    tool: str
    action: Action
    max_staleness_s: int
    hlc: HybridLogicalClock
    signer: str
    signature: str = ""
    removes: tuple[str, ...] = ()

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "action": self.action,
            "hlc": self.hlc.as_tuple(),
            "kind": self.kind,
            "max_staleness_s": self.max_staleness_s,
            "op_id": self.op_id,
            "removes": list(self.removes),
            "signer": self.signer,
            "subject_glob": self.subject_glob,
            "tool": self.tool,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.unsigned_payload(), sort_keys=True, separators=(",", ":")).encode()

    def with_signature(self, signature: bytes) -> Operation:
        return replace(self, signature=base64.b64encode(signature).decode("ascii"))


class Authority:
    """Ed25519 signing authority for policy deltas."""

    def __init__(self, name: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self.name = name
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def public_key_b64(self) -> str:
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def sign_rule(
        self,
        subject_glob: str,
        tool: str,
        action: Action,
        *,
        max_staleness_s: int = 60,
        hlc: HybridLogicalClock | None = None,
    ) -> Operation:
        op = Operation(
            str(uuid.uuid4()),
            "rule",
            subject_glob,
            tool,
            action,
            max_staleness_s,
            hlc or HybridLogicalClock.now(self.name),
            self.name,
        )
        return op.with_signature(self.private_key.sign(op.canonical_bytes()))

    def sign_remove(
        self, target_op_ids: tuple[str, ...], *, hlc: HybridLogicalClock | None = None
    ) -> Operation:
        op = Operation(
            str(uuid.uuid4()),
            "remove",
            "*",
            "*",
            "deny",
            0,
            hlc or HybridLogicalClock.now(self.name),
            self.name,
            removes=tuple(sorted(target_op_ids)),
        )
        return op.with_signature(self.private_key.sign(op.canonical_bytes()))


@dataclass(slots=True)
class DecisionView:
    action: Action
    reason: str
    matched: tuple[str, ...] = ()
    max_staleness_s: int = 60


@dataclass(slots=True)
class PolicyStore:
    node: str
    authorities: dict[str, Ed25519PublicKey]
    rules: dict[str, Operation] = field(default_factory=dict)
    removes: dict[str, Operation] = field(default_factory=dict)
    scalars: dict[str, Operation] = field(default_factory=dict)

    def verify(self, op: Operation) -> bool:
        key = self.authorities.get(op.signer)
        if key is None or not op.signature:
            return False
        try:
            key.verify(base64.b64decode(op.signature), op.canonical_bytes())
            return True
        except (InvalidSignature, ValueError):
            return False

    def apply(self, op: Operation) -> bool:
        if not self.verify(op):
            return False
        if op.kind == "rule":
            if op.op_id not in self.removes:
                self.rules[op.op_id] = op
            return True
        if op.kind == "remove":
            self.removes[op.op_id] = op
            for target in op.removes:
                self.rules.pop(target, None)
            return True
        prev = self.scalars.get(op.subject_glob)
        if prev is None or prev.hlc.as_tuple() < op.hlc.as_tuple():
            self.scalars[op.subject_glob] = op
        return True

    def merge(self, other: PolicyStore) -> None:
        for op in [*other.removes.values(), *other.rules.values(), *other.scalars.values()]:
            self.apply(op)
        for rm in self.removes.values():
            for target in rm.removes:
                self.rules.pop(target, None)

    def delta_since(self, known_ids: set[str]) -> list[Operation]:
        return [
            op
            for op in [*self.rules.values(), *self.removes.values(), *self.scalars.values()]
            if op.op_id not in known_ids
        ]

    def digest(self) -> set[str]:
        return set(self.rules) | set(self.removes) | set(self.scalars)

    def decide(self, spiffe_id: str, tool: str) -> DecisionView:
        matches = [
            op
            for op in self.rules.values()
            if fnmatch.fnmatchcase(spiffe_id, op.subject_glob)
            and (op.tool == tool or op.tool == "*")
        ]
        if not matches:
            return DecisionView("deny", "default_deny", ())
        denies = [op for op in matches if op.action == "deny"]
        if denies:
            best = max(denies, key=lambda op: op.hlc.as_tuple())
            return DecisionView("deny", "deny_rule", (best.op_id,), best.max_staleness_s)
        best = max(matches, key=lambda op: op.hlc.as_tuple())
        return DecisionView("allow", "allow_rule", (best.op_id,), best.max_staleness_s)

    def clone(self, node: str | None = None) -> PolicyStore:
        return PolicyStore(
            node or self.node,
            dict(self.authorities),
            dict(self.rules),
            dict(self.removes),
            dict(self.scalars),
        )
