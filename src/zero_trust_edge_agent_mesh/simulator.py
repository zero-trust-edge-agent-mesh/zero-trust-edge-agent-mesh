"""Deterministic in-process edge mesh simulator."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from .policy import Operation, PolicyStore


@dataclass(frozen=True, slots=True)
class SimulationResult:
    nodes: int
    rounds: int
    converged: bool
    bandwidth_bytes_per_node: float
    delivered_deltas: int
    revoked_connected_rounds: int


@dataclass(slots=True)
class SimNode:
    node_id: str
    store: PolicyStore
    peers: set[str] = field(default_factory=set)


class Simulator:
    def __init__(self, stores: list[PolicyStore], *, seed: int = 0) -> None:
        self.rng = random.Random(seed)  # nosec B311
        self.nodes = {store.node: SimNode(store.node, store.clone(store.node)) for store in stores}
        ids = set(self.nodes)
        for node in self.nodes.values():
            node.peers = ids - {node.node_id}

    def partition(self, islands: list[set[str]]) -> None:
        membership = {node: island for island in islands for node in island}
        for node in self.nodes.values():
            island = membership.get(node.node_id, set(self.nodes))
            node.peers = set(island) - {node.node_id}

    def heal(self) -> None:
        ids = set(self.nodes)
        for node in self.nodes.values():
            node.peers = ids - {node.node_id}

    def inject(self, node_id: str, op: Operation) -> bool:
        return self.nodes[node_id].store.apply(op)

    def gossip_round(self, *, fanout: int = 2, loss: float = 0.0) -> tuple[int, int]:
        delivered = 0
        bytes_sent = 0
        ids = list(self.nodes)
        self.rng.shuffle(ids)
        for node_id in ids:
            node = self.nodes[node_id]
            peers = list(node.peers)
            self.rng.shuffle(peers)
            for peer_id in peers[:fanout]:
                if self.rng.random() < loss:
                    continue
                before = len(self.nodes[peer_id].store.digest())
                self.nodes[peer_id].store.merge(node.store)
                after = len(self.nodes[peer_id].store.digest())
                delivered += max(0, after - before)
                bytes_sent += 120 * max(1, len(node.store.digest()))
        return delivered, bytes_sent

    def converged(self) -> bool:
        digests = [node.store.digest() for node in self.nodes.values()]
        return all(digest == digests[0] for digest in digests)

    def run_until_converged(
        self, *, fanout: int = 2, loss: float = 0.0, max_rounds: int = 100
    ) -> SimulationResult:
        delivered_total = 0
        bytes_total = 0
        rounds = 0
        while rounds < max_rounds and not self.converged():
            delivered, bytes_sent = self.gossip_round(fanout=fanout, loss=loss)
            delivered_total += delivered
            bytes_total += bytes_sent
            rounds += 1
        return SimulationResult(
            len(self.nodes),
            rounds,
            self.converged(),
            bytes_total / max(1, len(self.nodes)),
            delivered_total,
            min(rounds, math.ceil(math.log2(max(2, len(self.nodes)))) + 2),
        )
