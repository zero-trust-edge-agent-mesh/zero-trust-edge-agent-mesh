from __future__ import annotations

from copy import deepcopy

from hypothesis import given, settings
from hypothesis import strategies as st

from zero_trust_edge_agent_mesh.policy import Authority, PolicyStore


def _stores(n: int = 3) -> tuple[Authority, list[PolicyStore]]:
    auth = Authority("root")
    stores = [PolicyStore(f"n{i}", {"root": auth.public_key}) for i in range(n)]
    return auth, stores


def test_signed_ops_apply_and_forged_rejected() -> None:
    auth, stores = _stores(2)
    op = auth.sign_rule("spiffe://acme.test/site/sjc/*", "http.get", "allow")
    assert stores[0].apply(op)
    forged = deepcopy(op)
    object.__setattr__(forged, "tool", "*")
    assert not stores[1].apply(forged)


def test_remove_wins_and_deny_overrides_allow() -> None:
    auth, stores = _stores(1)
    allow = auth.sign_rule("spiffe://acme.test/site/sjc/*", "http.get", "allow")
    deny = auth.sign_rule("spiffe://acme.test/site/sjc/*", "http.get", "deny")
    store = stores[0]
    assert store.apply(allow)
    assert store.decide("spiffe://acme.test/site/sjc/agent/a", "http.get").action == "allow"
    assert store.apply(deny)
    assert store.decide("spiffe://acme.test/site/sjc/agent/a", "http.get").action == "deny"
    rm = auth.sign_remove((deny.op_id,))
    assert store.apply(rm)
    assert deny.op_id not in store.rules


@given(order=st.permutations([0, 1, 2, 3]))
@settings(max_examples=24, deadline=None)
def test_merge_converges_for_arbitrary_delivery_order(order: tuple[int, ...]) -> None:
    auth, stores = _stores(4)
    ops = [auth.sign_rule(f"spiffe://acme.test/site/s{i}/*", "http.get", "allow") for i in range(4)]
    for idx, op in enumerate(ops):
        stores[idx].apply(op)
    acc = stores[0].clone("acc")
    for idx in order:
        acc.merge(stores[idx])
        acc.merge(stores[idx])
    digest = acc.digest()
    for store in stores:
        store.merge(acc)
        assert store.digest() == digest
