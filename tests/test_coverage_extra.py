from __future__ import annotations

from pathlib import Path

import pytest

from zero_trust_edge_agent_mesh.adapter import defense
from zero_trust_edge_agent_mesh.identity import EdgePKI
from zero_trust_edge_agent_mesh.mesh import tls_client_context, tls_server_context
from zero_trust_edge_agent_mesh.pdp import EdgePDP
from zero_trust_edge_agent_mesh.policy import Authority, HybridLogicalClock, Operation, PolicyStore
from zero_trust_edge_agent_mesh.simulator import Simulator
from zero_trust_edge_agent_mesh.stats import bootstrap_quantile_ci, mean_t_ci, quantile, wilson


def _request(agent: dict[str, object] | None = None, **overrides: object) -> dict[str, object]:
    req: dict[str, object] = {
        "trace_id": "x",
        "step": 0,
        "agent": {
            "spiffe_id": "spiffe://acme.test/site/sjc/agent/a",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": ["benign"],
            "scopes": [
                "fs:read",
                "fs:write",
                "net:read",
                "net:write",
                "email:send",
                "calendar:write",
                "db:read",
                "secrets:read",
                "mcp:use",
            ],
            "role": "assistant",
        },
        "tool": "http.get",
        "args": {"url": "https://api.acme.test/x"},
        "context": {"content": "ok", "reasoning_tokens": 3},
        "history": [],
    }
    if agent:
        merged = dict(req["agent"])
        merged.update(agent)
        req["agent"] = merged
    req.update(overrides)
    return req


def test_adapter_factory_and_reset() -> None:
    adapter = defense()
    before = adapter.pdp.cache_updated_s
    adapter.pdp.cache_updated_s = 0
    adapter.reset()
    assert adapter.pdp.cache_updated_s >= before


def test_pdp_posture_scope_and_content_scope_boundaries() -> None:
    pdp = EdgePDP()
    assert pdp.decide(_request(agent={"svid": "expired"})).reason == "expired"
    assert pdp.decide(_request(agent={"attestation": "stale"})).reason == "invalid_attestation"
    assert (
        pdp.decide(
            _request(tool="secrets.get", agent={"trust_history": ["suspicious", "suspicious"]})
        ).reason
        == "low_trust"
    )
    assert pdp.decide(_request(agent={"scopes": []})).reason == "scope_missing"
    assert (
        pdp.decide(
            _request(args={"body": "opaque payload", "url": "https://api.acme.test/x"})
        ).decision
        == "allow"
    )
    assert (
        pdp.decide(
            _request(tool="email.send", args={"to": ["a@acme.test", "b@example.net"]})
        ).reason
        == "external_recipient"
    )


def test_policy_hlc_scalar_delta_and_unknown_signer() -> None:
    auth = Authority("root")
    store = PolicyStore("n", {"root": auth.public_key})
    hlc = HybridLogicalClock(10_000_000_000_000, 0, "n")
    assert hlc.tick().counter >= hlc.counter
    assert hlc.merge(HybridLogicalClock(hlc.wall_ms, hlc.counter, "m")).counter > hlc.counter
    scalar = Operation("scalar-1", "scalar", "epoch", "*", "deny", 0, hlc, "root")
    scalar = scalar.with_signature(auth.private_key.sign(scalar.canonical_bytes()))
    assert store.apply(scalar)
    assert store.delta_since(set())
    stranger = Authority("stranger")
    bad = stranger.sign_rule("*", "*", "allow")
    assert not store.apply(bad)


def test_identity_error_paths_and_tls_contexts(tmp_path: Path) -> None:
    pki = EdgePKI()
    with pytest.raises(ValueError):
        pki.create_site("bad/site")
    with pytest.raises(ValueError):
        pki.issue_svid("sjc", "bad/agent")
    svid = pki.issue_svid("sjc", "agent", dns_names=("localhost",))
    other = EdgePKI()
    assert other.validate_svid(svid.cert_pem, svid.chain_pem).reason == "wrong_root"
    assert not pki.validate_svid(svid.cert_pem, ()).ok
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    ca = tmp_path / "ca.pem"
    cert.write_bytes(svid.cert_pem + svid.chain_pem[0])
    key.write_bytes(svid.key_pem)
    ca.write_bytes(svid.chain_pem[-1])
    assert tls_server_context(cert, key, ca).minimum_version.name == "TLSv1_3"
    assert tls_client_context(cert, key, ca).minimum_version.name == "TLSv1_3"


def test_simulator_partition_heal_and_loss_branch() -> None:
    auth = Authority("root")
    stores = [PolicyStore(f"n{i}", {"root": auth.public_key}) for i in range(4)]
    sim = Simulator(stores, seed=3)
    sim.partition([{"n0", "n1"}, {"n2", "n3"}])
    sim.inject("n0", auth.sign_rule("*", "http.get", "allow"))
    sim.gossip_round(fanout=2, loss=1.0)
    assert not sim.converged()
    sim.heal()
    assert sim.run_until_converged(fanout=3, max_rounds=10).converged


def test_stats_error_and_edge_branches() -> None:
    assert wilson(0, 0).high == 1.0
    with pytest.raises(ValueError):
        wilson(2, 1)
    with pytest.raises(ValueError):
        quantile([], 0.5)
    with pytest.raises(ValueError):
        quantile([1.0], 2.0)
    assert mean_t_ci([1.0]).point == 1.0
    with pytest.raises(ValueError):
        mean_t_ci([])
    with pytest.raises(ValueError):
        bootstrap_quantile_ci([], 0.5)
    assert bootstrap_quantile_ci([1.0, 2.0], 0.5, resamples=5).point == 1.5


def test_pdp_identity_trust_and_policy_edge_branches() -> None:
    pdp = EdgePDP()
    assert pdp.decide(_request(agent={"spiffe_id": "not-a-spiffe"})).reason == "wrong_trust_domain"
    assert (
        pdp.decide(_request(tool="secrets.get", agent={"trust_history": []})).reason == "low_trust"
    )
    assert (
        EdgePDP(trust_threshold=0.0)
        .decide(_request(agent={"trust_history": ["nonsense", "benign"]}))
        .decision
        == "allow"
    )
    for state, reason in {
        "missing": "spiffe_missing",
        "forged": "signature_invalid",
        "revoked": "revoked",
        "other": "invalid_svid",
    }.items():
        assert pdp.decide(_request(agent={"svid": state})).reason == reason
    auth = Authority("root")
    store = PolicyStore("n", {"root": auth.public_key})
    store.apply(auth.sign_rule("spiffe://acme.test/*", "http.get", "deny"))
    assert EdgePDP(store).decide(_request()).reason == "deny_rule"


def test_pdp_real_certificate_validation_branch() -> None:
    pki = EdgePKI()
    svid = pki.issue_svid("edge", "agent")
    agent = {"cert_pem": svid.cert_pem, "chain_pem": svid.chain_pem}
    assert EdgePDP(pki=pki).decide(_request(agent=agent)).decision == "allow"
    other = EdgePKI()
    assert EdgePDP(pki=other).decide(_request(agent=agent)).reason == "wrong_root"


def test_bench_cli_import() -> None:
    import zero_trust_edge_agent_mesh.bench_cli as bench_cli

    assert callable(bench_cli.main)
