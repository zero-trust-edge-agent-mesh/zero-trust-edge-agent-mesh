from __future__ import annotations

import time

import pytest

from zero_trust_edge_agent_mesh.identity import EdgePKI
from zero_trust_edge_agent_mesh.pdp import EdgePDP
from zero_trust_edge_agent_mesh.policy import Authority, PolicyStore
from zero_trust_edge_agent_mesh.simulator import Simulator


def _req(
    tool: str = "http.get", args: dict[str, object] | None = None, **ctx: object
) -> dict[str, object]:
    return {
        "trace_id": "m",
        "step": 0,
        "agent": {
            "agent_id": "a",
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
        "tool": tool,
        "args": args or {"url": "https://api.acme.test/x"},
        "context": {
            "origin": "user",
            "content": str(ctx.get("content", "ok")),
            "reasoning_tokens": int(ctx.get("tokens", 5)),
            "user_task": str(ctx.get("user_task", "Run a local workspace check.")),
            **({"raw_generation": ctx["raw"]} if "raw" in ctx else {}),
            **({"tool_description": ctx["tool_description"]} if "tool_description" in ctx else {}),
        },
        "history": [],
    }


@pytest.mark.parametrize(
    "site", ["sjc", "sfo", "lon", "iad", "bom", "syd", "fra", "nrt", "gru", "jnb"]
)
def test_many_site_svids_validate(site: str) -> None:
    pki = EdgePKI()
    svid = pki.issue_svid(site, "agent")
    assert pki.validate_svid(svid.cert_pem, svid.chain_pem, expected_site=site).ok


@pytest.mark.parametrize("tool", ["shell.exec", "payments.transfer", "iam.grant", "db.admin"])
def test_high_risk_tools_without_required_scopes_are_denied(tool: str) -> None:
    assert EdgePDP().decide(_req(tool=tool, args={"cmd": "local-check"})).reason == "scope_missing"


@pytest.mark.parametrize("tool", ["fs.delete", "secrets.get"])
def test_high_risk_tools_with_scopes_and_trust_are_allowed(tool: str) -> None:
    user_task = (
        "Use the approved secret reference for deployment."
        if tool == "secrets.get"
        else "Run a local workspace check."
    )
    assert (
        EdgePDP()
        .decide(_req(tool=tool, args={"path": "/workspace/file"}, user_task=user_task))
        .decision
        == "allow"
    )


def test_devops_scoped_execution_tools_are_allowed_without_command_matching() -> None:
    req = _req(
        tool="shell.exec",
        args={"cmd": "opaque local operation"},
        user_task="Run a local workspace diagnostic command.",
    )
    agent = dict(req["agent"])
    agent["scopes"] = [*agent["scopes"], "shell:exec", "code:exec"]
    agent["role"] = "devops"
    req["agent"] = agent
    assert EdgePDP().decide(req).decision == "allow"
    req["tool"] = "code.run"
    assert EdgePDP().decide(req).decision == "allow"


@pytest.mark.parametrize(
    "host",
    [
        "collector.example.net",
        "sink.invalid",
        "updates.example.net",
        "evil.test",
        "acme.test.example",
    ],
)
def test_external_hosts_denied(host: str) -> None:
    assert EdgePDP().decide(_req(args={"url": f"https://{host}/x"})).reason == "external_egress"


@pytest.mark.parametrize(
    "host", ["acme.test", "api.acme.test", "docs.acme.test", "events.acme.test", "kb.acme.test"]
)
def test_internal_hosts_allowed(host: str) -> None:
    assert EdgePDP().decide(_req(args={"url": f"https://{host}/x"})).decision == "allow"


@pytest.mark.parametrize(
    "recipient",
    ["a@example.net", "case@sink.invalid", "ops@evil.test", "x@y.z", "team@acme.test.example"],
)
def test_external_recipients_denied(recipient: str) -> None:
    assert (
        EdgePDP().decide(_req(tool="email.send", args={"to": recipient})).reason
        == "external_recipient"
    )


@pytest.mark.parametrize(
    "recipient", ["ops@acme.test", "team-1@acme.test", "audit@acme.test", "a@acme.test"]
)
def test_internal_recipients_allowed(recipient: str) -> None:
    assert EdgePDP().decide(_req(tool="email.send", args={"to": recipient})).decision == "allow"


@pytest.mark.parametrize(
    "body",
    ["opaque credential text", "quoted control-token training sample", "partial frame example"],
)
def test_content_payload_is_out_of_scope_for_edge_pdp(body: str) -> None:
    assert (
        EdgePDP().decide(_req(args={"body": body, "url": "https://api.acme.test/x"})).decision
        == "allow"
    )


@pytest.mark.parametrize("tokens", [0, 1, 7])
def test_reasoning_token_count_is_out_of_scope(tokens: int) -> None:
    decision = EdgePDP().decide(_req(content="untrusted content sample", tokens=tokens))
    assert decision.reason == "allowed"


@pytest.mark.parametrize(
    "scope_tool",
    ["http.get", "http.post", "email.send", "fs.write", "mcp.notes.search", "db.query"],
)
def test_policy_default_deny_when_policy_attached(scope_tool: str) -> None:
    auth = Authority("root")
    store = PolicyStore("n", {"root": auth.public_key})
    assert EdgePDP(store).decide(_req(tool=scope_tool)).reason == "default_deny"


@pytest.mark.parametrize("idx", range(12))
def test_policy_allow_globs(idx: int) -> None:
    auth = Authority("root")
    store = PolicyStore("n", {"root": auth.public_key})
    store.apply(auth.sign_rule(f"spiffe://acme.test/site/s{idx}/*", "http.get", "allow"))
    assert store.decide(f"spiffe://acme.test/site/s{idx}/agent/a", "http.get").action == "allow"
    assert store.decide("spiffe://acme.test/site/other/agent/a", "http.get").action == "deny"


@pytest.mark.parametrize("seed", range(15))
def test_simulator_converges_many_seeds(seed: int) -> None:
    auth = Authority("root")
    stores = [PolicyStore(f"n{i}", {"root": auth.public_key}) for i in range(12)]
    sim = Simulator(stores, seed=seed)
    sim.inject("n0", auth.sign_rule("spiffe://acme.test/site/*", "http.get", "allow"))
    assert sim.run_until_converged(fanout=3, loss=0.0, max_rounds=20).converged


@pytest.mark.parametrize("age", [0, 10, 61, 300])
def test_staleness_boundary(age: int) -> None:
    pdp = EdgePDP(stale_after_s=60)
    pdp.cache_updated_s = time.time() - age
    dec = pdp.decide(_req(tool="email.send", args={"to": "ops@acme.test"}))
    assert dec.reason == ("stale_high_risk" if age > 60 else "allowed")
