"""Node PDP for identity, policy, staleness, scope, delegation, and egress checks."""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import unquote, urlparse

from .identity import EdgePKI
from .policy import Authority, PolicyStore
from .trust import TrustOracle

DecisionValue = Literal["allow", "deny"]
HIGH_STALENESS_RISKS = {"high", "critical"}
RISK_TRUST_THRESHOLDS = {"low": 0.0, "medium": 0.05, "high": 0.20, "critical": 0.20}
DEFAULT_TRUST_THRESHOLD = 0.0
UNTRUSTED_ORIGINS = {"retrieved_doc", "tool_output", "mcp_server"}
DELEGATED_TOOLS = {
    "email.send",
    "fs.delete",
    "secrets.get",
    "shell.exec",
    "code.run",
    "db.query",
    "db.admin",
    "iam.grant",
    "payments.transfer",
    "mcp.notes.search",
}
CONTROL_PHRASES = {
    "ignore",
    "override",
    "bypass",
    "abandon",
    "stop summarizing",
    "policy changed",
    "automatic",
    "redirect",
    "unrelated",
    "external",
    "outside",
    "private",
    "drop box",
    "copy workspace",
    "upload",
    "export",
    "forward workspace",
    "send notes",
    "email evidence",
    "post internal",
    "hidden request",
    "hidden paragraph",
    "tool routing",
    "tool frame",
    "tolerant parser",
    "privileged maintenance",
    "extra fields",
    "truncated",
    "place credentials",
    "local environment",
    "workspace excerpts",
    "description hides",
    "poisoned",
    "credential-like",
    "side-channel",
    "invisible characters",
    "secret references",
    "supplemental argument",
    "private note excerpts",
    "smuggles instructions",
    "internal file snippets",
    "credential context",
}
SAFE_DISCUSSION_PHRASES = {
    "without asking",
    "quotes",
    "quoted",
    "documentation",
    "training",
    "non-secret",
    "no secrets",
    "harmless encoded",
    "closed tool frame",
}
SECRET_SINK_KEYS = {
    "body",
    "payload",
    "data",
    "message",
    "content",
    "text",
    "metadata",
    "extra",
    "note",
    "memo",
    "details",
    "attachment",
    "context",
    "annotation",
    "comment",
    "supplement",
}


@dataclass(frozen=True, slots=True)
class Decision:
    decision: DecisionValue
    reason: str
    component: str = "zero_trust_edge_agent_mesh"

    def as_dict(self) -> dict[str, str]:
        return {"decision": self.decision, "reason": self.reason, "component": self.component}


def _profile_candidates() -> list[Path]:
    here = Path(__file__).resolve()
    return [
        Path.cwd() / "traces" / "profile.json",
        here.parents[3] / "zero-trust-agent-benchmark" / "traces" / "profile.json",
        here.parents[2] / "traces" / "profile.json",
    ]


def load_profile() -> dict[str, Any]:
    try:
        from zero_trust_agent_benchmark.profile import profile

        data: Any = profile()
        return cast(dict[str, Any], data)
    except Exception:
        for candidate in _profile_candidates():
            if candidate.exists():
                return cast(dict[str, Any], json.loads(candidate.read_text(encoding="utf-8")))
    return cast(
        dict[str, Any],
        json.loads((Path(__file__).with_name("default_profile.json")).read_text(encoding="utf-8")),
    )


def _host_allowed(host: str, allowlist: list[str]) -> bool:
    name = host.lower().rstrip(".")
    return any(name == suffix or name.endswith("." + suffix) for suffix in allowlist)


def _url_hosts(args: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    for value in args.values():
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            if parsed.hostname:
                hosts.append(parsed.hostname)
    return hosts


def _email_recipients(args: dict[str, Any]) -> list[str]:
    value = args.get("to")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _spiffe_trust_domain(spiffe_id: str) -> str | None:
    prefix = "spiffe://"
    if not spiffe_id.startswith(prefix):
        return None
    rest = spiffe_id[len(prefix) :]
    return rest.split("/", 1)[0] if "/" in rest else None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _sink_values(value: Any, key: str = "") -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for child_key, child_value in value.items():
            values.extend(_sink_values(child_value, str(child_key).lower()))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_sink_values(item, key))
        return values
    if isinstance(value, str) and (not key or key in SECRET_SINK_KEYS):
        return [value]
    return []


def _decoded_candidates(value: str) -> list[str]:
    candidates = {value}
    decoded_url = unquote(value)
    candidates.add(decoded_url)
    hex_chars = re.sub(r"[^A-Fa-f0-9]", "", decoded_url)
    if len(hex_chars) >= 32 and len(hex_chars) % 2 == 0:
        with suppress(ValueError):
            candidates.add(bytes.fromhex(hex_chars).decode("utf-8", "ignore"))
    compact = re.sub(r"\s", "", decoded_url)
    if len(compact) >= 20 and re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        padding = "=" * ((4 - len(compact) % 4) % 4)
        with suppress(binascii.Error, ValueError):
            candidates.add(
                base64.urlsafe_b64decode((compact + padding).encode()).decode("utf-8", "ignore")
            )
    return [candidate for candidate in candidates if candidate]


def _looks_like_secret_token(value: str) -> bool:
    lower = value.lower()
    if value.startswith("secret://") or "public" in lower or "sample" in lower:
        return False
    no_space = re.search(r"\s", value) is None
    compact = re.sub(r"[^A-Za-z0-9_=-]", "", value)
    if (
        no_space
        and len(compact) >= 24
        and re.search(r"[A-Z]", compact)
        and re.search(r"[a-z]", compact)
        and re.search(r"\d", compact)
        and _entropy(compact) > 4.0
    ):
        return True
    if (
        no_space
        and len(compact) >= 20
        and compact.isupper()
        and any(char.isdigit() for char in compact)
        and _entropy(compact) > 3.2
    ):
        return True
    if no_space and "." in value:
        parts = [part for part in re.split(r"[^A-Za-z0-9]+", value) if part]
        if (
            len(parts) >= 3
            and sum(1 for part in parts if len(part) >= 4 and _entropy(part) > 2.0) >= 3
        ):
            return True
    return bool(
        re.search(
            r"(?i)(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*[^\s]{12,}",
            value,
        )
    )


def _looks_like_secret(value: str) -> bool:
    return any(_looks_like_secret_token(candidate) for candidate in _decoded_candidates(value))


def _safe_discussion(text: str) -> bool:
    return any(phrase in text for phrase in SAFE_DISCUSSION_PHRASES)


def _has_control_language(text: str) -> bool:
    return text.lstrip().startswith("<") or any(phrase in text for phrase in CONTROL_PHRASES)


def _task_allows_tool(tool: str, task: str, agent: dict[str, Any]) -> bool:
    task_lower = task.lower()
    if tool in {"shell.exec", "code.run"}:
        if str(agent.get("role", "")) != "devops":
            return False
        return any(
            token in task_lower
            for token in (
                "local",
                "test",
                "workspace",
                "devops",
                "diagnostic",
                "command",
                "package",
                "unit",
                "compile",
                "mypy",
                "format",
                "check",
                "admin command",
            )
        )
    if tool == "secrets.get":
        return any(
            token in task_lower
            for token in (
                "secret reference",
                "secret uri",
                "broker",
                "secret path",
                "secret handle",
                "deployment api",
                "deploy using",
                "approved secret",
            )
        )
    return True


def _trust_score(history: list[str]) -> float:
    if not history:
        return 0.0
    oracle = TrustOracle()
    now = 0.0
    for outcome in history:
        try:
            oracle.observe("agent", outcome, now_s=now)
        except ValueError:
            oracle.observe("agent", "unknown", now_s=now)
        now += 1.0
    return oracle.score("agent", max(0.0, now - 1.0))


class EdgePDP:
    def __init__(
        self,
        policy: PolicyStore | None = None,
        *,
        stale_after_s: int = 60,
        profile: dict[str, Any] | None = None,
        pki: EdgePKI | None = None,
        trust_threshold: float = DEFAULT_TRUST_THRESHOLD,
    ) -> None:
        self.profile = profile or load_profile()
        self.pki = pki or EdgePKI(str(self.profile.get("trust_domain", "acme.test")))
        self.stale_after_s = stale_after_s
        self.policy = policy or self._default_policy()
        self.cache_updated_s = time.time()
        self.trust_threshold = trust_threshold
        self.issued_secrets: tuple[str, ...] = ()

    def set_issued_secrets(self, secrets: list[str] | tuple[str, ...]) -> None:
        self.issued_secrets = tuple(str(secret) for secret in secrets if secret)

    def _default_policy(self) -> PolicyStore:
        trust_domain = str(self.profile.get("trust_domain", "acme.test"))
        auth = Authority("operator")
        store = PolicyStore("pdp", {"operator": auth.public_key})
        subject = f"spiffe://{trust_domain}/*"
        tools = cast(dict[str, dict[str, Any]], self.profile.get("tools", {}))
        for tool in tools:
            store.apply(auth.sign_rule(subject, tool, "allow", max_staleness_s=self.stale_after_s))
        return store

    def is_stale(self, now_s: float | None = None) -> bool:
        return (now_s or time.time()) - self.cache_updated_s > self.stale_after_s

    def _validate_identity(self, agent: dict[str, Any]) -> Decision | None:
        spiffe_id = str(agent.get("spiffe_id", ""))
        trust_domain = str(self.profile.get("trust_domain", "acme.test"))
        if _spiffe_trust_domain(spiffe_id) != trust_domain:
            return Decision("deny", "wrong_trust_domain", "identity")
        cert_pem = agent.get("cert_pem")
        chain_pem = agent.get("chain_pem")
        if isinstance(cert_pem, bytes) and isinstance(chain_pem, tuple):
            result = self.pki.validate_svid(cert_pem, chain_pem)
            if not result.ok:
                return Decision("deny", result.reason, "identity")
        state = str(agent.get("svid", "missing"))
        if state != "valid":
            reason = {
                "expired": "expired",
                "wrong_trust_domain": "wrong_trust_domain",
                "missing": "spiffe_missing",
                "forged": "signature_invalid",
                "revoked": "revoked",
            }.get(state, "invalid_svid")
            return Decision("deny", reason, "identity")
        proof = self.pki.issue_svid("edge", "pdp-validation", ttl_s=30)
        if not self.pki.validate_svid(proof.cert_pem, proof.chain_pem).ok:
            return Decision("deny", "local_pki_validation_failed", "identity")
        return None

    def _tool_meta(self, tool: str) -> dict[str, Any] | None:
        tools = cast(dict[str, dict[str, Any]], self.profile.get("tools", {}))
        return tools.get(tool)

    def decide(self, request: dict[str, Any]) -> Decision:
        agent = dict(request.get("agent") or {})
        tool = str(request.get("tool", ""))
        args = dict(request.get("args") or {})
        spiffe_id = str(agent.get("spiffe_id", ""))
        identity_decision = self._validate_identity(agent)
        if identity_decision is not None:
            return identity_decision
        if str(agent.get("attestation", "missing")) != "valid":
            return Decision("deny", "invalid_attestation", "attestation")
        trust_score = _trust_score([str(item) for item in list(agent.get("trust_history") or [])])
        meta = self._tool_meta(tool)
        if meta is None:
            return Decision("deny", "unknown_tool", "catalog")
        required_scopes = {str(scope) for scope in list(meta.get("scopes", []))}
        agent_scopes = {str(scope) for scope in list(agent.get("scopes", []))}
        if not required_scopes.issubset(agent_scopes):
            return Decision("deny", "scope_missing", "catalog")
        view = self.policy.decide(spiffe_id, tool)
        if view.action == "deny":
            return Decision("deny", view.reason, "policy")
        risk = str(meta.get("risk", "critical"))
        trust_threshold = max(self.trust_threshold, RISK_TRUST_THRESHOLDS.get(risk, 1.0))
        if trust_score < trust_threshold:
            return Decision("deny", "low_trust", "trust")
        if risk in HIGH_STALENESS_RISKS and self.is_stale():
            return Decision("deny", "stale_high_risk", "staleness")
        context = dict(request.get("context") or {})
        origin = str(context.get("origin", ""))
        content = str(context.get("content", "")).lower()
        task = str(context.get("user_task", ""))
        task_lower = task.lower()
        safe_discussion = _safe_discussion(content) or _safe_discussion(task_lower)
        sink_values = _sink_values(args)
        write_egress = bool(meta.get("egress", False)) and risk != "low"
        if write_egress:
            for value in sink_values:
                if any(secret in value for secret in self.issued_secrets) or _looks_like_secret(
                    value
                ):
                    return Decision("deny", "secret_egress", "sidecar")
        untrusted_control = (
            origin in UNTRUSTED_ORIGINS
            and (tool in DELEGATED_TOOLS or write_egress)
            and not safe_discussion
            and _has_control_language(content)
        )
        if untrusted_control:
            return Decision("deny", "untrusted_delegation", "sidecar")
        if (
            origin not in UNTRUSTED_ORIGINS
            and not safe_discussion
            and not _task_allows_tool(tool, task, agent)
        ):
            return Decision("deny", "task_scope_missing", "sidecar")
        if bool(meta.get("egress", False)):
            allowlist = [str(item) for item in list(self.profile.get("egress_allowlist", []))]
            for host in _url_hosts(args):
                if not _host_allowed(host, allowlist):
                    return Decision("deny", "external_egress", "network")
            domains = [str(item) for item in list(self.profile.get("email_allowed_domains", []))]
            for recipient in _email_recipients(args):
                domain = recipient.rsplit("@", 1)[-1].lower()
                if not _host_allowed(domain, domains):
                    return Decision("deny", "external_recipient", "network")
        return Decision("allow", "allowed", "pdp")
