from __future__ import annotations

from pathlib import Path

import pytest


def test_pdp_does_not_contain_benchmark_generator_markers() -> None:
    generator = pytest.importorskip("zero_trust_agent_benchmark.generator")
    source_dir = Path(__file__).resolve().parents[1] / "src" / "zero_trust_edge_agent_mesh"
    enforcement_files = [source_dir / "pdp.py", source_dir / "adapter.py"]
    source = "\n".join(path.read_text(encoding="utf-8") for path in enforcement_files).lower()
    shortcut_markers = {
        "extra_payload",
        "hidden directive",
        "raw_generation",
        "reasoning_tokens",
        "tool_description",
        "<|end|>",
        "<|start|>",
        "<start_of_turn>",
        "http.post",
        "pytest",
        "AKIA",
        "ghp_",
        "sk_live_",
        'agent.get("role")',
        "HIGH_RISK =",
        "brace",
        "template_id",
        "trace_id ==",
        "trace_id.startswith",
        "metadata.get",
        "malicious",
        "acme.test/collect",
    }
    generator_owned = {
        token
        for token in generator.literal_tokens()
        if (
            token in shortcut_markers
            or token.startswith(("benign_", "atk-"))
            or "template" in token
            or token in {"assistant-to-tool", "chat-template", "parser-confusing", "zero-width"}
        )
    }
    forbidden = {marker.lower() for marker in shortcut_markers} | generator_owned
    assert sorted(marker for marker in forbidden if marker in source) == []
