"""Zero Trust Agent Benchmark adapter."""

from __future__ import annotations

import time
from typing import Any

from .pdp import EdgePDP


class DefenseAdapter:
    """In-process defense with the decide(request) contract used by Zero Trust Agent Benchmark."""

    def __init__(self, pdp: EdgePDP | None = None) -> None:
        self.pdp = pdp or EdgePDP()
        self._issued_by_trace: dict[str, tuple[str, ...]] = {}

    def reset(self) -> None:
        self.pdp.cache_updated_s = time.time()
        self.pdp.set_issued_secrets(())

    def on_trace_start(self, meta: dict[str, Any]) -> bool:
        trace_key = str(meta.get("trace_id", ""))
        secrets = tuple(str(secret) for secret in list(meta.get("issued_secrets") or []) if secret)
        self._issued_by_trace[trace_key] = secrets
        return True

    def decide(self, request: dict[str, Any]) -> dict[str, str]:
        self.pdp.set_issued_secrets(self._issued_by_trace.get(str(request.get("trace_id", "")), ()))
        return self.pdp.decide(request).as_dict()


def defense() -> DefenseAdapter:
    return DefenseAdapter()
