from __future__ import annotations

import runpy
from pathlib import Path


def main() -> int:
    script = Path.cwd() / "bench" / "run_bench.py"
    if not script.exists():
        raise FileNotFoundError("bench/run_bench.py must be run from the repository root")
    runpy.run_path(str(script), run_name="__main__")
    return 0


__all__ = ["main"]
