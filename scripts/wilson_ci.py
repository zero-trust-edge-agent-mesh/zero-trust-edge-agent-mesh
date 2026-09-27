from __future__ import annotations

import argparse
import json

from zero_trust_edge_agent_mesh.stats import wilson


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("k", type=int)
    p.add_argument("n", type=int)
    a = p.parse_args(argv)
    print(json.dumps(wilson(a.k, a.n).as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
