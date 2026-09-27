from __future__ import annotations

import subprocess

import pytest

IMAGES = [
    ("openpolicyagent/opa:1.10.1-static", ["version"]),
    ("hashicorp/vault:1.21", ["version"]),
    ("envoyproxy/envoy:v1.36.2", ["--version"]),
    ("ghcr.io/spiffe/spire-server:1.13.3", ["--help"]),
    ("ghcr.io/spiffe/spire-agent:1.13.3", ["--help"]),
]


@pytest.mark.integration
@pytest.mark.parametrize("image,cmd", IMAGES)
def test_pinned_docker_service_images_run(image: str, cmd: list[str]) -> None:
    result = subprocess.run(
        ["docker", "run", "--rm", image, *cmd],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert result.stdout or result.stderr
