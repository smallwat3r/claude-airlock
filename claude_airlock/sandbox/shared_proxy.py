"""What the two proxies the sessions share have in common: how one is
started, and how one started from something else is told."""

from __future__ import annotations

import hashlib

from ..docker import (
    NO_NEW_PRIVILEGES,
    container_label,
    container_running,
    docker_must,
    docker_ok,
)

# A hash of what a proxy sidecar was started from, so one started from
# something else (an edited rule, another image) is noticed and replaced
SIDECAR_CONFIG_LABEL = "claude-airlock.config"
# How many processes a shared proxy can have, a bound on one gone wrong
PROXY_PIDS = 512


def proxy_current(name: str, config: str) -> bool:
    """Running, and started from the config of that hash."""
    if not container_running(name):
        return False
    return container_label(name, SIDECAR_CONFIG_LABEL) == config


def start_shared_proxy(
    name: str, network: str, config: str, options: list[str], image: str
) -> None:
    """(Re)create a proxy that sessions share on a network, labelled with
    the hash of what it is started from."""
    docker_ok("rm", "--force", name)
    docker_must(
        "run",
        "--detach",
        f"--name={name}",
        f"--network={network}",
        # Should it die under its sessions. Not for longer than those: it
        # is removed with the last of them, see session_network.
        "--restart=on-failure",
        f"--label={SIDECAR_CONFIG_LABEL}={config}",
        # Nothing it runs gains what it was not started with, and one
        # gone wrong does not fill the host with processes. Its
        # capabilities are left as its image expects them.
        NO_NEW_PRIVILEGES,
        f"--pids-limit={PROXY_PIDS}",
        *options,
        image,
    )


def config_hash(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big") + part)
    return digest.hexdigest()[:16]
