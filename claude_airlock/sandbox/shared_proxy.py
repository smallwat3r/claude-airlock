"""What the two proxies the sessions share have in common: how one is
started, and how one started from something else is told."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass

from ..docker import (
    NO_NEW_PRIVILEGES,
    container_label,
    container_running,
    docker_must,
    docker_ok,
    mount_arg,
)
from ..files import private_dir
from ..settings import Host

# A hash of what a proxy sidecar was started from, so one started from
# something else (an edited rule, another image) is noticed and replaced
SIDECAR_CONFIG_LABEL = "claude-airlock.config"
# How many processes a shared proxy can have, a bound on one gone wrong
PROXY_PIDS = 512


@dataclass(frozen=True)
class SharedProxy:
    """A proxy that sessions share, as it is to be started: its name, the
    network it starts on, its image, what it reads of the launcher's
    checkout (by where it reads each file) and its other options."""

    name: str
    network: str
    image: str
    files: Mapping[str, bytes]
    options: tuple[str, ...] = ()

    @property
    def config(self) -> str:
        """The hash of what it is started from, but for its network: a
        proxy joins the networks of other sessions after it starts."""
        digest = hashlib.sha256()
        files = (part for item in self.files.items() for part in item)
        for part in (self.image, *files, *self.options):
            data = part.encode() if isinstance(part, str) else part
            digest.update(len(data).to_bytes(8, "big") + data)
        return digest.hexdigest()[:16]

    def current(self) -> bool:
        """Running, and started from what this one would be."""
        if not container_running(self.name):
            return False
        return container_label(self.name, SIDECAR_CONFIG_LABEL) == self.config

    def start(self, host: Host) -> None:
        """(Re)create it, labelled with its config. It reads copies of its
        files as they are here, see ProxyFiles."""
        docker_ok("rm", "--force", self.name)
        copies = ProxyFiles(host, self.name)
        kept = copies.keep(self.files)
        docker_must(
            "run",
            "--detach",
            f"--name={self.name}",
            f"--network={self.network}",
            # Should it die under its sessions. Not for longer than those:
            # it is removed with the last of them, see session_network.
            "--restart=on-failure",
            f"--label={SIDECAR_CONFIG_LABEL}={self.config}",
            # Nothing it runs gains what it was not started with, and one
            # gone wrong does not fill the host with processes. Its
            # capabilities are left as its image expects them, but where
            # its options take them away: squid starts as root and gives
            # its workers a user of their own, the socket proxy needs none.
            NO_NEW_PRIVILEGES,
            f"--pids-limit={PROXY_PIDS}",
            *(mount_arg(kept.copy(target), target, "ro,z") for target in self.files),
            *self.options,
            self.image,
        )
        copies.drop_all_but(kept)


@dataclass(frozen=True)
class KeptFiles:
    """A directory of the copies a proxy was started from."""

    path: str

    def copy(self, target: str) -> str:
        """The copy of the file the proxy reads at target."""
        return os.path.join(self.path, os.path.basename(target))


class ProxyFiles:
    """The copies of the checkout's files the proxies of a name are
    started from, with the launcher's records. A proxy is not given the
    checkout's own: a session that can write the checkout would change
    its rules while it runs, and the proxy reads them again without being
    replaced (squid starts its helpers anew on each rotation of its log, a
    restart renders the rules of the socket proxy again)."""

    def __init__(self, host: Host, name: str) -> None:
        self._top = os.path.join(host.proxy_files_dir, name)

    def keep(self, files: Mapping[str, bytes]) -> KeptFiles:
        """A new directory of copies, each under the name it has where the
        proxy reads it. Never written to once made, and readable by all:
        the proxy reads them as a user of its own, and the launcher's
        state directory above them keeps everyone else on the host out."""
        kept = KeptFiles(tempfile.mkdtemp(dir=private_dir(self._top)))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        for target, content in files.items():
            with os.fdopen(os.open(kept.copy(target), flags, 0o600), "wb") as file:
                file.write(content)
                # Read by the proxy's user, whatever the umask made of it
                os.fchmod(file.fileno(), 0o444)
        return kept

    def drop_all_but(self, kept: KeptFiles) -> None:
        """Remove the copies earlier proxies of the name were started
        from, whose containers are gone. Best effort, what is left is
        removed on the next start."""
        for entry in os.listdir(self._top):
            path = os.path.join(self._top, entry)
            if path != kept.path:
                shutil.rmtree(path, ignore_errors=True)
