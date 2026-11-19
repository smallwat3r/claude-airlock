"""The container runtime of a session (CLAUDE_AIRLOCK_RUNTIME), and how a
session differs under it.

Docker reports which runtimes the daemon has, as registered in
/etc/docker/daemon.json. The launcher treats most of them like Docker's
own runtime, which is what the Runtime class describes. A runtime that
needs different handling is a subclass of Runtime that overrides what
differs. The rest of the launcher calls the methods of Runtime and never
checks which runtime it has. To support another runtime, add a subclass
and list it in KNOWN.

gVisor (runsc) is the one subclass so far. It runs a session on its own
kernel, in user space, so a session cannot exploit a flaw in the host's
kernel. This has four consequences for the launcher:

- A sidecar that joins the session sees gVisor's kernel process, not the
  session's processes. The watcher of processes.py is therefore not
  started, and the launcher records memory and CPU use from the host
  instead (see host_health.py).
- The cgroup of the container counts gVisor's own threads, so the process
  limit given to Docker is raised to make room for them.
- A session that reaches its process or memory limit is ended as a whole,
  because the host's kernel sees a single program, gVisor.
- With gVisor's own network stack, which is its default, the session
  cannot reach Docker's resolver and no name resolves. Registering the
  runtime with --network=host makes it use the host's network stack. The
  session still has its own network namespace, and everything in
  network.py works, but the host kernel's network stack is exposed to the
  session again. Connecting to a socket of the host, such as the SSH
  agent's, also needs --host-uds=open (or all)."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import ClassVar

from .docker import docker_output
from .settings import Settings


@dataclass(frozen=True)
class Registered:
    """A runtime as registered in the daemon: its program, its type when it
    is a containerd shim, and its arguments. The arguments are None when
    they are not visible, which is the case for a shim, because a shim
    keeps them in its own configuration file."""

    name: str
    path: str = ""
    shim: str = ""
    args: tuple[str, ...] | None = None

    @classmethod
    def read(cls, name: str, said: object) -> Registered:
        """One entry of the runtimes listed by docker info."""
        about = said if isinstance(said, dict) else {}
        path = str(about.get("path") or "")
        args = about.get("runtimeArgs") or []
        return cls(
            name,
            path,
            str(about.get("runtimeType") or ""),
            tuple(map(str, args)) if path and isinstance(args, list) else None,
        )

    def flag(self, name: str) -> str | None:
        """The value of a command-line flag among the arguments, or None
        when it is absent or the arguments are not visible. Go programs
        accept -name=value, --name=value, and the value as the next
        argument. The last occurrence wins."""
        args = self.args or ()
        found = None
        for at, arg in enumerate(args):
            word, equals, value = arg.lstrip("-").partition("=")
            if not arg.startswith("-") or word != name:
                continue
            if equals:
                found = value
            elif at + 1 < len(args):
                found = args[at + 1]
        return found


@dataclass(frozen=True)
class Runtime:
    """A container runtime. This class describes Docker's own runtime and
    is used for every runtime the launcher has no subclass for. A subclass
    overrides what differs for a session under it."""

    # The name shown to the user for a runtime the launcher knows
    KIND: ClassVar[str] = ""
    # Whether a sidecar that joins a session can see the session's
    # processes, which the watcher of processes.py needs
    JOINABLE: ClassVar[bool] = True

    name: str = ""

    @classmethod
    def recognise(cls, registered: Registered) -> Runtime | None:
        """This runtime when a registered runtime is one of its kind,
        otherwise None."""
        return None

    @property
    def shown(self) -> str:
        """The runtime as named to the user."""
        if not self.KIND:
            return self.name or "docker's own runtime"
        return f"{self.KIND} ({self.name})"

    @property
    def no_host_sockets(self) -> str:
        """The reason a session cannot connect to a socket of the host.
        Empty when it can, or when the launcher cannot tell."""
        return ""

    def process_limit(self, limit: str) -> str:
        """The process limit to give Docker so that a session can have as
        many processes of its own as the setting says."""
        return limit

    def notes(self, settings: Settings) -> list[str]:
        """What a session lacks under this runtime compared with Docker's
        own, to be said at launch. Usually nothing."""
        if not settings.proc_log or self.JOINABLE:
            return []
        unrecorded = (
            "processes are not recorded, nor which process made each"
            " connection. Only memory and CPU use are recorded"
        )
        return [unrecorded]


@dataclass(frozen=True)
class Gvisor(Runtime):
    """gVisor, recognised by its program, runsc. Its registered arguments
    say which network stack it uses and whether it can reach the sockets
    of the host. When the arguments are not visible, the launcher assumes
    the runtime is set up correctly."""

    KIND: ClassVar[str] = "gVisor"
    JOINABLE: ClassVar[bool] = False
    PROGRAM: ClassVar[str] = "runsc"
    # How many of the host's process slots gVisor uses for itself, and for
    # each process of the session. gVisor does not report these numbers.
    # They are estimates, rounded up from counts on one machine with
    # gVisor's systrap platform: 36 for an idle session, 250 with 100
    # sleeping processes, 653 with 300. Idle threads within one process
    # cost almost nothing: 300 of them added 3. CLAUDE_AIRLOCK_PIDS is the
    # setting to raise when the estimate is too low for a workload.
    OWN_SLOTS: ClassVar[int] = 64
    SLOTS_PER_PROCESS: ClassVar[int] = 2
    # The values of --host-uds that allow connecting to a socket of the host
    OPEN_SOCKETS: ClassVar[tuple[str, ...]] = ("open", "all")

    registered: Registered = Registered("")

    @classmethod
    def recognise(cls, registered: Registered) -> Gvisor | None:
        program = os.path.basename(registered.path)
        if cls.PROGRAM in program or cls.PROGRAM in registered.shim:
            return cls(registered.name, registered)
        return None

    @property
    def _args_visible(self) -> bool:
        return self.registered.args is not None

    @property
    def own_network_stack(self) -> bool:
        """Whether the session uses gVisor's network stack, in which no
        name resolves."""
        return self._args_visible and self.registered.flag("network") != "host"

    @property
    def no_host_sockets(self) -> str:
        allowed = self.registered.flag("host-uds") in self.OPEN_SOCKETS
        if self._args_visible and not allowed:
            return "the runtime is registered without --host-uds=open"
        return ""

    def process_limit(self, limit: str) -> str:
        # Docker reads anything that is not a positive number itself
        if not limit.isdigit() or int(limit) == 0:
            return limit
        return str(self.OWN_SLOTS + self.SLOTS_PER_PROCESS * int(limit))

    def notes(self, settings: Settings) -> list[str]:
        notes = []
        if self.own_network_stack:
            notes.append(
                "names do not resolve, because the runtime uses gVisor's own"
                " network stack. Register it with --network=host, see"
                " docs/sandbox.md"
            )
        notes.append(
            "the session is ended as a whole when it reaches its memory or"
            " process limit, and the process limit is an estimate"
        )
        return notes + super().notes(settings)


# The runtimes that need their own handling. The first that recognises a
# registered runtime is used.
KNOWN: tuple[type[Runtime], ...] = (Gvisor,)
# Docker's own runtime
DOCKERS_OWN = Runtime()
_RUNTIMES = '--format={{json .DefaultRuntime}}{{"\\n"}}{{json .Runtimes}}'


def known_runtime(registered: Registered) -> Runtime:
    """A registered runtime as the launcher handles it. A runtime that no
    class in KNOWN recognises is handled like Docker's own."""
    for kind in KNOWN:
        runtime = kind.recognise(registered)
        if runtime:
            return runtime
    return Runtime(registered.name)


def session_runtime(settings: Settings) -> Runtime:
    """The runtime a session with these settings runs under: the one set
    in CLAUDE_AIRLOCK_RUNTIME, otherwise the daemon's default. When the
    daemon does not list it, or does not answer, the runtime is handled
    like Docker's own and Docker reports any error."""
    default, _, listed = docker_output("info", _RUNTIMES).partition("\n")
    try:
        name = settings.runtime or str(json.loads(default))
        runtimes = json.loads(listed)
        return known_runtime(Registered.read(name, runtimes[name]))
    except (ValueError, KeyError, TypeError):
        return Runtime(settings.runtime)


def say_runtime_notes(runtime: Runtime, settings: Settings) -> None:
    """Print the runtime's notes before the session starts. Once it runs,
    the terminal belongs to the session."""
    notes = runtime.notes(settings)
    if notes:
        print(
            f"claude-airlock: under {runtime.shown}:",
            *(f"  {note}" for note in notes),
            sep="\n",
            file=sys.stderr,
        )
