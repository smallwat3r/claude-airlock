"""What stands for the machine a session runs on, for the checks of
more than one module: the cgroup and the processes a watcher reads of a
session, and what docker info says of the runtimes there are."""

from __future__ import annotations

import json
from pathlib import Path

from claude_airlock.recording import procwatch
from claude_airlock.sandbox import runtime

GIB = 2**30


class FakeSession:
    """What a watcher reads of a session, made up in a directory: the
    cgroup of its container and its processes."""

    def __init__(self, root: Path, cgroup: Path | None = None):
        self.proc = root
        self.first = root / "1"
        # Under the root of the first process, unless another place is given
        self.cgroup = cgroup or self.first / "root" / "sys" / "fs" / "cgroup"
        self.cgroup.mkdir(parents=True)
        (self.first / "root" / "tmp").mkdir(parents=True)
        (self.first / "mounts").write_text(
            "proc /proc proc rw 0 0\n"
            "tmpfs /dev tmpfs rw 0 0\n"
            "tmpfs /sys/fs/cgroup tmpfs ro 0 0\n"
            "tmpfs /tmp tmpfs rw,size=4194304k 0 0\n"
            "overlay / overlay ro 0 0\n"
        )
        self.set("memory.max", str(16 * GIB))
        self.set("pids.max", "512")
        self.set("cpu.max", "150000 100000")
        self.set("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0")
        self.use()

    def set(self, name: str, said: str) -> None:
        (self.cgroup / name).write_text(said + "\n")

    def use(
        self,
        memory: float = 1.0,
        cpu_seconds: float = 0.0,
        throttled_seconds: float = 0.0,
        processes: int = 20,
        waited_for_memory: float = 0.0,
    ) -> None:
        """What the session has used by now: memory in GiB, the rest as
        it has added up since it started."""
        cached = GIB // 4
        self.set("memory.current", str(int(memory * GIB) + cached))
        self.set("memory.stat", f"anon 5\ninactive_file {cached}\nactive_file 7")
        self.set("pids.current", str(processes))
        self.set(
            "cpu.stat",
            f"usage_usec {int(cpu_seconds * 1e6)}\nuser_usec 1\nnr_throttled 3\n"
            f"throttled_usec {int(throttled_seconds * 1e6)}",
        )
        waited = int(waited_for_memory * 1e6)
        self.set("memory.pressure", f"some avg10=0.00 total={waited}\nfull total=0")
        self.set("cpu.pressure", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0")

    def run(self, pid: int, megabytes: int) -> None:
        directory = self.proc / str(pid)
        directory.mkdir(exist_ok=True)
        pages = megabytes * 2**20 // procwatch.PAGE
        (directory / "statm").write_text(f"{pages * 2} {pages} 10 1 0 5 0\n")


HOSTNET = ["--network=host", "--host-uds=open"]


def docker_info(default: str = "runc", **runtimes: list[str] | None) -> str:
    """The answer of docker info to what session_runtime asks: the
    default runtime, then every runtime by name. Each keyword is a runsc
    runtime with the given arguments."""
    listed: dict[str, dict] = {"runc": {"path": "runc"}}
    for name, args in runtimes.items():
        about: dict = {"path": "/usr/local/bin/runsc"}
        if args:
            about["runtimeArgs"] = args
        listed[name.replace("_", "-")] = about
    return f"{json.dumps(default)}\n{json.dumps(listed)}"


INFO = docker_info(runsc=None, runsc_hostnet=HOSTNET)


def gvisor(*args: str, path: str = "/usr/local/bin/runsc") -> runtime.Runtime:
    """The runtime of a runsc registered under the name gv with these
    arguments."""
    return runtime.known_runtime(runtime.Registered("gv", path, args=args))
