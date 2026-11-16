"""Noting each use of the two doors a session can be given out of the
sandbox: the SSH agent (CLAUDE_DOCKER_SSH_AGENT=1) and the Docker socket
(CLAUDE_DOCKER_SOCKET), for --trace to show.

The agent signs as the user towards every host their keys reach, and says
nothing of it. So the session is not given the agent's socket but one of
the launcher's own, which passes every request on and notes it: which key
was asked to sign, and what for. It lives as long as the launcher does, a
session that outlives its launcher is left without an agent.

The socket proxy logs every call it is asked for, with the address it came
from. While a session runs, the launcher reads that log and notes the
calls of the session's address.

Both go to one file of the launcher's state directory, a line per use,
which names the project and the session."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress

from .docker import env_arg, mount_arg
from .events import Event, Who, clean
from .network import session_address, socket_proxy_name, socket_proxy_options
from .pcap import Cursor, NotThis
from .settings import Host, Settings, private_dir

# The lines kept, the oldest go once there are more
KEPT_USES = 5000
# The longest message an agent takes, as OpenSSH has it
AGENT_LONGEST = 256 * 1024
AGENT_FAILURE = 5
AGENT_LIST = 11
AGENT_IDENTITIES = 12
AGENT_SIGN = 13
# What else an agent can be asked, by the number of the request
AGENT_REQUESTS = {
    17: "asked to add a key",
    18: "asked to remove a key",
    19: "asked to remove every key",
    20: "asked to add a smartcard key",
    21: "asked to remove a smartcard key",
    22: "asked to lock the agent",
    23: "asked to unlock the agent",
    25: "asked to add a key",
    26: "asked to add a smartcard key",
}
# An extension, which is how ssh tells the agent which host it signs for.
# Not a use of a key, and not noted.
AGENT_EXTENSION = 27
# In what is signed to log in, the message that asks for it
USERAUTH_REQUEST = 50
# Where the session finds the agent
AGENT_TARGET = "/tmp/ssh-agent.sock"
MACOS_AGENT = "/run/host-services/ssh-auth.sock"
# A line of the socket proxy's log (HAProxy's httplog): the address and
# port it came from, then further on the status and, quoted, the request
_PROXY_LINE = re.compile(
    r"^(?P<address>[0-9a-fA-F.:]+):\d+ \[[^\]]*\] \S+ \S+ \S+ (?P<status>\d{3}) .*"
    r'"(?P<method>[A-Z]+) (?P<path>\S+)'
)


def note_use(host: Host, project: str, session: str, door: str, **said: object) -> None:
    """Add a use of a door to the record, and let go of the oldest lines
    past KEPT_USES. Under a lock, launchers of other sessions write here
    too."""
    line = json.dumps(
        {
            "t": round(time.time(), 3),
            "project": project,
            "session": session,
            "door": door,
            **said,
        }
    )
    private_dir(host.state_dir)
    descriptor = os.open(host.doors_file, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a+", encoding="utf-8", errors="replace") as record:
        fcntl.flock(record, fcntl.LOCK_EX)
        record.write(line + "\n")
        record.flush()
        record.seek(0)
        lines = record.readlines()
        if len(lines) > KEPT_USES:
            record.truncate(0)
            record.writelines(lines[-KEPT_USES:])


def read_uses(host: Host, start: float, end: float) -> list[dict]:
    """The uses of a door by this project's sessions between two times,
    in the order they were noted."""
    found = []
    try:
        with open(host.doors_file, encoding="utf-8", errors="replace") as record:
            for line in record:
                try:
                    said = json.loads(line)
                    when = float(said["t"])
                except (ValueError, KeyError, TypeError, RecursionError):
                    continue
                if said.get("project") == host.project_dir and start <= when <= end:
                    found.append(said)
    except OSError:
        return []
    return found


def fingerprint(key: bytes) -> str:
    """A public key the way ssh-add -l names it."""
    digest = base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def text(reader: Cursor) -> bytes:
    """The next string of an agent message: its length, then its bytes."""
    return reader.take(reader.number(4))


def signed_for(data: bytes) -> str:
    """What a signature was asked for, from what was to be signed: a
    login says as whom, a signature of a file (a git commit) says for
    what. Anything else is not told apart."""
    try:
        if data.startswith(b"SSHSIG"):
            namespace = text(Cursor(data, 6)).decode("utf-8", "replace")
            return f"a signature for {namespace}"
        reader = Cursor(data)
        text(reader)  # what the two ends agreed on, which names the session
        if reader.number(1) != USERAUTH_REQUEST:
            raise NotThis
        return f"a login as {text(reader).decode('utf-8', 'replace')}"
    except NotThis:
        return "a signature"


class AgentDoor:
    """A socket that passes what it is asked on to the SSH agent and notes
    each request. One connection at a time is one request at a time: the
    agent answers each before it reads the next."""

    def __init__(self, host: Host, session: str, agent: str) -> None:
        self._host = host
        self._session = session
        self._agent = agent
        # The comment of each key the agent has listed, by its fingerprint
        self._comments: dict[str, str] = {}
        directory = private_dir(host.agent_sockets_dir)
        # A short name: the path of a socket cannot be long
        name = hashlib.sha256(session.encode()).hexdigest()[:12]
        self.path = os.path.join(directory, f"{name}-{os.getpid()}.sock")
        with suppress(FileNotFoundError):
            os.unlink(self.path)
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._listener.bind(self.path)
            os.chmod(self.path, 0o600)
            self._listener.listen(8)
        except OSError:
            self._listener.close()
            raise
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._listener.close()
        with suppress(OSError):
            os.unlink(self.path)

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                # Closed, the session has ended
                return
            threading.Thread(target=self._pass_on, args=(client,), daemon=True).start()

    def _pass_on(self, client: socket.socket) -> None:
        with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as agent:
            try:
                agent.connect(self._agent)
                while True:
                    request = read_message(client)
                    if request is None:
                        return
                    agent.sendall(len(request).to_bytes(4, "big") + request)
                    answer = read_message(agent)
                    if answer is None:
                        return
                    self._note(request, answer)
                    client.sendall(len(answer).to_bytes(4, "big") + answer)
            except OSError:
                return

    def _note(self, request: bytes, answer: bytes) -> None:
        """Note a request and how the agent answered it. What a session
        sends is the session's to choose: one that is not what it says it
        is is noted as that."""
        kind = request[:1]
        refused = answer[:1] == bytes([AGENT_FAILURE])
        said: dict[str, object] = {"refused": True} if refused else {}
        try:
            if kind == bytes([AGENT_SIGN]):
                reader = Cursor(request, 1)
                key = fingerprint(text(reader))
                said.update(
                    did="sign",
                    key=key,
                    comment=self._comments.get(key, ""),
                    what=signed_for(text(reader)),
                )
            elif kind == bytes([AGENT_LIST]):
                said.update(did="list", keys=self._listed(answer))
            elif kind == bytes([AGENT_EXTENSION]):
                return
            else:
                number = kind[0] if kind else 0
                said.update(
                    did="other",
                    what=AGENT_REQUESTS.get(number, f"sent request {number}"),
                )
        except NotThis:
            said.update(did="other", what="sent a request that could not be read")
        try:
            note_use(
                self._host, self._host.project_dir, self._session, "ssh-agent", **said
            )
        except OSError:
            # A full disk or the like: the agent goes on without the note
            return

    def _listed(self, answer: bytes) -> int:
        """How many keys the agent listed, their comments remembered."""
        if answer[:1] != bytes([AGENT_IDENTITIES]):
            return 0
        reader = Cursor(answer, 1)
        count = reader.number(4)
        for _ in range(min(count, 1000)):
            key = fingerprint(text(reader))
            self._comments[key] = text(reader).decode("utf-8", "replace")[:200]
        return count


def read_message(connection: socket.socket) -> bytes | None:
    """The next message of the agent protocol on a connection, without
    its length, none when the other end is done or sends what is not
    one."""
    header = read_exactly(connection, 4)
    if header is None:
        return None
    length = int.from_bytes(header, "big")
    if not 0 < length <= AGENT_LONGEST:
        return None
    return read_exactly(connection, length)


def read_exactly(connection: socket.socket, count: int) -> bytes | None:
    data = b""
    while len(data) < count:
        more = connection.recv(count - len(data))
        if not more:
            return None
        data += more
    return data


def agent_socket(env: Mapping[str, str]) -> tuple[str, bool] | None:
    """The agent's socket on the host and whether the launcher can listen
    in front of it, none without an agent. Docker Desktop on macOS exposes
    the host's agent at a fixed path inside its machine, where the host's
    SSH_AUTH_SOCK is not mountable, and neither is a socket of ours."""
    if sys.platform == "darwin" and os.path.exists(MACOS_AGENT):
        return MACOS_AGENT, False
    if env.get("SSH_AUTH_SOCK"):
        return env["SSH_AUTH_SOCK"], True
    return None


@contextmanager
def ssh_agent_door(
    settings: Settings, host: Host, session: str, env: Mapping[str, str]
) -> Iterator[list[str]]:
    """Forward the SSH agent for as long as a session runs, opt-in with
    CLAUDE_DOCKER_SSH_AGENT=1: the agent lets the container authenticate
    as you to every host your keys reach, not only the git remote. Loading
    keys with ssh-add -c makes each use ask first. Gives the options the
    session is run with. What the session is given is a socket of the
    launcher's that notes each request, the agent's own where that is not
    possible, which is then said."""
    found = agent_socket(env) if settings.ssh_agent else None
    if found is None:
        yield []
        return
    agent, can_listen = found
    door = None
    if can_listen:
        try:
            door = AgentDoor(host, session, agent)
        except OSError as problem:
            print(
                f"claude-docker: the use of the SSH agent is not recorded: {problem}",
                file=sys.stderr,
            )
    mount = (
        mount_arg(door.path, AGENT_TARGET, "z")
        if door
        else mount_arg(agent, AGENT_TARGET, "z" if can_listen else "")
    )
    try:
        yield [
            mount,
            env_arg("SSH_AUTH_SOCK", AGENT_TARGET),
            # Shown by bin/claude-statusline
            env_arg("CLAUDE_DOCKER_SSH_AGENT", 1),
        ]
    finally:
        if door:
            door.close()


def parse_proxy_call(line: str) -> tuple[str, str, str, int] | None:
    """The address, method, path and status of a line of the socket
    proxy's log, none for a line that is not a request."""
    found = _PROXY_LINE.match(line.strip())
    if not found:
        return None
    return (
        found["address"],
        found["method"],
        found["path"],
        int(found["status"]),
    )


class SocketWatch:
    """Reads the socket proxy's log while a session runs and notes the
    calls that came from the session's address."""

    def __init__(self, host: Host, session: str, owner: str, proxy: str) -> None:
        self._host = host
        self._session = session
        self._owner = owner
        self._proxy = proxy
        self._stop = threading.Event()
        # From when the calls are read: the log is only followed once the
        # session has an address, a moment after it started
        self._since = int(time.time())
        self._log: subprocess.Popen | None = None
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        # Give the last calls of the session the moment it takes to read them
        self._thread.join(timeout=1.0)
        if self._log and self._log.poll() is None:
            self._log.terminate()
        self._thread.join()

    def _watch(self) -> None:
        # The address is only known once the container is up
        while not (address := session_address(self._owner)):
            if self._stop.wait(0.2):
                return
        try:
            self._log = subprocess.Popen(
                ["docker", "logs", "--follow", f"--since={self._since}", self._proxy],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
        except OSError:
            return
        with self._log:
            for line in self._log.stdout or ():
                call = parse_proxy_call(line)
                if call is None or call[0] != address:
                    continue
                _, method, path, status = call
                try:
                    note_use(
                        self._host,
                        self._host.project_dir,
                        self._session,
                        "docker",
                        method=method,
                        path=path,
                        status=status,
                    )
                except OSError:
                    continue


@contextmanager
def socket_proxy_watched(
    settings: Settings, host: Host, session: str, owner: str
) -> Iterator[None]:
    """While a session with a way to the Docker socket runs, note the
    calls it makes. owner is the container whose address the session has
    on its network: itself, or its capture sidecar."""
    if socket_proxy_options(settings) is None:
        yield
        return
    watch = SocketWatch(host, session, owner, socket_proxy_name(settings))
    try:
        yield
    finally:
        watch.close()


def use_event(said: dict) -> Event | None:
    """A use of a door as an event, none for a line that is not one. The
    record is the launcher's own, what it holds was still chosen by a
    session: it is cleaned like the rest."""
    when, door = float(said["t"]), said.get("door")
    refused = bool(said.get("refused"))
    if door == "ssh-agent":
        did = said.get("did")
        if did == "sign":
            comment = f" ({said['comment']})" if said.get("comment") else ""
            detail = f"signed {said.get('what', 'something')} with {said.get('key')}{comment}"
            if refused:
                detail = "asked for " + detail[len("signed ") :]
        elif did == "list":
            detail = f"listed the keys, {said.get('keys', 0)} of them"
        else:
            detail = str(said.get("what", "sent a request"))
        fields = {
            key: said[key]
            for key in ("did", "key", "comment", "what", "keys")
            if key in said
        }
        if refused:
            detail += "  REFUSED by the agent"
            fields["error"] = "refused by the agent"
        return Event(when, Who.SANDBOX, "ssh-agent", [clean(detail)], fields)
    if door == "docker":
        status = said.get("status")
        denied = status == 403
        detail = f"{said.get('method')} {said.get('path')} {status}"
        fields = {
            "method": said.get("method"),
            "path": said.get("path"),
            "status": status,
            "denied": denied,
        }
        if denied:
            detail += "  DENIED"
        return Event(when, Who.SANDBOX, "docker", [clean(detail)], fields)
    return None


def door_events(host: Host, start: float, end: float) -> tuple[list[str], list[Event]]:
    """What this project's sessions did through the doors between two
    times, as summary lines and as events."""
    events = [event for event in map(use_event, read_uses(host, start, end)) if event]
    by_door = Counter(event.what for event in events)
    lines = []
    if by_door["ssh-agent"]:
        signed = sum(
            event.fields.get("did") == "sign" and "error" not in event.fields
            for event in events
        )
        lines.append(
            f"ssh agent   {by_door['ssh-agent']} requests, {signed} signatures"
        )
    if by_door["docker"]:
        denied = sum(bool(event.fields.get("denied")) for event in events)
        lines.append(
            f"docker      {by_door['docker']} calls"
            + (f", {denied} DENIED" if denied else "")
        )
    return lines, events
