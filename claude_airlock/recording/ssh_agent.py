"""The door to the SSH agent (CLAUDE_AIRLOCK_SSH_AGENT=1), with each
use of it noted.

The agent signs as the user towards every host their keys reach, and says
nothing of it. So the session is not given the agent's socket but one of
the launcher's own, which notes every request: which key was asked to
sign, and what for. It passes on the two a session has a use for, to list
the keys and to sign with one, and answers the rest itself with a refusal:
an agent can also be asked to add a key, to remove them all or to lock
itself, none of which is a session's to ask. It lives as long as the
launcher does, a session that outlives its launcher is left without an
agent.

The uses go to the record of doors.py."""

from __future__ import annotations

import base64
import enum
import hashlib
import os
import socket
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress

from ..docker import env_arg, mount_arg
from ..errors import Fatal
from ..files import private_dir
from ..reader import Cursor, NotThis
from ..sandbox.runtime import Runtime
from ..settings import Host, Settings
from .doors import BY_LAUNCHER, AgentUse, Door, SessionUses

# The connections a session can have to the agent at once, and the seconds
# one can stay open with nothing asked. Each takes a thread and two
# descriptors of the launcher: without a bound a session could use them
# all up, and with them what else the launcher does while it runs, the
# copy of its transcript for one (see recorder.py).
AGENT_CONNECTIONS = 16
AGENT_IDLE = 120.0
# The longest message an agent takes, as OpenSSH has it
AGENT_LONGEST = 256 * 1024
# No more of a name is kept in the record than this, a key's comment or
# what a session says a signature is for
MOST_NAMED = 200


class AgentMessage(enum.IntEnum):
    """What a message to or from an SSH agent is, by the number it starts
    with (draft-ietf-sshm-ssh-agent)."""

    FAILURE = 5
    LIST = 11
    # The answer to LIST
    IDENTITIES = 12
    SIGN = 13
    ADD = 17
    REMOVE = 18
    REMOVE_ALL = 19
    ADD_SMARTCARD = 20
    REMOVE_SMARTCARD = 21
    LOCK = 22
    UNLOCK = 23
    ADD_CONSTRAINED = 25
    ADD_SMARTCARD_CONSTRAINED = 26
    # By its name, see SESSION_BIND
    EXTENSION = 27


# What else an agent can be asked than to list its keys and to sign
AGENT_REQUESTS: dict[int, str] = {
    AgentMessage.ADD: "asked to add a key",
    AgentMessage.REMOVE: "asked to remove a key",
    AgentMessage.REMOVE_ALL: "asked to remove every key",
    AgentMessage.ADD_SMARTCARD: "asked to add a smartcard key",
    AgentMessage.REMOVE_SMARTCARD: "asked to remove a smartcard key",
    AgentMessage.LOCK: "asked to lock the agent",
    AgentMessage.UNLOCK: "asked to unlock the agent",
    AgentMessage.ADD_CONSTRAINED: "asked to add a key",
    AgentMessage.ADD_SMARTCARD_CONSTRAINED: "asked to add a smartcard key",
}
# The extension that is passed on is how ssh tells the agent which host it
# signs for: not a use of a key, and not noted.
SESSION_BIND = b"session-bind@openssh.com"
# In what is signed to log in, the message that asks for it
USERAUTH_REQUEST = 50
# Where the session finds the agent
AGENT_TARGET = "/tmp/ssh-agent.sock"
# Where Docker Desktop on macOS has the host's agent, inside its machine
MACOS_AGENT = "/run/host-services/ssh-auth.sock"


def fingerprint(key: bytes) -> str:
    """A public key the way ssh-add -l names it."""
    digest = base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def text(reader: Cursor) -> bytes:
    """The next string of an agent message: its length, then its bytes."""
    return reader.take(reader.number(4))


def named(name: bytes) -> str:
    """A name the agent or a session gave, the start of it: a session's
    can be as long as a request, and every one is kept in the record."""
    return name.decode("utf-8", "replace")[:MOST_NAMED]


def signed_for(data: bytes) -> str:
    """What a signature was asked for, from what was to be signed: a
    login says as whom, a signature of a file (a git commit) says for
    what. Anything else is not told apart."""
    try:
        if data.startswith(b"SSHSIG"):
            return f"a signature for {named(text(Cursor(data, 6)))}"
        reader = Cursor(data)
        text(reader)  # what the two ends agreed on, which names the session
        if reader.number(1) != USERAUTH_REQUEST:
            raise NotThis
        return f"a login as {named(text(reader))}"
    except NotThis:
        return "a signature"


def kind_of(message: bytes) -> int:
    """The number a message starts with, which says what it is, see
    AgentMessage. An empty one is none of them."""
    return message[0] if message else 0


def passed_on(request: bytes) -> bool:
    """Whether a request is one the agent is asked on a session's behalf:
    to list the keys, to sign, and the extension that goes with signing.
    Anything else would change the agent for the user and everything else
    that uses it."""
    kind = kind_of(request)
    if kind in (AgentMessage.LIST, AgentMessage.SIGN):
        return True
    if kind != AgentMessage.EXTENSION:
        return False
    try:
        return text(Cursor(request, 1)) == SESSION_BIND
    except NotThis:
        return False


class AgentDoor:
    """A socket that passes what it may (see passed_on) on to the SSH agent,
    refuses the rest and notes each request. One connection at a time is
    one request at a time: the agent answers each before it reads the
    next."""

    def __init__(self, host: Host, session: str, agent: str) -> None:
        self._uses = SessionUses(host, session, Door.SSH_AGENT)
        self._agent = agent
        # The comment of each key the agent has listed, by its fingerprint
        self._comments: dict[str, str] = {}
        self._free = threading.BoundedSemaphore(AGENT_CONNECTIONS)
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
        # Shut first: closing alone leaves _serve waiting in accept
        with suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        with suppress(OSError):
            os.unlink(self.path)
        self._uses.close()

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                # Closed, the session has ended
                return
            if not self._free.acquire(blocking=False):
                # Too many at once, see AGENT_CONNECTIONS: ssh takes this
                # for an agent that is not there
                client.close()
                continue
            # Only for what the session is waited on, the agent takes
            # the time its user does to confirm
            client.settimeout(AGENT_IDLE)
            threading.Thread(
                target=self._serve_one, args=(client,), daemon=True
            ).start()

    def _serve_one(self, client: socket.socket) -> None:
        try:
            self._pass_on(client)
        finally:
            self._free.release()

    def _pass_on(self, client: socket.socket) -> None:
        with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as agent:
            try:
                agent.connect(self._agent)
                while True:
                    request = read_message(client)
                    if request is None:
                        return
                    if not passed_on(request):
                        refusal = bytes([AgentMessage.FAILURE])
                        self._note(request, refusal, refused_by=BY_LAUNCHER)
                        client.sendall(len(refusal).to_bytes(4, "big") + refusal)
                        continue
                    agent.sendall(len(request).to_bytes(4, "big") + request)
                    answer = read_message(agent)
                    if answer is None:
                        return
                    self._note(request, answer)
                    client.sendall(len(answer).to_bytes(4, "big") + answer)
            except OSError:
                return

    def _note(self, request: bytes, answer: bytes, refused_by: str = "") -> None:
        """Note a request and how it was answered, by the agent unless
        refused_by names who refused it instead. What a session sends is
        the session's to choose: one that is not what it says it is is
        noted as that."""
        kind = kind_of(request)
        refused = kind_of(answer) == AgentMessage.FAILURE
        said: dict[str, object] = {"refused": True} if refused else {}
        if refused_by:
            said["by"] = refused_by
        try:
            if kind == AgentMessage.SIGN:
                reader = Cursor(request, 1)
                key = fingerprint(text(reader))
                said.update(
                    did=AgentUse.SIGN.value,
                    key=key,
                    comment=self._comments.get(key, ""),
                    what=signed_for(text(reader)),
                )
            elif kind == AgentMessage.LIST:
                said.update(did=AgentUse.LIST.value, keys=self._listed(answer))
            elif kind == AgentMessage.EXTENSION:
                if not refused_by:
                    return
                said.update(did=AgentUse.OTHER.value, what="asked for an extension")
            else:
                said.update(
                    did=AgentUse.OTHER.value,
                    what=AGENT_REQUESTS.get(kind, f"sent request {kind}"),
                )
        except NotThis:
            said.update(
                did=AgentUse.OTHER.value, what="sent a request that could not be read"
            )
        try:
            self._uses.note(str(said["did"]), **said)
        except OSError:
            # A full disk or the like: the agent goes on without the note
            return

    def _listed(self, answer: bytes) -> int:
        """How many keys the agent listed, their comments remembered."""
        if kind_of(answer) != AgentMessage.IDENTITIES:
            return 0
        reader = Cursor(answer, 1)
        count = reader.number(4)
        for _ in range(min(count, 1000)):
            key = fingerprint(text(reader))
            self._comments[key] = named(text(reader))
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


def agent_socket(
    env: Mapping[str, str], platform: str = sys.platform
) -> tuple[str, bool] | None:
    """The agent's socket as the daemon finds it and whether the launcher
    can listen in front of it, none without an agent. On macOS the daemon
    runs in a machine of its own, where no socket of the host can be
    mounted, the agent's or ours. Docker Desktop exposes the host's agent
    at a fixed path inside that machine: a path of the machine's, which
    the host does not have and cannot check."""
    if platform == "darwin":
        return MACOS_AGENT, False
    if env.get("SSH_AUTH_SOCK"):
        return env["SSH_AUTH_SOCK"], True
    return None


def refuse_unreachable_agent(
    settings: Settings, env: Mapping[str, str], runtime: Runtime
) -> None:
    """Refuse a session that asks for the SSH agent under a runtime that
    cannot connect to sockets of the host. Without this, ssh in the
    session would only report that it has no agent."""
    if runtime.no_host_sockets and settings.ssh_agent and agent_socket(env):
        raise Fatal(
            f"the SSH agent cannot be reached under {runtime.shown}:"
            f" {runtime.no_host_sockets}, see docs/sandbox.md."
            " CLAUDE_AIRLOCK_SSH_AGENT=0 runs without the agent."
        )


@contextmanager
def ssh_agent_door(
    settings: Settings, host: Host, session: str, env: Mapping[str, str]
) -> Iterator[list[str]]:
    """Forward the SSH agent for as long as a session runs, opt-in with
    CLAUDE_AIRLOCK_SSH_AGENT=1: the agent lets the container authenticate
    as you to every host your keys reach, not only the git remote. Loading
    keys with ssh-add -c makes each use ask first. Gives the options the
    session is run with. What the session is given is a socket of the
    launcher's that notes each request and refuses those that are not a
    session's to make (see passed_on), the agent's own where that is not
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
                f"claude-airlock: the use of the SSH agent is not recorded: {problem}",
                file=sys.stderr,
            )
    mount = (
        mount_arg(door.path, AGENT_TARGET, "z")
        if door
        else mount_arg(
            agent, AGENT_TARGET, "z" if can_listen else "", daemons=not can_listen
        )
    )
    try:
        yield [
            mount,
            env_arg("SSH_AUTH_SOCK", AGENT_TARGET),
            # Shown by bin/claude-statusline
            env_arg("CLAUDE_AIRLOCK_SSH_AGENT", 1),
        ]
    finally:
        if door:
            door.close()
