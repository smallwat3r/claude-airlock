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
import socket
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from ..docker import env_arg, mount_arg
from ..errors import Fatal
from ..notice import warn
from ..reader import Cursor, NotThis
from ..sandbox.runtime import Runtime
from ..settings import Host, Settings, variable
from .doors import BY_LAUNCHER, AgentUse, Door, SessionUses
from .unix_socket import PrivateSocket

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


# What the agent, or the launcher in its place, answers a request it
# refuses
REFUSAL = bytes([AgentMessage.FAILURE])


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
AGENT_TARGET = "/tmp/ssh-agent.sock"  # noqa: S108, in the session's own tmpfs
# Where Docker Desktop on macOS has the host's agent, inside its machine
MACOS_AGENT = "/run/host-services/ssh-auth.sock"


def fingerprint(key: bytes) -> str:
    """A public key the way ssh-add -l names it."""
    digest = base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def text(reader: Cursor) -> bytes:
    """The next string of an agent message: its length, then its bytes."""
    return reader.take(reader.number(4))


def _named(name: bytes) -> str:
    """A name the agent or a session gave, the start of it: a session's
    can be as long as a request, and every one is kept in the record."""
    return name.decode("utf-8", "replace")[:MOST_NAMED]


def _signed_for(data: bytes) -> str:
    """What a signature was asked for, from what was to be signed: a
    login says as whom, a signature of a file (a git commit) says for
    what. Anything else is not told apart."""
    try:
        if data.startswith(b"SSHSIG"):
            return f"a signature for {_named(text(Cursor(data, 6)))}"
        reader = Cursor(data)
        text(reader)  # what the two ends agreed on, which names the session
        if reader.number(1) != USERAUTH_REQUEST:
            raise NotThis
        return f"a login as {_named(text(reader))}"
    except NotThis:
        return "a signature"


def _kind_of(message: bytes) -> int:
    """The number a message starts with, which says what it is, see
    AgentMessage. An empty one is none of them."""
    return message[0] if message else 0


def _passed_on(request: bytes) -> bool:
    """Whether a request is one the agent is asked on a session's behalf:
    to list the keys, to sign, and the extension that goes with signing.
    Anything else would change the agent for the user and everything else
    that uses it."""
    kind = _kind_of(request)
    if kind in (AgentMessage.LIST, AgentMessage.SIGN):
        return True
    if kind != AgentMessage.EXTENSION:
        return False
    try:
        return text(Cursor(request, 1)) == SESSION_BIND
    except NotThis:
        return False


class AgentDoor:
    """A socket that passes what it may (see _passed_on) on to the SSH agent,
    refuses the rest and notes each request. One connection at a time is
    one request at a time: the agent answers each before it reads the
    next."""

    def __init__(self, host: Host, session: str, agent: str) -> None:
        self._uses = SessionUses(host, session, Door.SSH_AGENT)
        self._agent = agent
        # The comment of each key the agent has listed, by its fingerprint
        self._comments: dict[str, str] = {}
        self._free = threading.BoundedSemaphore(AGENT_CONNECTIONS)
        # Why a request could not be noted and was refused for it, the
        # last of them, empty when they all were
        self._unnoted = ""
        self._listener = PrivateSocket(
            host.agent_sockets_dir, session, socket.SOCK_STREAM, 8
        )
        self.path = self._listener.path
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._listener.close()
        self._uses.close()
        if self._unnoted:
            warn(
                "the SSH agent was refused to the session for some of what it"
                " asked, the record of its use could not be written:"
                f" {self._unnoted}"
            )

    def _serve(self) -> None:
        # Until it is closed, the session has ended
        while (client := self._listener.accept()) is not None:
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
                    request = read_message(client, AGENT_IDLE)
                    if request is None:
                        return
                    refused_by = "" if _passed_on(request) else BY_LAUNCHER
                    answer = REFUSAL
                    if not refused_by:
                        agent.sendall(_framed(request))
                        answered = read_message(agent)
                        if answered is None:
                            return
                        answer = answered
                    try:
                        self._note(request, answer, refused_by)
                    except OSError as problem:
                        # Not given what could not be noted: a session
                        # can fill the disk the record is on, and would
                        # have its signatures unrecorded for it. Said
                        # when the door is closed
                        self._unnoted = str(problem)
                        answer = REFUSAL
                    client.sendall(_framed(answer))
            except OSError:
                return

    def _note(self, request: bytes, answer: bytes, refused_by: str = "") -> None:
        """Note a request and how it was answered, by the agent unless
        refused_by names who refused it instead. What a session sends is
        the session's to choose: one that is not what it says it is is
        noted as that. Raises OSError when the record cannot be written,
        a full disk or the like."""
        kind = _kind_of(request)
        refused = _kind_of(answer) == AgentMessage.FAILURE
        said: dict[str, object] = {}
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
                    what=_signed_for(text(reader)),
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
        self._uses.note(str(said["did"]), refused=refused, **said)

    def _listed(self, answer: bytes) -> int:
        """How many keys the agent listed, their comments remembered."""
        if _kind_of(answer) != AgentMessage.IDENTITIES:
            return 0
        reader = Cursor(answer, 1)
        count = reader.number(4)
        for _ in range(min(count, 1000)):
            key = fingerprint(text(reader))
            self._comments[key] = _named(text(reader))
        return count


def _framed(message: bytes) -> bytes:
    """A message of the agent protocol as it is sent, after its length."""
    return len(message).to_bytes(4, "big") + message


def read_message(
    connection: socket.socket, within: float | None = None
) -> bytes | None:
    """The next message of the agent protocol on a connection, without
    its length, none when the other end is done or sends what is not
    one. Within that many seconds when given, from the first byte to the
    last, else TimeoutError: a time for each read alone would keep a
    connection that sends a byte now and then open for good."""
    until = None if within is None else time.monotonic() + within
    before = connection.gettimeout() if until is not None else None
    try:
        header = _read_exactly(connection, 4, until)
        if header is None:
            return None
        length = int.from_bytes(header, "big")
        if not 0 < length <= AGENT_LONGEST:
            return None
        return _read_exactly(connection, length, until)
    finally:
        if until is not None:
            connection.settimeout(before)


def _read_exactly(
    connection: socket.socket, count: int, until: float | None
) -> bytes | None:
    """So many bytes of a connection, none when it ends first, before the
    time on the monotonic clock that until says, if any. Into one buffer
    as they come: a session that sends a byte at a time would otherwise
    have each copied again with every one after it."""
    data = bytearray(count)
    view = memoryview(data)
    got = 0
    while got < count:
        if until is not None:
            left = until - time.monotonic()
            if left <= 0:
                raise TimeoutError("the message took too long to come")
            connection.settimeout(left)
        more = connection.recv_into(view[got:])
        if not more:
            return None
        got += more
    return bytes(data)


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
    session's to make (see _passed_on). The agent's own only where no
    socket of the host can be listened on for it, on macOS, as the docs
    say: where one can and that fails, the session is not started."""
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
            # Not the agent's own socket in its place: that one takes
            # what the door refuses, keys added and removed, and notes
            # nothing
            raise Fatal(
                f"the SSH agent cannot be given to the session, the launcher"
                f" could not listen in front of it: {problem}."
                " CLAUDE_AIRLOCK_SSH_AGENT=0 runs without the agent."
            ) from problem
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
            # Said in docker/CLAUDE-airlock.md
            env_arg(variable("ssh_agent"), 1),
        ]
    finally:
        if door:
            door.close()
