"""What is watched of the config the sandboxed sessions share, the
.claude.json of their ~/.claude: the servers it starts and what else of
it steers every later session of every project, as entries of a
fingerprint (see shared_config_hashes), compared by tampered.py."""

from __future__ import annotations

import json
from collections.abc import Iterator

from ..files import NotRead, json_object, read_plain
from .bounded import file_stamp, sha256_hex

# The servers of the config the sandboxed sessions share, by this name
# wherever in it they are: those of every project, and those of each
SERVERS = "mcpServers"
# No more of that config is read than this, it is a session's to write
SERVERS_BYTES = 16 * 1024 * 1024
# What else at the top of that config every later sandboxed session of
# every project takes from it: the environment Claude Code gives itself,
# as a user's settings would (a proxy, the address of the API, a script
# every shell runs first), whether Remote Control starts with a session
# (and the earlier name of that, which Claude Code turns into it), and
# the API keys it takes without asking. The last two by what they are
# said as once they changed. Each in the fingerprint as the config with
# what it is, next to the hash of the servers, which stays what it was
# without them.
SHARED_ENVIRONMENT = "env"
SHARED_STEERING = (
    ("Remote Control", ("remoteControlAtStartup", "replBridgeEnabled")),
    ("the API keys", ("customApiKeyResponses", "primaryApiKey")),
)
# How an entry of the environment is named in the fingerprint, after the
# config, and how many of them are each named by their variable: the rest
# go together, as do variables of longer names, which a session can make
# as long as the file is, and an environment that is no object
ENVIRONMENT_NAMED = "the environment, "
ENVIRONMENT_REST = "the rest of the environment"
# What comes between the config and what each is in the name of such an
# entry, see shared_part
_SHARED_PART = ": "
MOST_ENVIRONMENT_NAMED = 100
LONGEST_ENVIRONMENT_NAME = 200


def _servers_in(value: object, at: tuple[str, ...] = ()) -> Iterator[tuple[str, str]]:
    """Every set of servers a config holds, at whatever depth: where it
    is and what it says. Not one that names no server, which is what a
    project that was only run in the sandbox has."""
    if not isinstance(value, dict):
        return
    for key, inner in value.items():
        if key == SERVERS:
            if inner:
                yield "/".join(at), json.dumps(inner, sort_keys=True)
        else:
            yield from _servers_in(inner, (*at, str(key)))


def shared_config_hashes(config: str) -> dict[str, str]:
    """What is watched of the config the sandboxed sessions share, as
    entries of a fingerprint: the hash of the servers it starts (see
    _servers_in) by the path of the config, and by the config with what
    each is, the hashes of the rest of what steers them, see
    _steering_hashes. Of nothing else in it: the rest is rewritten by
    every session. The file is a session's to write, so one that is not
    a plain file says so, and one too large or too odd to read is told
    from one written since as file_stamp does, with nothing more of it."""
    content = read_plain(config, SERVERS_BYTES)
    if content is NotRead.ABSENT:
        return {config: "absent"}
    if content is NotRead.UNREADABLE:
        return {config: "unreadable"}
    held = None if isinstance(content, NotRead) else json_object(content)
    if held is None:
        return {config: "not read: " + file_stamp(config)}
    try:
        said = sorted(_servers_in(held))
        steering = _steering_hashes(held)
    except (ValueError, RecursionError):
        return {config: "not read: " + file_stamp(config)}
    hashes = {config: sha256_hex(json.dumps(said).encode())}
    return hashes | {
        _shared_entry(config, part): hashed for part, hashed in steering.items()
    }


def _shared_entry(config: str, part: str) -> str:
    """The entry of a fingerprint for a part of what steers the sandboxed
    sessions in the config they share, see shared_part."""
    return f"{config}{_SHARED_PART}{part}"


def shared_part(config: str, path: str) -> str | None:
    """What of the config the sandboxed sessions share an entry of a
    fingerprint is (see shared_config_hashes): empty for its servers, the
    entry by the config's own path, what steers them for one of
    _steering_hashes, none for an entry of something else."""
    if path == config:
        return ""
    prefix = config + _SHARED_PART
    return path.removeprefix(prefix) if path.startswith(prefix) else None


def _value_hash(value: object) -> str:
    """Hash of a value of a config as JSON, the same however its keys
    are ordered. Raises ValueError or RecursionError for one nested too
    deep to write."""
    return sha256_hex(json.dumps(value, sort_keys=True).encode())


def _steering_hashes(held: dict) -> dict[str, str]:
    """Hashes of what at the top of the config the sandboxed sessions
    share steers them, by what each is (see SHARED_STEERING), of those
    it holds alone: one without any of them has none, and is hashed as
    a config of before they were watched. The environment by each of
    its variables, so that a change says which, no more of them than
    MOST_ENVIRONMENT_NAMED and none of a name longer than
    LONGEST_ENVIRONMENT_NAME, the rest together."""
    hashes: dict[str, str] = {}
    environment = held.get(SHARED_ENVIRONMENT, {})
    if not isinstance(environment, dict):
        environment = {"": environment}
    rest = {}
    for name in sorted(environment):
        if len(hashes) < MOST_ENVIRONMENT_NAMED and (
            0 < len(name) <= LONGEST_ENVIRONMENT_NAME
        ):
            hashes[ENVIRONMENT_NAMED + name] = _value_hash(environment[name])
        else:
            rest[name] = environment[name]
    if rest:
        hashes[ENVIRONMENT_REST] = _value_hash(rest)
    for part, keys in SHARED_STEERING:
        values = {key: held[key] for key in keys if key in held}
        if values:
            hashes[part] = _value_hash(values)
    return hashes
