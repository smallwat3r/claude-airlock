"""What is left of the project's names of before its rename, when it was
claude-sandbox with a claude-docker command: a user who has not moved on
is served as before and told of each name that changed. The settings
under their old names are read in settings.py, see renamed there."""

from __future__ import annotations

import dataclasses
import os

from .settings import LEGACY_COMMAND, LEGACY_NAME, NAME, Fatal, Host


def adopt_legacy_dirs(host: Host, told: list[str]) -> Host:
    """The host with what the launcher kept under its old name taken
    over, told gets a line for each."""
    move_state(host, told)
    return legacy_config(host, told)


def move_state(host: Host, told: list[str]) -> None:
    """Move the launcher's records from where they were before the rename,
    once, and leave a link there: a session that runs across the move
    still writes to the old place, as would an older checkout."""
    old, new = host.legacy_state_dir, host.state_dir
    if os.path.lexists(new) or os.path.islink(old) or not os.path.isdir(old):
        return
    try:
        os.rename(old, new)
    except FileNotFoundError:
        # Another launcher moved it first
        return
    except OSError as problem:
        raise Fatal(f"the records in {old} could not be moved to {new}: {problem}")
    try:
        os.symlink(NAME, old)
    except OSError:
        # Without the link the records are still all in the new place
        pass
    told.append(f"the records of {old} are now in {new}")


def legacy_config(host: Host, told: list[str]) -> Host:
    """The host with the user's config directory of before the rename as
    its own, when that is the one the user has. It is theirs to move, it
    may be kept with their dotfiles."""
    new = host.user_conf
    old = os.path.join(host.config_home, LEGACY_NAME)
    if os.path.lexists(new) or not os.path.isdir(old):
        return host
    told.append(f"{old} is read for now, rename it to {new}")
    return dataclasses.replace(host, config_name=LEGACY_NAME)


def legacy_command(program: str, told: list[str]) -> None:
    """A line in told when the launcher was started under its old name."""
    if os.path.basename(program) == LEGACY_COMMAND:
        told.append(f"{LEGACY_COMMAND} is now {NAME}, the old name works for now")
