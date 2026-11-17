"""The command line: the launcher's own options, then one session from
start to finish."""

from __future__ import annotations

import contextlib
import dataclasses
import os
import sys
import time
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from .capture import CaptureSidecar, session_captured
from .chat import CHAT_ARGS, Handover, Sandbox, chat
from .claude_args import has_a_conversation, resumed_args
from .digest import report_session
from .docker import docker_ok
from .doors import socket_proxy_watched, ssh_agent_door
from .egress_log import net_log
from .ending import Ending, ending_passed_on, interrupts_held
from .follow import follow
from .history import history_args
from .home import prepare_home, protect_config_args
from .image import PLUGIN_DIR, Image, build_image, prepare_image, prune_images
from .login import login_shared
from .mounts import (
    ExtraDir,
    add_extra_dir,
    configured_extra_dirs,
    extra_dir_args,
    protect_args,
    protect_env_args,
    protected_dirs,
    refuse_unsafe_dir,
    shadow_args,
)
from .network import (
    network_args,
    session_address_recorded,
    session_network,
    sidecars_locked,
    socket_proxy_args,
    start_egress_proxy,
)
from .processes import Watcher, processes_recorded
from .recorder import transcripts_copied
from .session import (
    base_args,
    container_name,
    git_config_args,
    permission_args,
    run_session,
    session_args,
)
from .settings import (
    Fatal,
    Host,
    Settings,
    detect_host,
    load_settings,
    settings_help,
)
from .tamper import (
    host_exec_fingerprint,
    report_tampering,
    report_unchecked_sessions,
    save_pending_check,
)
from .trace import trace


def parse_args(argv: list[str]) -> tuple[str, list[str], list[tuple[str, bool]]]:
    """Take the launcher's own options out of argv. Returns the action
    (run, help, shell, line-mode, rebuild, prune, dockerfile, net-log, net-reload
    or trace), the arguments left for claude, and the directories asked for
    with --add-dir and --add-dir-ro, each with whether it is read-only."""
    action = "run"
    claude_args: list[str] = []
    added: list[tuple[str, bool]] = []
    actions = (
        "--help",
        "--rebuild",
        "--prune",
        "--dockerfile",
        "--shell",
        "--line-mode",
        "--net-log",
        "--net-reload",
        "--trace",
    )
    args = iter(argv)
    for arg in args:
        option, has_value, value = arg.partition("=")
        if arg == "-h":
            action = "help"
        elif arg in actions:
            action = arg[2:]
        elif option in ("--add-dir", "--add-dir-ro"):
            if not has_value:
                following = next(args, None)
                if following is None:
                    raise Fatal(f"{option} requires a path")
                value = following
            added.append((value, option == "--add-dir-ro"))
        else:
            claude_args.append(arg)
    return action, claude_args, added


def main(argv: list[str], usage: str = "") -> int:
    action, claude_args, added = parse_args(argv)
    if action == "help":
        # Ahead of the settings: a config file that is refused is one of
        # the things the text is asked about
        print(usage.strip() + "\n\n" + settings_help())
        return 0
    env = os.environ
    host = detect_host(env)
    settings = load_settings(env, os.path.join(host.user_conf, "config"))

    # What needs neither the image nor the directories of a session
    if action == "net-log":
        return net_log()
    if action == "trace":
        following = "--follow" in claude_args
        return (follow if following else trace)(host, claude_args)
    if action == "net-reload":
        with sidecars_locked(host):
            start_egress_proxy()
        return 0

    if action == "run" and settings.line_mode and has_a_conversation(claude_args):
        # Line mode, Claude Code without its full-screen UI, see chat/
        action = "line-mode"
    image = prepare_image(settings, host)
    if action == "dockerfile":
        print(image.dockerfile)
        return 0
    if action == "rebuild":
        return build_image(image, host, "--no-cache")
    if action == "prune":
        return prune_images(image.tag)

    dirs = configured_extra_dirs(settings, host)
    for raw, read_only in added:
        add_extra_dir(dirs, raw, host, read_only)
    dirs, protected = protected_dirs(dirs, settings, host)
    plan = Plan(settings, host, image, action, dirs, protected, claude_args)
    return chats(plan) if action == "line-mode" else session(plan)


@dataclass(frozen=True)
class Plan:
    """What one session is to be: claude, bash for the shell action, or
    claude behind the lines of a trace for the chat action (see chat/), in
    a container of the image, with the directories mounted next to the
    project, the paths in what is mounted that are read-only, and the
    arguments it is given."""

    settings: Settings
    host: Host
    image: Image
    action: str
    dirs: list[ExtraDir]
    protected: list[str]
    claude_args: list[str]
    # Where a chat leaves what is to be done after it, see chats
    handover: Handover | None = None


def chats(plan: Plan) -> int:
    """A chat, and after it one with each session its user asked to go on
    with (/resume). Each is a session of its own from start to finish:
    the one before is over, recorded and checked before the next starts,
    in a container of its own."""
    while True:
        handover = Handover()
        status = session(dataclasses.replace(plan, handover=handover))
        if not handover.session:
            return status
        resumed = resumed_args(plan.claude_args, handover.session)
        plan = dataclasses.replace(plan, claude_args=resumed)


def session(plan: Plan) -> int:
    """One session from start to finish. Returns its exit status."""
    settings, host, image = plan.settings, plan.host, plan.image
    refuse_unsafe_dir(host.project_dir, host)
    if not docker_ok("image", "inspect", image.tag):
        status = build_image(image, host)
        if status != 0:
            return status
    prepare_home(host)
    # The name, then the network and the proxies a session leans on, before
    # the arguments that name them
    with container_name(host, os.environ) as name, ending_passed_on(name) as ending:
        with session_network(settings, host):
            status = named_session(plan, name, ending)
        return ending.status(status)


def named_session(plan: Plan, name: str, ending: Ending) -> int:
    """The session of a plan in the container of a name, with its network
    there. It is ended when the launcher is told to end, see
    ending_passed_on."""
    settings, host, image = plan.settings, plan.host, plan.image
    action, dirs, protected = plan.action, plan.dirs, plan.protected
    claude_args = plan.claude_args
    env = os.environ
    # With a capture, the session's network namespace is its sidecar's
    capture = CaptureSidecar.name_for(name) if settings.net_log else ""
    run_args = [
        *base_args(settings, host, name),
        *session_args(action, env),
        *protect_config_args(settings, host),
        *history_args(settings, host),
        *extra_dir_args(dirs),
        *protect_args(protected),
        *protect_env_args(protected),
        *network_args(settings, capture),
        *socket_proxy_args(settings),
        *git_config_args(host),
        *shadow_args(settings, host, dirs),
    ]
    # --add-dir is variadic: written as two arguments it takes what follows
    # for more directories, a prompt that comes first among the user's
    # arguments included. With = it takes the one. A --shell session runs
    # bash, which takes no --add-dir.
    if action != "shell":
        add_dirs = [f"--add-dir={extra.path}" for extra in dirs]
        # The language servers of the image, as a plugin for this session
        plugin = ["--plugin-dir", PLUGIN_DIR] if image.has_language_servers else []
        # A chat has claude speak JSON Lines, ahead of the user's arguments
        spoken = list(CHAT_ARGS) if action == "line-mode" else []
        unasked = permission_args(settings, claude_args)
        claude_args = plugin + add_dirs + spoken + unasked + claude_args

    watched = [host.project_dir] + [extra.path for extra in dirs]
    pending = Path(host.pending_checks_dir, name + ".json")
    report_unchecked_sessions(pending.parent)
    before = host_exec_fingerprint(watched, host.claude_dir)
    save_pending_check(pending, watched, host.claude_dir, before)
    # What sessions that ended without their launcher left behind
    CaptureSidecar.collect_left_behind(host)
    Watcher.collect_left_behind(host)
    # The container whose network namespace the session is in
    owner = capture or name
    started = time.time()
    # From here to the end of the checks, see interrupts_held
    with interrupts_held():
        try:
            with contextlib.ExitStack() as running:
                # The capture first, a filtered session's address is its
                # sidecar's
                for recording in (
                    session_captured(settings, host, name, image.tag),
                    session_address_recorded(settings, host, name, owner),
                    socket_proxy_watched(settings, host, name, owner),
                    processes_recorded(settings, host, name, owner, image.tag),
                    transcripts_copied(host),
                    login_shared(host),
                ):
                    running.enter_context(recording)
                agent = ssh_agent_door(settings, host, name, env)
                agent_args = running.enter_context(agent)
                run_args += agent_args
                through = None
                if action == "line-mode":
                    # The agent's door is open when the host has an agent
                    sandbox = Sandbox.started(
                        name, settings, dirs, host.home, ssh_agent=bool(agent_args)
                    )
                    through = partial(chat, host, sandbox, handover=plan.handover)
                status = run_session(run_args, image, claude_args, ending, through)
        except Fatal:
            # The session did not start, there is nothing of it to check
            pending.unlink(missing_ok=True)
            raise
        try:
            report_session(host, name, started)
        finally:
            # Whatever became of the digest: this check matters more
            after = host_exec_fingerprint(watched, host.claude_dir)
            report_tampering(before, after, claude_dir=host.claude_dir)
            pending.unlink(missing_ok=True)
    return status


def cli(usage: str = "") -> int:
    """Run the launcher on the arguments of the command line. usage is
    the text --help prints ahead of the settings, the docstring of
    bin/claude-docker."""
    try:
        status = main(sys.argv[1:], usage)
        # Here, where a reader that left can still be told from a failure
        sys.stdout.flush()
        return status
    except Fatal as err:
        print(f"claude-docker: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # The reader left (a trace piped into head): nothing more to
        # write, at exit either
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
