"""The command line: the launcher's own options, then one session from
start to finish."""

from __future__ import annotations

import contextlib
import dataclasses
import io
import os
import sys
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from functools import partial
from typing import NamedTuple

from .action import Action
from .chat import CHAT_ARGS, Handover, Sandbox, chat
from .docker import docker_ok
from .errors import Fatal
from .notice import warn
from .recording.address import session_address_recorded
from .recording.capture import CaptureSidecar, session_captured
from .recording.egress_log import net_log
from .recording.host_health import collect_left_behind, health_recorded
from .recording.processes import Watcher, processes_recorded
from .recording.recorder import transcripts_copied
from .recording.socket_watch import socket_proxy_watched
from .recording.ssh_agent import refuse_unreachable_agent, ssh_agent_door
from .recording.started import Start, note_end, note_start
from .report.digest import report_session
from .report.follow import follow
from .report.trace import trace
from .sandbox.asked_hosts import hosts_asked
from .sandbox.claude_args import has_a_conversation, resumed_args
from .sandbox.egress_proxy import start_egress_proxy
from .sandbox.ending import Ending, ending_passed_on, interrupts_held
from .sandbox.history import history_args
from .sandbox.home import prepare_home, protect_config_args
from .sandbox.image import PLUGIN_DIR, Image, build_image, prepare_image, prune_images
from .sandbox.limits import limits_watched
from .sandbox.login import login_shared
from .sandbox.mounts import (
    ExtraDir,
    add_extra_dir,
    configured_extra_dirs,
    extra_dir_args,
    protect_args,
    protect_env_args,
    protected_dirs,
    refuse_links_out,
    refuse_unsafe_dir,
    shadow_args,
)
from .sandbox.network import network_args, session_network
from .sandbox.plugins import enabled_plugins
from .sandbox.proxy_use import sidecars_locked
from .sandbox.runtime import Runtime, say_runtime_notes, session_runtime
from .sandbox.session import (
    base_args,
    container_name,
    git_config_args,
    permission_args,
    run_session,
    session_args,
)
from .sandbox.socket_proxy import socket_proxy_args
from .sandbox.tamper import PendingCheck
from .settings import Host, Settings, detect_host, load_settings, settings_help


class ParsedArgs(NamedTuple):
    """The command line taken apart: what to do, the arguments left for
    claude, and the directories asked for with --add-dir and --add-dir-ro,
    each with whether it is read-only."""

    action: Action
    claude_args: list[str]
    added: list[tuple[str, bool]]


# The launcher's own options that say what to do
ACTIONS = {action.option: action for action in Action if action is not Action.RUN}


# What ends the launcher's own options: all that follows is claude's, or
# bash's after --shell
OPTIONS_END = "--"


def parse_args(argv: list[str]) -> ParsedArgs:
    """Take the launcher's own options out of argv. Only up to where
    they end: what follows -- is for claude, or for bash, as it is
    written, an option of the launcher's name too. One thing to do at a
    time: a second one is refused, not left to be the one that counts
    without a word. But after --shell, where what reads as one is for
    bash or the script it runs: only the directories to mount are the
    launcher's there."""
    action = Action.RUN
    asked = ""
    claude_args: list[str] = []
    added: list[tuple[str, bool]] = []
    args = iter(argv)
    for arg in args:
        option, has_value, value = arg.partition("=")
        if arg == OPTIONS_END:
            claude_args += args
        elif (arg == "-h" or arg in ACTIONS) and action is not Action.SHELL:
            if asked:
                raise Fatal(f"{arg} cannot be given with {asked}, one at a time")
            action, asked = ACTIONS.get(arg, Action.HELP), arg
        elif option in ("--add-dir", "--add-dir-ro"):
            if not has_value:
                following = next(args, None)
                if following is None:
                    raise Fatal(f"{option} requires a path")
                value = following
            added.append((value, option == "--add-dir-ro"))
        else:
            claude_args.append(arg)
    return ParsedArgs(action, claude_args, added)


def main(argv: list[str], usage: str = "") -> int:
    action, claude_args, added = parse_args(argv)
    if action is Action.HELP:
        # Ahead of the settings: a config file that is refused is one of
        # the things the text is asked about
        print(usage.strip() + "\n\n" + settings_help())
        return 0
    env = os.environ
    host = detect_host(env)
    settings = load_settings(env, os.path.join(host.user_conf, "config"))

    # What needs neither the image nor the directories of a session
    if action is Action.NET_LOG:
        return net_log()
    if action is Action.TRACE:
        following = "--follow" in claude_args
        return (follow if following else trace)(host, claude_args)
    if action is Action.NET_RELOAD:
        with sidecars_locked(host):
            start_egress_proxy(host)
        return 0

    if action is Action.RUN and settings.line_mode and has_a_conversation(claude_args):
        # Line mode, Claude Code without its native UI, see chat/
        action = Action.LINE_MODE
    image = prepare_image(settings, host)
    if action is Action.DOCKERFILE:
        print(image.dockerfile)
        return 0
    if action is Action.REBUILD:
        return build_image(image, host, "--no-cache")
    if action is Action.PRUNE:
        return prune_images(image.tag)

    dirs = configured_extra_dirs(settings, host)
    for raw, read_only in added:
        add_extra_dir(dirs, raw, host, read_only)
    refuse_links_out(dirs, host)
    dirs, protected = protected_dirs(dirs, settings, host)
    plan = Plan(settings, host, image, action, dirs, protected, claude_args)
    return chats(plan) if plan.is_chat else session(plan)


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
    action: Action
    dirs: list[ExtraDir]
    protected: list[str]
    claude_args: list[str]
    # Where a chat leaves what is to be done after it, see chats
    handover: Handover | None = None

    @property
    def runs_claude(self) -> bool:
        """Not for the shell action, which runs bash."""
        return self.action is not Action.SHELL

    @property
    def is_chat(self) -> bool:
        return self.action is Action.LINE_MODE


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
    # Refuse or report what the runtime cannot provide before anything is
    # started for the session
    runtime = session_runtime(settings)
    refuse_unreachable_agent(settings, os.environ, runtime)
    say_runtime_notes(runtime, settings)
    # The name, then the network and the proxies a session leans on, before
    # the arguments that name them
    with container_name(host, os.environ) as name, ending_passed_on(name) as ending:
        with session_network(settings, host):
            status = named_session(plan, name, ending, runtime)
        return ending.status(status)


def session_watched(
    plan: Plan, name: str, owner: str, runtime: Runtime
) -> AbstractContextManager[None]:
    """The recorder for CLAUDE_AIRLOCK_PROC_LOG while a session runs. It
    is normally a sidecar that records the session's processes and its
    memory and CPU use. Under a runtime where a sidecar cannot see into
    the session, the launcher records memory and CPU use from outside
    instead. owner is the container whose network namespace the session
    is in."""
    settings, host = plan.settings, plan.host
    if settings.proc_log and not runtime.JOINABLE:
        return health_recorded(host, name, runtime.shown)
    return processes_recorded(settings, host, name, owner, plan.image.tag)


def session_run_args(
    plan: Plan, name: str, runtime: Runtime, capture: str
) -> list[str]:
    """The options of docker run for the session of a plan, but for what
    is only known once its recorders run. capture names the sidecar whose
    network namespace the session is in, if any."""
    settings, host, dirs, protected = (
        plan.settings,
        plan.host,
        plan.dirs,
        plan.protected,
    )
    return [
        *base_args(settings, host, name, runtime),
        *session_args(plan.action, os.environ),
        *protect_config_args(settings, host),
        *history_args(settings, host),
        *extra_dir_args(dirs),
        *protect_args(protected, host, dirs),
        *protect_env_args(protected),
        *network_args(settings, capture),
        *socket_proxy_args(settings),
        *git_config_args(host),
        *shadow_args(settings, host, dirs),
    ]


def command_args(plan: Plan) -> list[str]:
    """What the session's program is given: the user's arguments, for
    claude after the launcher's own."""
    if not plan.runs_claude:
        # Bash takes none of claude's
        return plan.claude_args
    # --add-dir is variadic: written as two arguments it takes what follows
    # for more directories, a prompt that comes first among the user's
    # arguments included. With = it takes the one.
    add_dirs = [f"--add-dir={extra.path}" for extra in plan.dirs]
    # The language servers of the image, as a plugin for this session
    servers = plan.image.has_language_servers
    plugin = ["--plugin-dir", PLUGIN_DIR] if servers else []
    # A chat has claude speak JSON Lines, ahead of the user's arguments
    spoken = list(CHAT_ARGS) if plan.is_chat else []
    unasked = permission_args(plan.settings, plan.claude_args)
    return plugin + add_dirs + spoken + unasked + plan.claude_args


def collect_all_left_behind(host: Host) -> None:
    """What sessions that ended without their launcher left behind."""
    CaptureSidecar.collect_left_behind(host)
    Watcher.collect_left_behind(host)
    collect_left_behind(host)


def recorded_session(
    plan: Plan,
    name: str,
    ending: Ending,
    runtime: Runtime,
    run_args: list[str],
    owner: str,
) -> tuple[int, list[str]]:
    """Run the session of a plan with its recorders around it, and its
    doors open. owner is the container whose network namespace the
    session is in. Returns its exit status, and what is to be said of
    the limits it ran into."""
    settings, host, image = plan.settings, plan.host, plan.image
    with contextlib.ExitStack() as running:
        # The capture first, a filtered session's address is its
        # sidecar's
        for recording in (
            session_captured(settings, host, name, image.tag),
            session_address_recorded(settings, host, name, owner),
            socket_proxy_watched(settings, host, name, owner),
            session_watched(plan, name, owner, runtime),
            transcripts_copied(host),
            login_shared(host),
        ):
            running.enter_context(recording)
        hit = running.enter_context(limits_watched(settings, name))
        hosts = running.enter_context(
            hosts_asked(settings, host, name, owner, plan.is_chat)
        )
        agent = ssh_agent_door(settings, host, name, os.environ)
        agent_args = running.enter_context(agent)
        # How the sandbox is started, noted for a trace and what
        # follows the sessions, and for a chat to say first
        start = Start.of(
            settings,
            runtime,
            image.tag,
            plan.dirs,
            # The agent's door is open when the host has an agent
            ssh_agent=bool(agent_args),
            net_ask=hosts is not None,
            plugins=enabled_plugins(host.claude_dir, host.project_dir),
            # A --shell session runs bash, which is given no plugin
            servers=image.language_servers if plan.runs_claude else (),
        )
        said = note_start(host, name, start)
        through = None
        if plan.is_chat:
            sandbox = Sandbox.started(name, start, host.home)
            through = partial(
                chat,
                host,
                sandbox,
                handover=plan.handover,
                start=said,
                guarded=settings.injection_stop,
                hosts=hosts,
            )
        run_args = run_args + agent_args
        try:
            status = run_session(run_args, image, command_args(plan), ending, through)
        finally:
            note_end(host, name)
    # Whole once the recorders are done
    return status, hit.lines()


def named_session(plan: Plan, name: str, ending: Ending, runtime: Runtime) -> int:
    """The session of a plan in the container of a name, with its network
    there, under the given runtime. It is ended when the launcher is told
    to end, see ending_passed_on."""
    settings, host = plan.settings, plan.host
    # With a capture, the session's network namespace is its sidecar's
    capture = CaptureSidecar.name_for(name) if settings.net_log else ""
    run_args = session_run_args(plan, name, runtime, capture)
    watched = [host.project_dir] + [extra.path for extra in plan.dirs]
    collect_all_left_behind(host)
    # Kept on disk from here: nothing that Ctrl-C can end comes between
    # this and interrupts_held, a check left for a session that never ran
    # would be reported as one that ended without it
    check = PendingCheck.begin(host, name, watched)
    started = time.time()
    # From here to the end of the checks, see interrupts_held
    with interrupts_held():
        try:
            status, limits = recorded_session(
                plan, name, ending, runtime, run_args, capture or name
            )
        except Fatal:
            check.drop()
            raise
        try:
            report_session(host, name, started, limits)
        finally:
            # Whatever became of the digest: this check matters more
            check.run()
    return status


def cli(usage: str = "") -> int:
    """Run the launcher on the arguments of the command line. usage is
    the text --help prints ahead of the settings, the docstring of
    bin/claude-airlock."""
    try:
        # Whatever a session wrote, showing it must not be what fails: a
        # character the terminal's encoding has none for is written as
        # its number
        for stream in (sys.stdout, sys.stderr):
            if isinstance(stream, io.TextIOWrapper):
                stream.reconfigure(errors="backslashreplace")
        status = main(sys.argv[1:], usage)
        # Here, where a reader that left can still be told from a failure
        sys.stdout.flush()
        return status
    except Fatal as err:
        warn(str(err))
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # The reader left (a trace piped into head): nothing more to
        # write, at exit either
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
