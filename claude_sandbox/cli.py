"""The command line: the launcher's own options, then one session from
start to finish."""

from __future__ import annotations

import contextlib
import os
import sys
import time
from pathlib import Path

from .capture import CaptureSidecar, collect_ended_captures, session_captured
from .digest import report_session
from .docker import docker_ok
from .doors import socket_proxy_watched, ssh_agent_door
from .follow import follow
from .history import history_args
from .image import PLUGIN_DIR, Image, build_image, prepare_image
from .network import (
    net_log,
    network_args,
    prepare_network,
    session_address_recorded,
    socket_proxy_args,
    start_egress_proxy,
    start_socket_proxy,
)
from .processes import collect_ended_records, processes_recorded
from .recorder import transcripts_copied
from .session import (
    ExtraDir,
    add_extra_dir,
    base_args,
    configured_extra_dirs,
    container_name,
    extra_dir_args,
    git_config_args,
    interrupts_held,
    prepare_claude_dir,
    protect_config_args,
    refuse_unsafe_dir,
    run_session,
    session_args,
    shadow_args,
)
from .settings import Fatal, Host, Settings, detect_host, load_settings
from .tamper import (
    host_exec_fingerprint,
    report_tampering,
    report_unchecked_sessions,
    save_pending_check,
)
from .trace import trace


def parse_args(argv: list[str]) -> tuple[str, list[str], list[tuple[str, bool]]]:
    """Take the launcher's own options out of argv. Returns the action
    (run, shell, rebuild, dockerfile, net-log, net-reload or trace), the
    arguments left for claude, and the directories asked for with
    --add-dir and --add-dir-ro, each with whether it is read-only."""
    action = "run"
    claude_args: list[str] = []
    added: list[tuple[str, bool]] = []
    actions = (
        "--rebuild",
        "--dockerfile",
        "--shell",
        "--net-log",
        "--net-reload",
        "--trace",
    )
    args = iter(argv)
    for arg in args:
        option, has_value, value = arg.partition("=")
        if arg in actions:
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


def main(argv: list[str]) -> int:
    env = os.environ
    host = detect_host(env)
    settings = load_settings(env, os.path.join(host.user_conf, "config"))
    action, claude_args, added = parse_args(argv)

    # What needs neither the image nor the directories of a session
    if action == "net-log":
        return net_log()
    if action == "trace":
        following = "--follow" in claude_args
        return (follow if following else trace)(host, claude_args)
    if action == "net-reload":
        start_egress_proxy()
        return 0

    image = prepare_image(settings, host)
    if action == "dockerfile":
        print(image.dockerfile)
        return 0
    if action == "rebuild":
        return build_image(image, host, "--no-cache")

    dirs = configured_extra_dirs(settings, host)
    for raw, read_only in added:
        add_extra_dir(dirs, raw, host, read_only)
    return session(settings, host, image, action, dirs, claude_args)


def session(
    settings: Settings,
    host: Host,
    image: Image,
    action: str,
    dirs: list[ExtraDir],
    claude_args: list[str],
) -> int:
    """One session from start to finish: claude, or bash for the shell
    action, in a container of the image. Returns its exit status."""
    env = os.environ
    refuse_unsafe_dir(host.project_dir, host)
    if not docker_ok("image", "inspect", image.tag):
        status = build_image(image, host)
        if status != 0:
            return status

    name = container_name(host, env)
    # With a capture, the session's network namespace is its sidecar's
    capture = CaptureSidecar.name_for(name) if settings.net_log else ""
    prepare_claude_dir(settings, host)
    # The sidecars a session leans on, before the arguments that name them
    prepare_network(settings)
    start_socket_proxy(settings)
    run_args = [
        *base_args(settings, host, name),
        *session_args(action, env),
        *protect_config_args(settings, host),
        *history_args(settings, host),
        *extra_dir_args(dirs),
        *network_args(settings, capture),
        *socket_proxy_args(settings),
        *git_config_args(host),
        *shadow_args(settings, host, dirs),
    ]
    # --add-dir is variadic, keep it ahead of the user's args so a trailing
    # prompt is never swallowed as another directory. A --shell session runs
    # bash, which takes no --add-dir.
    if action != "shell":
        add_dirs = [arg for extra in dirs for arg in ("--add-dir", extra.path)]
        # The language servers of the image, as a plugin for this session
        plugin = ["--plugin-dir", PLUGIN_DIR] if image.has_language_servers else []
        claude_args = plugin + add_dirs + claude_args

    watched = [host.project_dir] + [extra.path for extra in dirs]
    pending = Path(host.pending_checks_dir, name + ".json")
    report_unchecked_sessions(pending.parent)
    before = host_exec_fingerprint(watched, host.claude_dir)
    save_pending_check(pending, watched, host.claude_dir, before)
    collect_ended_captures(host)
    collect_ended_records(host)
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
                ):
                    running.enter_context(recording)
                agent = ssh_agent_door(settings, host, name, env)
                run_args += running.enter_context(agent)
                status = run_session(run_args, image, claude_args)
        except Fatal:
            # The session did not start, there is nothing of it to check
            pending.unlink(missing_ok=True)
            raise
        try:
            report_session(host, name, started)
        finally:
            # Whatever became of the digest: this check matters more
            after = host_exec_fingerprint(watched, host.claude_dir)
            report_tampering(before, after)
            pending.unlink(missing_ok=True)
    return status


def cli() -> int:
    try:
        status = main(sys.argv[1:])
        # Here, where a reader that left can still be told from a failure
        sys.stdout.flush()
        return status
    except Fatal as err:
        print(err, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # The reader left (a trace piped into head): nothing more to
        # write, at exit either
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
