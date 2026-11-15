"""The command line: the launcher's own options, then one session from
start to finish."""

from __future__ import annotations

import os
import sys

from .docker import docker_ok
from .image import build_image, prepare_image
from .network import net_log, network_args, socket_proxy_args, start_egress_proxy
from .session import (
    ExtraDir,
    add_extra_dir,
    base_args,
    configured_extra_dirs,
    container_name,
    extra_dir_args,
    git_config_args,
    prepare_claude_dir,
    protect_config_args,
    refuse_unsafe_dir,
    run_session,
    session_args,
    shadow_args,
    ssh_agent_args,
)
from .settings import Fatal, Host, detect_host, load_settings
from .tamper import host_exec_fingerprint, report_tampering


def parse_args(
    argv: list[str], dirs: list[ExtraDir], host: Host
) -> tuple[str, list[str]]:
    """Take the launcher's own options out of argv, adding the directories
    they name to dirs. Returns the action (run, shell, rebuild, dockerfile,
    net-log or net-reload) and the arguments left for claude."""
    action = "run"
    claude_args: list[str] = []
    actions = ("--rebuild", "--dockerfile", "--shell", "--net-log", "--net-reload")
    args = iter(argv)
    for arg in args:
        option, has_value, value = arg.partition("=")
        if arg in actions:
            action = arg[2:]
        elif option in ("--add-dir", "--add-dir-ro"):
            if not has_value:
                value = next(args, None)
                if value is None:
                    raise Fatal(f"{option} requires a path")
            add_extra_dir(dirs, value, host, read_only=option == "--add-dir-ro")
        else:
            claude_args.append(arg)
    return action, claude_args


def main(argv: list[str]) -> int:
    env = os.environ
    host = detect_host(env)
    settings = load_settings(env, os.path.join(host.user_conf, "config"))
    dirs = configured_extra_dirs(settings, host)
    action, claude_args = parse_args(argv, dirs, host)

    if action == "net-log":
        return net_log()
    if action == "net-reload":
        start_egress_proxy()
        return 0

    image = prepare_image(settings, host)
    if action == "dockerfile":
        print(image.dockerfile)
        return 0
    if action == "rebuild":
        return build_image(image, host, "--no-cache")

    refuse_unsafe_dir(host.project_dir, host)
    if not docker_ok("image", "inspect", image.tag):
        status = build_image(image, host)
        if status != 0:
            return status

    name = container_name(host, env)
    prepare_claude_dir(settings, host)
    run_args = [
        *base_args(settings, host, name),
        *session_args(action, env),
        *protect_config_args(settings, host),
        *extra_dir_args(dirs),
        *network_args(settings),
        *socket_proxy_args(settings),
        *ssh_agent_args(settings, env),
        *git_config_args(host),
        *shadow_args(settings, host, dirs),
    ]
    # --add-dir is variadic, keep it ahead of the user's args so a trailing
    # prompt is never swallowed as another directory. A --shell session runs
    # bash, which takes no --add-dir.
    if action != "shell":
        add_dirs = [arg for extra in dirs for arg in ("--add-dir", extra.path)]
        claude_args = add_dirs + claude_args

    watched = [host.project_dir] + [extra.path for extra in dirs]
    before = host_exec_fingerprint(watched)
    status = run_session(run_args, image, claude_args)
    report_tampering(before, host_exec_fingerprint(watched))
    return status


def cli() -> int:
    try:
        return main(sys.argv[1:])
    except Fatal as err:
        print(err, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
