#!/usr/bin/env python3
"""The options of a session, from the environment and the config file."""

from __future__ import annotations

import fcntl
import json
import subprocess
import sys

import pytest
from harness import (
    LAUNCHER,
    LauncherTest,
    Result,
    mounts_host_sockets,
)

from claude_airlock.sandbox import session


class OptionsTest(LauncherTest):
    def test_a_python_that_is_too_old_is_said_to_be(self):
        # As an older Python would find it, before it reads the package
        older = (
            "import runpy, sys;"
            "sys.version_info = (3, 12, 9, 'final', 0);"
            "sys.argv = sys.argv[1:];"
            "runpy.run_path(sys.argv[0], run_name='__main__')"
        )
        ran = subprocess.run(
            [sys.executable, "-c", older, str(LAUNCHER), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert ran.returncode == 1
        assert ran.stderr == (
            "claude-airlock: python3 is Python 3.12.9, it takes 3.13 or later\n"
        )
        assert ran.stdout == ""

    def test_opt_ins(self):
        flags = self.launch(
            SSH_AUTH_SOCK="/tmp/agent.sock",
            CLAUDE_AIRLOCK_SSH_AGENT="1",
            CLAUDE_AIRLOCK_SHADOW="*.pem",
            CLAUDE_AIRLOCK_RW_CONFIG="1",
            CLAUDE_AIRLOCK_CACHE="0",
            CLAUDE_AIRLOCK_RUNTIME="runsc",
        ).flags
        assert "--env=SSH_AUTH_SOCK=/tmp/ssh-agent.sock" in flags
        assert f"--volume=/dev/null:{self.project / 'key.pem'}:ro" in flags
        assert not [
            flag for flag in flags if "/.claude/" in flag and flag.endswith(":ro,z")
        ]
        # The host's all the same, not one a session makes for the sandbox
        claude = self.home / ".claude"
        for item in ("settings.json", "hooks", "rules"):
            assert f"--volume={claude / item}:/home/sandbox/.claude/{item}:z" in flags
        assert "--tmpfs=/home/sandbox/.cache:exec,size=2g" in flags
        assert "--runtime=runsc" in flags

    @mounts_host_sockets
    def test_the_agent_is_reached_through_the_launcher(self):
        flags = self.launch(
            SSH_AUTH_SOCK="/tmp/agent.sock", CLAUDE_AIRLOCK_SSH_AGENT="1"
        ).flags
        # Not the agent's own socket, one of the launcher's in front of it
        (agent,) = (flag for flag in flags if flag.endswith(":/tmp/ssh-agent.sock:z"))
        assert f"--volume={self.state / 'agents'}/" in agent

    def test_a_flag_must_be_0_or_1(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="true")
        self.assert_refused(result, "CLAUDE_AIRLOCK_NET_FILTER must be 0 or 1")

    def test_shell_runs_bash_without_claude_arguments(self):
        result = self.launch("--shell", "--add-dir", str(self.home / "ref"), "-c", "ls")
        assert "--entrypoint=bash" in result.flags
        assert result.command == ["-c", "ls"]

    def test_what_follows_shell_is_for_bash_whatever_it_reads_as(self):
        result = self.launch("--shell", "run.sh", "--prune", "-h", "--trace")
        assert "--entrypoint=bash" in result.flags
        assert result.command == ["run.sh", "--prune", "-h", "--trace"]

    def test_what_follows_the_end_of_the_options_is_passed_as_it_is(self):
        ref = str(self.home / "ref")
        result = self.launch("--shell", "--", "run.sh", "--add-dir", ref, "--")
        assert result.command == ["run.sh", "--add-dir", ref, "--"]
        assert f"--volume={ref}:{ref}:z" not in result.flags

    def test_a_second_thing_to_do_is_refused(self):
        for first, second in (("--rebuild", "--shell"), ("--trace", "--prune")):
            result = self.launch(first, second)
            self.assert_refused(result, f"{second} cannot be given with {first}")

    def test_filtered_egress(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="1")
        assert "--network=claude-airlock-net" in result.flags
        assert "--dns=127.0.0.1" in result.flags
        assert "--env=HTTPS_PROXY=http://claude-egress-proxy:3128" in result.flags
        # Without the host on it, which would be a way around the filter
        isolated = [
            f"--opt=com.docker.network.bridge.gateway_mode_ipv{version}=isolated"
            for version in (4, 6)
        ]
        assert [
            "network",
            "create",
            "--internal",
            *isolated,
            "claude-airlock-net",
        ] in result.calls
        # Waited for, a session must not start ahead of its proxy
        assert [c for c in result.calls if c[:2] == ["exec", "claude-egress-proxy"]]
        proxy = result.sidecar("claude-egress-proxy")
        assert "--network=claude-airlock-net" in proxy
        assert any("allowed-domains.txt" in arg for arg in proxy)

    def test_the_filter_network_is_never_made_with_a_route_out(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="1")
        made = [call for call in result.calls if call[:2] == ["network", "create"]]
        assert made
        for call in made:
            assert "--internal" in call

    def test_a_filter_network_with_a_route_out_is_refused(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="1", FAKE_NETWORK="false")
        self.assert_refused(result, "claude-airlock-net is not internal")

    def test_a_socket_proxy_left_on_the_network_is_taken_off_it(self):
        result = self.launch(FAKE_NETWORK="false claude-airlock-proxy claude-other")
        off = [call for call in result.calls if call[:2] == ["network", "disconnect"]]
        assert off == [
            [
                *("network", "disconnect", "--force"),
                *("claude-airlock-open-net", "claude-airlock-proxy"),
            ]
        ]

    def test_a_filter_network_the_host_is_on_is_made_anew_once_free(self):
        made_anew = ["network", "rm", "claude-airlock-net"]
        # From before the host was kept off it, with its proxy alone on it
        old = "true mode= claude-egress-proxy"

        def filtered(network: str, version: str) -> Result:
            (self.work / "log").unlink(missing_ok=True)
            result = self.launch(
                CLAUDE_AIRLOCK_NET_FILTER="1",
                FAKE_NETWORK=network,
                FAKE_VERSION=version,
            )
            assert result.status == 0, result.stderr
            return result

        calls = filtered(old, "29.1.0").calls
        assert made_anew in calls
        off = ["network", "disconnect", "--force", "claude-airlock-net"]
        assert [*off, "claude-egress-proxy"] in calls
        # Not under a session, which is said
        busy = filtered(old + " claude-other.capture", "29.1.0")
        assert made_anew not in busy.calls
        assert "lets a session reach what the host listens on" in busy.stderr
        # Not where docker cannot, and not when it is so already
        assert made_anew not in filtered(old, "27.5.1").calls
        assert made_anew not in filtered("true mode=isolated", "29.1.0").calls

    def test_a_proxy_is_removed_with_the_last_session_that_uses_it(self):
        proxies = "claude-airlock-ps-proxy\nclaude-egress-proxy\nclaude-other"

        def removed(**env: str) -> list[str]:
            (self.work / "log").unlink(missing_ok=True)
            calls = self.launch(FAKE_PS=proxies, **env).calls
            removed = [call[-1] for call in calls if call[:2] == ["rm", "--force"]]
            # After the container of the session itself
            assert removed[0].startswith("claude-proj")
            return removed[1:]

        # Whichever session started them, and nothing that is not a proxy
        assert removed() == ["claude-airlock-ps-proxy", "claude-egress-proxy"]
        # Not under a session on a network of theirs
        assert removed(FAKE_NETWORK="false claude-other.capture") == []
        # Nor while another launcher says it uses one, its session yet to start
        in_use = self.state / "proxies" / "claude-egress-proxy"
        with open(in_use, "w") as held:
            fcntl.flock(held, fcntl.LOCK_SH)
            assert removed() == ["claude-airlock-ps-proxy"]

    def test_a_session_never_takes_the_name_of_a_proxy(self, subtests: pytest.Subtests):
        # It would be taken for the proxy, and removed as an idle one
        for name, proxy in (
            ("egress-proxy", "claude-egress-proxy"),
            ("airlock-proxy", "claude-airlock-proxy"),
            ("airlock-ps-proxy", "claude-airlock-ps-proxy"),
        ):
            with subtests.test(name=name):
                project = self.home / name
                project.mkdir()
                (self.work / "log").unlink(missing_ok=True)
                flags = self.launch(cwd=project).flags
                assert f"--name={proxy}-2" in flags
                assert f"--name={proxy}" not in flags

    def test_two_launchers_do_not_take_the_same_name(self):
        assert "--name=claude-proj" in self.launch().flags
        (self.work / "log").unlink()
        # Another launcher has the name, its container is yet to start
        with open(self.state / "names" / "claude-proj", "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            assert "--name=claude-proj-2" in self.launch().flags

    def test_what_claude_follows_cannot_be_written_or_created(self):
        flags = self.launch().flags
        claude = self.home / ".claude"
        for name in ("settings.json", "CLAUDE.md", "hooks", "skills", "agents"):
            assert (
                f"--volume={claude / name}:/home/sandbox/.claude/{name}:ro,z" in flags
            )
        # Not there before: made empty, so that a session cannot make them
        for name in ("commands", "rules"):
            assert list((claude / name).iterdir()) == []
            assert (
                f"--volume={claude / name}:/home/sandbox/.claude/{name}:ro,z" in flags
            )

    def test_the_seeded_config_leaves_the_other_projects_out(self):
        config = {
            "theme": "dark",
            "projects": {"/home/me/other": {"mcpServers": {}}},
            # With what they are started with, a token as often as not
            "mcpServers": {"tracker": {"command": "x", "env": {"TOKEN": "secret"}}},
        }
        (self.home / ".claude.json").write_text(json.dumps(config))
        self.launch()
        seeded = self.base / ".claude.json"
        assert json.loads(seeded.read_text()) == {"theme": "dark"}
        assert seeded.stat().st_mode & 511 == 384
        assert seeded.stat().st_nlink == 1
        # And is not seeded again over what the sessions made of it
        seeded.write_text("{}")
        self.launch()
        assert seeded.read_text() == "{}"

    def test_the_config_the_sandbox_had_is_carried_over_whole(self):
        # From when the host's ~/.claude was mounted whole
        had = {"theme": "light", "projects": {str(self.project): {"trusted": True}}}
        (self.home / ".claude" / ".claude.json").write_text(json.dumps(had))
        (self.home / ".claude.json").write_text(json.dumps({"theme": "dark"}))
        self.launch()
        assert json.loads((self.base / ".claude.json").read_text()) == had


class ScratchTest(LauncherTest):
    def sizes(self, **env: str) -> dict[str, str]:
        """How large each tmpfs of the session is, by its place under
        the home of the container, or where it is."""
        found = {}
        for flag in self.launch(**env).flags:
            if not flag.startswith("--tmpfs="):
                continue
            target, _, options = flag[len("--tmpfs=") :].partition(":")
            (size,) = (o[5:] for o in options.split(",") if o.startswith("size="))
            found[target.replace("/home/sandbox/", "")] = size
        return found

    def test_it_is_as_large_as_it_is_meant_to_be_with_memory_to_spare(self):
        assert self.sizes() == {
            "/tmp": "4g",
            ".config": "64m",
            ".npm": "1g",
            ".claude/shell-snapshots": "64m",
            ".claude/session-env": "64m",
        }

    def test_it_takes_no_more_than_half_of_a_small_memory_limit(self):
        sizes = self.sizes(CLAUDE_AIRLOCK_MEMORY="2g", CLAUDE_AIRLOCK_CACHE="0")
        assert len(sizes) == 6
        assert ".cache" in sizes
        # What Claude Code keeps for the session is of them
        assert ".claude/session-env" in sizes
        total = sum(int(size.rstrip("m")) for size in sizes.values())
        assert total <= 1024
        assert total > 1024 - len(sizes)

    def test_a_memory_limit_is_read_as_docker_reads_it(self):
        for said, megabytes in (
            ("2g", 2048),
            ("2048m", 2048),
            ("1.5GiB", 1536),
            ("512 MB", 512),
            ("1048576k", 1024),
            ("1073741824", 1024),
            ("1t", 1024 * 1024),
        ):
            assert session.memory_megabytes(said) == megabytes, said
        for said in ("", "lots", "-2g", "2x", "g"):
            assert session.memory_megabytes(said) is None, said

    def test_none_is_without_a_limit_however_little_memory_there_is(self):
        sizes = self.sizes(CLAUDE_AIRLOCK_MEMORY="6m")
        assert sizes[".config"] == "1m"

    def test_no_memory_limit_leaves_them_as_large_as_they_are(self):
        assert (
            "--tmpfs=/tmp:exec,size=4g" in self.launch(CLAUDE_AIRLOCK_MEMORY="0").flags
        )

    def test_a_limit_that_is_not_read_is_left_to_docker(self):
        launched = self.launch(CLAUDE_AIRLOCK_MEMORY="lots")
        assert "--memory=lots" in launched.flags
        assert "--tmpfs=/tmp:exec,size=4g" in launched.flags


class ConfigFileTest(LauncherTest):
    def test_sets_a_default(self):
        self.write_config("# limits", "", "CLAUDE_AIRLOCK_MEMORY=8g")
        assert "--memory=8g" in self.launch().flags

    def test_environment_wins(self):
        self.write_config("CLAUDE_AIRLOCK_MEMORY=8g")
        assert "--memory=4g" in self.launch(CLAUDE_AIRLOCK_MEMORY="4g").flags

    def test_an_empty_switch_does_not_undo_the_file(self):
        self.write_config("CLAUDE_AIRLOCK_NET_FILTER=1")
        flags = self.launch(CLAUDE_AIRLOCK_NET_FILTER="").flags
        assert "--network=claude-airlock-net" in flags

    def test_what_the_file_hides_the_environment_does_not_show(self):
        (self.project / "notes.secret").touch()
        self.write_config("CLAUDE_AIRLOCK_SHADOW=*.pem")
        flags = self.launch(CLAUDE_AIRLOCK_SHADOW="*.secret").flags
        for name in ("key.pem", "notes.secret"):
            assert f"--volume=/dev/null:{self.project / name}:ro" in flags

    def test_an_empty_list_does_not_undo_the_file(self):
        self.write_config("CLAUDE_AIRLOCK_SHADOW=*.pem")
        flags = self.launch(CLAUDE_AIRLOCK_SHADOW="").flags
        assert f"--volume=/dev/null:{self.project / 'key.pem'}:ro" in flags

    def test_rejects_an_unknown_setting(self):
        self.write_config("CLAUDE_AIRLOCK_NET_FILTR=1")
        self.assert_refused(self.launch(), "not a known setting")

    def test_rejects_an_unknown_setting_of_the_environment(self):
        refused = self.launch(CLAUDE_AIRLOCK_NET_FILTR="1")
        self.assert_refused(refused, "not a known setting: CLAUDE_AIRLOCK_NET_FILTR")

    def test_what_a_session_is_told_of_itself_is_no_unknown_setting(self):
        # A launcher run in a session finds them in its environment
        told = {
            "CLAUDE_AIRLOCK_SANDBOX": "claude-proj",
            "CLAUDE_AIRLOCK_DIRS": "/x",
            "CLAUDE_AIRLOCK_KERNEL": "gVisor",
        }
        assert self.launch(**told).status == 0

    def test_a_value_written_as_a_shell_would_take_it_is_refused(
        self, subtests: pytest.Subtests
    ):
        # Taken as it is, it would name nothing, and hide or protect
        # nothing, without a word
        for line in (
            'CLAUDE_AIRLOCK_SHADOW="*.pem:.npmrc"',
            "CLAUDE_AIRLOCK_SHADOW='*.pem'",
            'CLAUDE_AIRLOCK_PROTECT="~/kit"',
            "CLAUDE_AIRLOCK_SHADOW=*.pem ",
            "CLAUDE_AIRLOCK_MEMORY= 8g",
        ):
            with subtests.test(line=line):
                self.write_config(line)
                refused = self.launch()
                self.assert_refused(refused, "a value is taken as it is written")
                assert line in refused.stderr
        # A quote that is part of a value is one
        self.write_config("CLAUDE_AIRLOCK_SHADOW=*.pem:it's")
        assert self.launch().status == 0

    def test_rejects_per_project_settings(self):
        self.write_config("CLAUDE_AIRLOCK_EXTRA_DIRS=/tmp")
        self.assert_refused(self.launch(), "not a known setting")

    def test_rejects_other_variables(self):
        self.write_config("PATH=/tmp/evil")
        self.assert_refused(self.launch(), "not a known setting")

    def test_values_are_not_evaluated(self):
        self.write_config("CLAUDE_AIRLOCK_RUNTIME=$(echo pwned)")
        assert "--runtime=$(echo pwned)" in self.launch().flags
