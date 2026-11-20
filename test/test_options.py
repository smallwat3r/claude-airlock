#!/usr/bin/env python3
"""The options of a session, from the environment and the config file."""

from __future__ import annotations

import fcntl
import json
import unittest

from harness import (
    LauncherTest,
    Result,
    mounts_host_sockets,
)

from claude_airlock.sandbox import session


class OptionsTest(LauncherTest):
    def test_opt_ins(self):
        flags = self.launch(
            SSH_AUTH_SOCK="/tmp/agent.sock",
            CLAUDE_AIRLOCK_SSH_AGENT="1",
            CLAUDE_AIRLOCK_SHADOW="*.pem",
            CLAUDE_AIRLOCK_RW_CONFIG="1",
            CLAUDE_AIRLOCK_CACHE="0",
            CLAUDE_AIRLOCK_RUNTIME="runsc",
        ).flags
        self.assertIn("--env=SSH_AUTH_SOCK=/tmp/ssh-agent.sock", flags)
        self.assertIn(f"--volume=/dev/null:{self.project / 'key.pem'}:ro", flags)
        self.assertFalse(
            [flag for flag in flags if "/.claude/" in flag and flag.endswith(":ro,z")]
        )
        # The host's all the same, not one a session makes for the sandbox
        claude = self.home / ".claude"
        for item in ("settings.json", "hooks", "rules"):
            self.assertIn(
                f"--volume={claude / item}:/home/sandbox/.claude/{item}:z", flags
            )
        self.assertIn("--tmpfs=/home/sandbox/.cache:exec,size=2g", flags)
        self.assertIn("--runtime=runsc", flags)

    @mounts_host_sockets
    def test_the_agent_is_reached_through_the_launcher(self):
        flags = self.launch(
            SSH_AUTH_SOCK="/tmp/agent.sock", CLAUDE_AIRLOCK_SSH_AGENT="1"
        ).flags
        # Not the agent's own socket, one of the launcher's in front of it
        (agent,) = (flag for flag in flags if flag.endswith(":/tmp/ssh-agent.sock:z"))
        self.assertIn(f"--volume={self.state / 'agents'}/", agent)

    def test_a_flag_must_be_0_or_1(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="true")
        self.assert_refused(result, "CLAUDE_AIRLOCK_NET_FILTER must be 0 or 1")

    def test_shell_runs_bash_without_claude_arguments(self):
        result = self.launch("--shell", "--add-dir", str(self.home / "ref"), "-c", "ls")
        self.assertIn("--entrypoint=bash", result.flags)
        self.assertEqual(result.command, ["-c", "ls"])

    def test_filtered_egress(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="1")
        self.assertIn("--network=claude-airlock-net", result.flags)
        self.assertIn("--dns=127.0.0.1", result.flags)
        self.assertIn("--env=HTTPS_PROXY=http://claude-egress-proxy:3128", result.flags)
        # Without the host on it, which would be a way around the filter
        isolated = [
            f"--opt=com.docker.network.bridge.gateway_mode_ipv{version}=isolated"
            for version in (4, 6)
        ]
        self.assertIn(
            ["network", "create", "--internal", *isolated, "claude-airlock-net"],
            result.calls,
        )
        # Waited for, a session must not start ahead of its proxy
        self.assertTrue(
            [c for c in result.calls if c[:2] == ["exec", "claude-egress-proxy"]]
        )
        proxy = result.sidecar("claude-egress-proxy")
        self.assertIn("--network=claude-airlock-net", proxy)
        self.assertTrue(any("allowed-domains.txt" in arg for arg in proxy))

    def test_the_filter_network_is_never_made_with_a_route_out(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="1")
        made = [call for call in result.calls if call[:2] == ["network", "create"]]
        self.assertTrue(made)
        for call in made:
            self.assertIn("--internal", call)

    def test_a_filter_network_with_a_route_out_is_refused(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="1", FAKE_NETWORK="false")
        self.assert_refused(result, "claude-airlock-net is not internal")

    def test_a_socket_proxy_left_on_the_network_is_taken_off_it(self):
        result = self.launch(FAKE_NETWORK="false claude-airlock-proxy claude-other")
        off = [call for call in result.calls if call[:2] == ["network", "disconnect"]]
        self.assertEqual(
            off,
            [
                [
                    *("network", "disconnect", "--force"),
                    *("claude-airlock-open-net", "claude-airlock-proxy"),
                ]
            ],
        )

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
            self.assertEqual(result.status, 0, result.stderr)
            return result

        calls = filtered(old, "29.1.0").calls
        self.assertIn(made_anew, calls)
        off = ["network", "disconnect", "--force", "claude-airlock-net"]
        self.assertIn([*off, "claude-egress-proxy"], calls)
        # Not under a session, which is said
        busy = filtered(old + " claude-other.capture", "29.1.0")
        self.assertNotIn(made_anew, busy.calls)
        self.assertIn("lets a session reach what the host listens on", busy.stderr)
        # Not where docker cannot, and not when it is so already
        self.assertNotIn(made_anew, filtered(old, "27.5.1").calls)
        self.assertNotIn(made_anew, filtered("true mode=isolated", "29.1.0").calls)

    def test_a_proxy_is_removed_with_the_last_session_that_uses_it(self):
        proxies = "claude-airlock-ps-proxy\nclaude-egress-proxy\nclaude-other"

        def removed(**env: str) -> list[str]:
            (self.work / "log").unlink(missing_ok=True)
            calls = self.launch(FAKE_PS=proxies, **env).calls
            return [call[-1] for call in calls if call[:2] == ["rm", "--force"]]

        # Whichever session started them, and nothing that is not a proxy
        self.assertEqual(removed(), ["claude-airlock-ps-proxy", "claude-egress-proxy"])
        # Not under a session on a network of theirs
        self.assertEqual(removed(FAKE_NETWORK="false claude-other.capture"), [])
        # Nor while another launcher says it uses one, its session yet to start
        in_use = self.state / "proxies" / "claude-egress-proxy"
        with open(in_use, "w") as held:
            fcntl.flock(held, fcntl.LOCK_SH)
            self.assertEqual(removed(), ["claude-airlock-ps-proxy"])

    def test_two_launchers_do_not_take_the_same_name(self):
        self.assertIn("--name=claude-proj", self.launch().flags)
        (self.work / "log").unlink()
        # Another launcher has the name, its container is yet to start
        with open(self.state / "names" / "claude-proj", "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            self.assertIn("--name=claude-proj-2", self.launch().flags)

    def test_what_claude_follows_cannot_be_written_or_created(self):
        flags = self.launch().flags
        claude = self.home / ".claude"
        for name in ("settings.json", "CLAUDE.md", "hooks", "skills", "agents"):
            self.assertIn(
                f"--volume={claude / name}:/home/sandbox/.claude/{name}:ro,z", flags
            )
        # Not there before: made empty, so that a session cannot make them
        for name in ("commands", "rules"):
            self.assertEqual(list((claude / name).iterdir()), [])
            self.assertIn(
                f"--volume={claude / name}:/home/sandbox/.claude/{name}:ro,z", flags
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
        self.assertEqual(json.loads(seeded.read_text()), {"theme": "dark"})
        self.assertEqual(seeded.stat().st_mode & 0o777, 0o600)
        self.assertEqual(seeded.stat().st_nlink, 1)
        # And is not seeded again over what the sessions made of it
        seeded.write_text("{}")
        self.launch()
        self.assertEqual(seeded.read_text(), "{}")

    def test_the_config_the_sandbox_had_is_carried_over_whole(self):
        # From when the host's ~/.claude was mounted whole
        had = {"theme": "light", "projects": {str(self.project): {"trusted": True}}}
        (self.home / ".claude" / ".claude.json").write_text(json.dumps(had))
        (self.home / ".claude.json").write_text(json.dumps({"theme": "dark"}))
        self.launch()
        self.assertEqual(json.loads((self.base / ".claude.json").read_text()), had)


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
        self.assertEqual(
            self.sizes(),
            {
                "/tmp": "4g",
                ".config": "64m",
                ".npm": "1g",
                ".claude/shell-snapshots": "64m",
                ".claude/session-env": "64m",
            },
        )

    def test_it_takes_no_more_than_half_of_a_small_memory_limit(self):
        sizes = self.sizes(CLAUDE_AIRLOCK_MEMORY="2g", CLAUDE_AIRLOCK_CACHE="0")
        self.assertEqual(len(sizes), 6)
        self.assertIn(".cache", sizes)
        # What Claude Code keeps for the session is of them
        self.assertIn(".claude/session-env", sizes)
        total = sum(int(size.rstrip("m")) for size in sizes.values())
        self.assertLessEqual(total, 1024)
        self.assertGreater(total, 1024 - len(sizes))

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
            self.assertEqual(session.memory_megabytes(said), megabytes, said)
        for said in ("", "lots", "-2g", "2x", "g"):
            self.assertIsNone(session.memory_megabytes(said), said)

    def test_none_is_without_a_limit_however_little_memory_there_is(self):
        sizes = self.sizes(CLAUDE_AIRLOCK_MEMORY="6m")
        self.assertEqual(sizes[".config"], "1m")

    def test_no_memory_limit_leaves_them_as_large_as_they_are(self):
        self.assertIn(
            "--tmpfs=/tmp:exec,size=4g", self.launch(CLAUDE_AIRLOCK_MEMORY="0").flags
        )

    def test_a_limit_that_is_not_read_is_left_to_docker(self):
        launched = self.launch(CLAUDE_AIRLOCK_MEMORY="lots")
        self.assertIn("--memory=lots", launched.flags)
        self.assertIn("--tmpfs=/tmp:exec,size=4g", launched.flags)


class ConfigFileTest(LauncherTest):
    def test_sets_a_default(self):
        self.write_config("# limits", "", "CLAUDE_AIRLOCK_MEMORY=8g")
        self.assertIn("--memory=8g", self.launch().flags)

    def test_environment_wins(self):
        self.write_config("CLAUDE_AIRLOCK_MEMORY=8g")
        self.assertIn("--memory=4g", self.launch(CLAUDE_AIRLOCK_MEMORY="4g").flags)

    def test_an_empty_switch_does_not_undo_the_file(self):
        self.write_config("CLAUDE_AIRLOCK_NET_FILTER=1")
        flags = self.launch(CLAUDE_AIRLOCK_NET_FILTER="").flags
        self.assertIn("--network=claude-airlock-net", flags)

    def test_what_the_file_hides_the_environment_does_not_show(self):
        (self.project / "notes.secret").touch()
        self.write_config("CLAUDE_AIRLOCK_SHADOW=*.pem")
        flags = self.launch(CLAUDE_AIRLOCK_SHADOW="*.secret").flags
        for name in ("key.pem", "notes.secret"):
            self.assertIn(f"--volume=/dev/null:{self.project / name}:ro", flags)

    def test_an_empty_list_does_not_undo_the_file(self):
        self.write_config("CLAUDE_AIRLOCK_SHADOW=*.pem")
        flags = self.launch(CLAUDE_AIRLOCK_SHADOW="").flags
        self.assertIn(f"--volume=/dev/null:{self.project / 'key.pem'}:ro", flags)

    def test_rejects_an_unknown_setting(self):
        self.write_config("CLAUDE_AIRLOCK_NET_FILTR=1")
        self.assert_refused(self.launch(), "not a known setting")

    def test_rejects_per_project_settings(self):
        self.write_config("CLAUDE_AIRLOCK_EXTRA_DIRS=/tmp")
        self.assert_refused(self.launch(), "not a known setting")

    def test_rejects_other_variables(self):
        self.write_config("PATH=/tmp/evil")
        self.assert_refused(self.launch(), "not a known setting")

    def test_values_are_not_evaluated(self):
        self.write_config("CLAUDE_AIRLOCK_RUNTIME=$(echo pwned)")
        self.assertIn("--runtime=$(echo pwned)", self.launch().flags)


if __name__ == "__main__":
    unittest.main()
