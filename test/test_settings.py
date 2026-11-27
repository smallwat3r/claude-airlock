#!/usr/bin/env python3
"""The one list of the CLAUDE_AIRLOCK_* settings, and what has to keep up
with it: the fields their values are read into, --help, the README and
what a session is told of them."""

from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path

import pytest
from harness import ROOT, LauncherTest

from claude_airlock import errors, settings

NAMED = re.compile(r"CLAUDE_AIRLOCK_[A-Z_]+")
# What a session is told that is not a setting: its container's name, the
# directories mounted next to its project, and the kernel it runs on when
# that is its own
TOLD_TO_A_SESSION = set(settings.SESSION_SAID)


class SettingsListTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def variables_listed(self, sandbox: None) -> None:
        self.variables = {setting.variable for setting in settings.SETTINGS}

    def test_every_setting_has_its_field_and_no_field_is_without_one(self):
        fields = [field.name for field in dataclasses.fields(settings.Settings)]
        assert [s.field for s in settings.SETTINGS] == fields

    def test_a_session_is_told_a_setting_by_its_variable_alone(self):
        assert settings.variable("net_filter") == "CLAUDE_AIRLOCK_NET_FILTER"
        with pytest.raises(KeyError):
            settings.variable("netfilter")

    def test_the_defaults_are_read_as_the_defaults(self):
        missing = str(self.work / "no-config")
        assert settings.load_settings({}, missing) == settings.Settings()

    def test_a_choice_is_read_as_what_it_names_and_no_other_is_taken(self):
        missing = str(self.work / "no-config")
        for said, access in (
            ("0", settings.SocketAccess.OFF),
            ("1", settings.SocketAccess.LIMITED),
            ("full", settings.SocketAccess.FULL),
        ):
            read = settings.load_settings(
                {"CLAUDE_AIRLOCK_DOCKER_SOCKET": said}, missing
            )
            assert read.docker_socket is access
        with pytest.raises(errors.Fatal):
            settings.load_settings({"CLAUDE_AIRLOCK_DOCKER_SOCKET": "all"}, missing)

    def test_a_name_falls_back_to_its_default_and_empty_says_none(self):
        config = self.work / "config"
        missing = str(self.work / "no-config")
        assert settings.load_settings({}, missing).model == "opus"
        config.write_text("CLAUDE_AIRLOCK_MODEL=\nCLAUDE_AIRLOCK_EFFORT=max\n")
        read = settings.load_settings({}, str(config))
        assert (read.model, read.effort) == ("", "max")
        read = settings.load_settings(
            {"CLAUDE_AIRLOCK_MODEL": "fable", "CLAUDE_AIRLOCK_EFFORT": ""},
            str(config),
        )
        assert (read.model, read.effort) == ("fable", "")

    def test_the_config_file_takes_all_but_the_per_project_ones(self):
        left_out = {s.name for s in settings.SETTINGS} - settings.CONFIG_FILE_SETTINGS
        assert left_out == {"EXTRA_DIRS", "EXTRA_DIRS_RO"}

    def test_help_names_every_setting(self):
        said = self.launch("--help").stdout
        assert set(NAMED.findall(said)) == self.variables

    def test_the_readme_names_every_setting_and_no_other(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        assert set(NAMED.findall(readme)) == self.variables

    def test_the_docs_name_no_setting_that_is_not_one(self):
        for page in sorted((ROOT / "docs").glob("*.md")):
            named = set(NAMED.findall(page.read_text(encoding="utf-8")))
            assert named <= self.variables, page.name

    def test_every_link_between_the_docs_leads_somewhere(self):
        def anchors(page: Path) -> set[str]:
            text = re.sub(
                r"^```.*?^```", "", page.read_text(), flags=re.MULTILINE | re.DOTALL
            )
            headings = re.findall(r"^#{1,6} (.+)$", text, flags=re.MULTILINE)
            return {
                re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-")
                for h in headings
            }

        pages = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
        for page in pages:
            for target, anchor in re.findall(
                r"\]\(([^)#\s]*)#([\w-]+)\)", page.read_text()
            ):
                linked = (page.parent / target).resolve() if target else page
                assert anchor in anchors(linked), f"{page.name}: {target}#{anchor}"
            for target in re.findall(
                r"\]\(((?:\.\./)?(?:docs/)?[\w.-]+\.(?:md|png))\)", page.read_text()
            ):
                assert (page.parent / target).exists(), f"{page.name}: {target}"

    def test_a_session_is_told_of_no_setting_that_is_not_one(self):
        told = (ROOT / "docker" / "CLAUDE-airlock.md").read_text(encoding="utf-8")
        named = set(NAMED.findall(told)) - TOLD_TO_A_SESSION
        assert named <= self.variables

    def test_a_session_is_told_of_every_setting_it_is_given(self):
        told = (ROOT / "docker" / "CLAUDE-airlock.md").read_text(encoding="utf-8")
        (self.project / "docs").mkdir()
        flags = self.launch(
            "--add-dir-ro",
            "~/ref",
            SSH_AUTH_SOCK="/tmp/agent.sock",
            CLAUDE_AIRLOCK_SSH_AGENT="1",
            CLAUDE_AIRLOCK_RW_CONFIG="1",
            CLAUDE_AIRLOCK_SHARED_HISTORY="1",
            CLAUDE_AIRLOCK_API_LOG="1",
            CLAUDE_AIRLOCK_PROTECT="docs",
            CLAUDE_AIRLOCK_CPUS="2",
        ).flags
        given = {
            NAMED.match(flag[len("--env=") :]).group()
            for flag in flags
            if flag.startswith("--env=CLAUDE_AIRLOCK_")
        }
        assert {"CLAUDE_AIRLOCK_PROTECT", "CLAUDE_AIRLOCK_DIRS"} <= given
        assert given - {"CLAUDE_AIRLOCK_SANDBOX"} <= set(NAMED.findall(told))


class WorkingDirectoryTest:
    """A working directory the launcher cannot name its records by is
    said in a line."""

    def test_one_that_was_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        gone = tmp_path / "gone"
        gone.mkdir()
        monkeypatch.chdir(gone)
        gone.rmdir()
        with pytest.raises(errors.Fatal, match="the working directory was removed"):
            settings.detect_host({"HOME": str(tmp_path)})

    def test_one_whose_path_is_no_utf8(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        odd = os.path.join(os.fsencode(tmp_path), b"caf\xe9")
        try:
            os.mkdir(odd)
        except OSError:
            pytest.skip("the filesystem takes no name that is not UTF-8")
        monkeypatch.chdir(os.fsdecode(odd))
        monkeypatch.delenv("PWD", raising=False)
        with pytest.raises(
            errors.Fatal, match=r"project is not UTF-8, rename it: .*caf\\xe9$"
        ):
            settings.detect_host({"HOME": str(tmp_path)})
