"""The plugins of Claude Code as far as a session is told by them: which
are switched on as one starts, with the version installed, and which of
them a tool call of a transcript is of.

A plugin brings skills, hooks, servers and instructions that a session
runs and follows, and it is updated behind the user's back: which ones a
session had, and in which version, is not in its transcript, and the
settings of a later day are not those it ran with."""

from __future__ import annotations

import os
from pathlib import Path

from .files import settings_object

# Where plugins are switched on, each file over the ones before it as
# Claude Code reads them: the user's settings, then the project's
USER_SETTINGS = ("settings.json",)
PROJECT_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")
INSTALLED = "plugins/installed_plugins.json"
# No more plugins than this are noted of a session
MOST_PLUGINS = 100
# The tool that runs a skill, and how it names one a plugin brought:
# the plugin, then the skill. A path ahead of the skill is the directory
# of the project a skill is kept for, not a plugin.
SKILL_TOOL = "Skill"
# How Claude Code names the tools of a server a plugin brought:
# mcp__plugin_<plugin>_<server>__<tool>
PLUGIN_SERVER_PREFIX = "mcp__plugin_"


def _switched_on(claude_dir: str, project_dir: str) -> list[str]:
    """The plugins the settings switch on, each as name@marketplace."""
    files = [Path(claude_dir, name) for name in USER_SETTINGS]
    files += [Path(project_dir, name) for name in PROJECT_SETTINGS]
    switched: dict[str, bool] = {}
    for file in files:
        chosen = settings_object(file).get("enabledPlugins")
        if isinstance(chosen, dict):
            switched.update((name, on is True) for name, on in chosen.items() if name)
    return sorted(name for name, on in switched.items() if on)


def _version(installs: object, project_dir: str) -> str:
    """The version of a plugin a session of the project gets, of what is
    noted of its installs: the one installed for the project when there
    is one, else the first. Empty when none says."""
    found = installs if isinstance(installs, list) else []
    listed = [each for each in found if isinstance(each, dict)]
    for_project = [
        each
        for each in listed
        if isinstance(each.get("projectPath"), str)
        and os.path.normpath(each["projectPath"]) == os.path.normpath(project_dir)
    ]
    for install in (*for_project, *listed):
        version = install.get("version")
        if isinstance(version, str) and version:
            return version
    return ""


def enabled_plugins(claude_dir: str, project_dir: str) -> tuple[str, ...]:
    """The plugins switched on for a session of a project as it starts,
    each as name@marketplace and the version installed, by name. What the
    settings say, not what Claude Code went on to load: a session can
    switch a plugin on or off as it runs, and one that is switched on
    and not installed is named without a version."""
    installed = settings_object(Path(claude_dir, INSTALLED)).get("plugins")
    installs = installed if isinstance(installed, dict) else {}
    found = []
    for name in _switched_on(claude_dir, project_dir)[:MOST_PLUGINS]:
        version = _version(installs.get(name), project_dir)
        found.append(f"{name} {version}" if version else name)
    return tuple(found)


def skill_plugin(tool: str, tool_input: dict) -> str:
    """The plugin that brought the skill a call runs, empty for any other
    call and for a skill that is the user's or the project's own."""
    skill = tool_input.get("skill")
    if tool != SKILL_TOOL or not isinstance(skill, str):
        return ""
    plugin, found, _ = skill.partition(":")
    return plugin if found and plugin and "/" not in plugin else ""


def plugin_server(tool: str) -> str:
    """The server of a plugin a called tool is of, as Claude Code names
    it: the plugin and the name of the server, joined by an underscore.
    Not told apart here, either can have one in its name. Empty for any
    other tool."""
    if not tool.startswith(PLUGIN_SERVER_PREFIX):
        return ""
    server, found, _ = tool[len(PLUGIN_SERVER_PREFIX) :].partition("__")
    return server if found else ""
