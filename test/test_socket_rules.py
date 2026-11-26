"""What the rules of the Docker socket proxy let through, in each mode:
the paths of the Docker API that match what the rules allow. HAProxy is
not run here, its regular expressions are read out of the rules."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from claude_airlock import settings
from claude_airlock.sandbox.socket_proxy import PROXY_RULES

DOCKERFILE_DIR = settings.DOCKERFILE_DIR
SocketAccess = settings.SocketAccess

ACL = re.compile(r"^\s*acl\s+(\w+)\s+path -m reg (\S+)$", re.MULTILINE)
ALLOW = re.compile(r"^\s*http-request allow if (.+)$", re.MULTILINE)

# Reads that a mode may answer from the daemon, by the first mode that does
LIMITED_READS = (
    "/_ping",
    "/v1.47/version",
    "/containers/json",
    "/v1.47/containers/json",
    "/v1.47/containers/web_1/logs",
)
FULL_READS = (
    "/v1.47/info",
    "/v1.47/events",
    "/v1.47/containers/web_1/json",
    "/v1.47/containers/0123abcd/stats",
    "/containers/web.1/top",
)
# What no mode answers: GETs that write to a container or hand out its
# files, what is not a container's, and paths made to pass for an allowed one
NEVER = (
    "/v1.47/containers/web_1/attach/ws",
    "/v1.47/containers/web_1/archive",
    "/v1.47/containers/web_1/export",
    "/v1.47/containers/web_1/changes",
    "/v1.47/containers/web_1/json/../attach/ws",
    "/v1.47/containers/web_1/attach/ws/json",
    "/v1.47/containers/web_1%2Fattach%2Fws/json",
    "/v1.47/containers/web_1/logs/",
    "/v1.47/containers/a/b/logs",
    "/v1.47/images/json",
    "/v1.47/volumes",
    "/v1.47/networks",
    "/v1.47/exec/0123abcd/json",
    "/v1.47/containers",
    "//containers/json",
    "/v1.47/v1.47/containers/json",
)


def allowed_paths(mode: SocketAccess) -> list[re.Pattern[str]]:
    """The patterns of the paths the rules of a mode pass on to the
    daemon."""
    rules = Path(DOCKERFILE_DIR, PROXY_RULES[mode]).read_text()
    patterns = dict(ACL.findall(rules))
    (allow,) = ALLOW.findall(rules)
    return [re.compile(patterns[name]) for name in allow.split(" or ")]


def passes(mode: SocketAccess, path: str) -> bool:
    # HAProxy's reg is a search, as the rules are anchored for
    return any(pattern.search(path) for pattern in allowed_paths(mode))


@pytest.mark.parametrize("mode", list(PROXY_RULES))
class SocketRulesTest:
    def test_what_every_mode_reads_passes(self, mode: SocketAccess):
        for path in LIMITED_READS:
            assert passes(mode, path), path

    def test_what_writes_or_reads_files_never_passes(self, mode: SocketAccess):
        for path in NEVER:
            assert not passes(mode, path), path

    def test_every_pattern_is_anchored_at_both_ends(self, mode: SocketAccess):
        for pattern in allowed_paths(mode):
            assert pattern.pattern.startswith("^"), pattern.pattern
            assert pattern.pattern.endswith("$"), pattern.pattern

    def test_only_reads_are_let_through(self, mode: SocketAccess):
        rules = Path(DOCKERFILE_DIR, PROXY_RULES[mode]).read_text()
        refusal = rules.index("http-request deny unless METH_GET")
        assert refusal < rules.index("http-request allow")
        # Whatever no rule allowed is denied, not passed on
        assert re.search(r"http-request allow .*\n\s*http-request deny\n", rules)


class ModesTest:
    def test_the_real_inspect_stats_and_top_are_of_full_alone(self):
        for path in FULL_READS:
            assert passes(SocketAccess.FULL, path), path
            assert not passes(SocketAccess.LIMITED, path), path

    def test_full_passes_nothing_that_asks_for_another_protocol(self):
        rules = Path(DOCKERFILE_DIR, PROXY_RULES[SocketAccess.FULL]).read_text()
        refusal = rules.index("http-request deny if { req.hdr(Upgrade) -m found }")
        assert refusal < rules.index("http-request allow")
