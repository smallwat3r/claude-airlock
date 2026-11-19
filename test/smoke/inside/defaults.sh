# shellcheck shell=bash
# The tildes below are in descriptions that are printed, not in paths
# shellcheck disable=SC2088
# A session with the default settings. run.sh leaves the checksum of the
# host's login in .smoke-login, in the project.

check "runs as the host user, the owner of the project" [ "$(id -u)" = "$(stat -c %u .)" ]
check "holds no capabilities" grep -q "^CapEff:.0000000000000000$" /proc/self/status
check_fails "root filesystem is read-only" touch /smoke-probe
check "/tmp is writable" touch /tmp/smoke-probe
check "~/.cache is writable" touch "/home/sandbox/.cache/smoke-probe"
check "project is mounted read-write" touch written-by-session
check_fails ".env is shadowed" [ -s .env ]
check ".env.example stays readable" [ -s .env.example ]
check_fails "settings.json is read-only" [ -w /home/sandbox/.claude/settings.json ]
check_fails "skills are read-only" [ -w /home/sandbox/.claude/skills ]
check "CLAUDE.md lists the installed tools" grep -q "^- Python 3 with uv" /etc/claude-code/CLAUDE.md
check_fails "CLAUDE.md has no template placeholder" grep -q Placeholder /etc/claude-code/CLAUDE.md
check_fails "the transcripts of another project are out of sight" \
  [ -e /home/sandbox/.claude/projects/-claude-smoke-another-project/session.jsonl ]
check "the prompt history is there to add to" [ -w /home/sandbox/.claude/history.jsonl ]
check "the file history is there to add to" touch /home/sandbox/.claude/file-history/smoke-probe
check_fails "the sessions of the host are out of sight" \
  [ -e /home/sandbox/.claude/sessions/smoke-host-session ]
check "~/.claude is writable" touch /home/sandbox/.claude/smoke-probe
check "the plugins of the host are there" [ -e /home/sandbox/.claude/plugins/smoke-host-plugin ]
check "the login is that of the host" \
  [ "$(sha256sum </home/sandbox/.claude/.credentials.json)" = "$(cat .smoke-login)" ]
check "claude starts" claude --version
check "egress is open" curl -fsS -m 15 -o /dev/null https://example.com
# run.sh checks that the launcher reports this hook when the session ends
echo planted >.git/hooks/pre-commit
