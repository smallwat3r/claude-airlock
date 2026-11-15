#!/usr/bin/env bash
# Checks the launcher's security-relevant argument assembly without Docker:
# the launcher is sourced, docker is stubbed, and each case inspects the
# docker run arguments built for a throwaway home and project.
#
#   test/launcher-test.sh

# The snippets are meant to expand in the launcher's shell, not this one
# shellcheck disable=SC2016

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "${SANDBOX}"' EXIT
FAILED=0

# Run a snippet in a fresh shell with the launcher sourced, a fake home and
# project, and docker stubbed out. Prints one docker run argument per line.
# Extra arguments are VAR=value settings for the launcher's environment.
run_case() { # snippet [VAR=value]...
  local snippet="$1"
  shift
  rm -rf "${SANDBOX:?}/home"
  mkdir -p "${SANDBOX}/home/.claude/hooks" "${SANDBOX}/home/proj/.git/hooks" \
    "${SANDBOX}/home/ref"
  echo '{}' > "${SANDBOX}/home/.claude/settings.json"
  printf '[core]\n\tbare = false\n' > "${SANDBOX}/home/proj/.git/config"
  touch "${SANDBOX}/home/proj/.env" "${SANDBOX}/home/proj/.env.example" \
    "${SANDBOX}/home/proj/.netrc" "${SANDBOX}/home/proj/key.pem"
  (
    cd "${SANDBOX}/home/proj"
    env -i PATH="${PATH}" HOME="${SANDBOX}/home" "$@" bash -c '
      source "$1"
      docker() { return 1; }
      sidecar_running() { return 1; }
      start_sidecar() { echo "sidecar: $*"; }
      CONTAINER_NAME=test
      all_args() {
        base_args; protect_config_args; extra_dir_args; socket_proxy_args
        ssh_agent_args; git_config_args; shadow_env_files
        printf "%s\n" "${DOCKER_ARGS[@]}"
      }
      '"${snippet}" launcher-test "${ROOT}/bin/claude-docker"
  ) 2>&1 || true
}

check() { # description, expected (has|lacks), pattern, output
  local found=lacks
  if grep -qE -- "$3" <<< "$4"; then found=has; fi
  if [ "${found}" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1 (output $found /$3/)"
    FAILED=1
  fi
}

out="$(run_case all_args SSH_AUTH_SOCK=/tmp/agent.sock)"
check "project is mounted" has '/home/proj:.*/home/proj:z$' "${out}"
check ".env is shadowed" has '^/dev/null:.*/proj/\.env:ro$' "${out}"
check ".netrc is shadowed" has '^/dev/null:.*/proj/\.netrc:ro$' "${out}"
check ".env.example stays readable" lacks '\.env\.example' "${out}"
check "other files are not shadowed by default" lacks 'key\.pem' "${out}"
check "settings.json is read-only" has '\.claude/settings\.json:ro,z$' "${out}"
check "hooks are read-only" has '\.claude/hooks:ro,z$' "${out}"
check "ssh agent is off by default" lacks 'SSH_AUTH_SOCK|ssh-agent' "${out}"
check "docker socket is off by default" lacks 'DOCKER_HOST|sidecar' "${out}"
check "capabilities are dropped" has '^--cap-drop=ALL$' "${out}"
check "root filesystem is read-only" has '^--read-only$' "${out}"
check "no new privileges" has '^--security-opt=no-new-privileges$' "${out}"
check "cache is a per-project volume" has '^claude-cache-proj-[0-9a-f]{8}:/home/node/\.cache$' "${out}"
check "no TTY without a terminal" lacks '^-t$' "${out}"

out="$(run_case all_args SSH_AUTH_SOCK=/tmp/agent.sock CLAUDE_DOCKER_SSH_AGENT=1 \
  CLAUDE_DOCKER_SHADOW='*.pem' CLAUDE_DOCKER_RW_CONFIG=1 CLAUDE_DOCKER_CACHE=0 \
  CLAUDE_DOCKER_RUNTIME=runsc)"
check "ssh agent is forwarded on request" has '^SSH_AUTH_SOCK=/tmp/ssh-agent.sock$' "${out}"
check "extra shadow globs apply" has '^/dev/null:.*/proj/key\.pem:ro$' "${out}"
check "settings.json writable on request" lacks 'settings\.json' "${out}"
check "cache on tmpfs on request" has '\.cache:exec,size=2g$' "${out}"
check "runtime is passed through" has '^runsc$' "${out}"

# The socket checks need a socket file to exist, any will do
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' \
  "${SANDBOX}/docker.sock"
socket_case='DOCKER_SOCK="'"${SANDBOX}"'/docker.sock"; all_args'
out="$(run_case "${socket_case}" CLAUDE_DOCKER_SOCKET=1)"
check "socket mode 1 uses the limited sidecar" has '^sidecar: claude-docker-ps-proxy .*docker-socket-proxy\.cfg' "${out}"
check "socket mode 1 passes no allow switches" lacks 'CONTAINERS=1' "${out}"
out="$(run_case "${socket_case}" CLAUDE_DOCKER_SOCKET=full)"
check "socket mode full uses its own sidecar" has '^sidecar: claude-docker-proxy .*CONTAINERS=1' "${out}"
check "socket mode full blocks writes" has 'POST=0.*EXEC=0|EXEC=0.*POST=0' "${out}"

out="$(run_case 'add_ro_dir "${HOME}/ref"; all_args; printf "%s\n" "${CLAUDE_ARGS[@]}"')"
check "read-only dir is mounted read-only" has '/home/ref:.*/home/ref:ro,z$' "${out}"
check "read-only dir is passed to claude" has '^--add-dir$' "${out}"

out="$(run_case 'refuse_unsafe_dir "${HOME}"; echo survived')"
check "home directory is refused" lacks 'survived' "${out}"
out="$(run_case 'refuse_unsafe_dir /; echo survived')"
check "filesystem root is refused" lacks 'survived' "${out}"

out="$(run_case 'mkdir ~/claude-shared; add_shared_dir; all_args')"
check "default shared dir is mounted" has '/home/claude-shared:.*/home/claude-shared:z$' "${out}"
out="$(run_case 'mkdir ~/claude-shared; add_shared_dir; all_args' CLAUDE_DOCKER_SHARED_DIR="${SANDBOX}/home/ref")"
check "shared dir can be moved" has '/home/ref:.*/home/ref:z$' "${out}"
check "a moved shared dir replaces the default" lacks 'claude-shared' "${out}"
out="$(run_case 'mkdir ~/claude-shared; add_shared_dir; all_args' CLAUDE_DOCKER_SHARED_DIR=)"
check "empty shared dir setting mounts none" lacks 'claude-shared' "${out}"
out="$(run_case 'add_shared_dir; echo survived' CLAUDE_DOCKER_SHARED_DIR=/nonexistent)"
check "a missing named shared dir aborts" lacks 'survived' "${out}"

conf='mkdir -p ~/.config/claude-sandbox; printf "%s\n" "# limits" "" "CLAUDE_DOCKER_MEMORY=8g" "${EXTRA_LINE:-}" > ~/.config/claude-sandbox/config; load_user_config;'
out="$(run_case "${conf} all_args")"
check "config file sets a default" has '^--memory=8g$' "${out}"
out="$(run_case "${conf} all_args" CLAUDE_DOCKER_MEMORY=4g)"
check "environment wins over the config file" has '^--memory=4g$' "${out}"
out="$(run_case "${conf} echo survived" EXTRA_LINE='CLAUDE_DOCKER_NET_FILTR=1')"
check "config file rejects an unknown setting" lacks 'survived' "${out}"
out="$(run_case "${conf} echo survived" EXTRA_LINE='CLAUDE_DOCKER_EXTRA_DIRS=/tmp')"
check "config file rejects per-project settings" lacks 'survived' "${out}"
out="$(run_case "${conf} echo survived" EXTRA_LINE='PATH=/tmp/evil')"
check "config file rejects other variables" lacks 'survived' "${out}"
out="$(run_case "${conf} echo \"\${CLAUDE_DOCKER_SHADOW}\"" EXTRA_LINE='CLAUDE_DOCKER_SHADOW=$(echo pwned)')"
check "config file values are not evaluated" has '^\$\(echo pwned\)$' "${out}"

out="$(run_case 'feature_file ../../etc/passwd; echo survived')"
check "feature names cannot escape the directory" lacks 'survived' "${out}"
out="$(run_case 'selected_features | tr "\n" " "' CLAUDE_DOCKER_FEATURES='typst,go go')"
check "feature selection is sorted and unique" has '^go typst $' "${out}"
out="$(run_case 'prepare_image; echo "${IMAGE}"; echo "${CLAUDE_MD}"' CLAUDE_DOCKER_FEATURES=go)"
check "image tag is a content hash" has '^claude-code-sandbox:[0-9a-f]{12}$' "${out}"
check "CLAUDE.md lists a selected feature" has '^- Go ' "${out}"
check "CLAUDE.md omits unselected features" lacks 'KiCad' "${out}"
check "CLAUDE.md drops the template placeholder" lacks 'Placeholder' "${out}"

tamper='before="$(host_exec_fingerprint)"; %s; report_tampering "${before}"'
# shellcheck disable=SC2059 # the format string is the template above
out="$(run_case "$(printf "${tamper}" 'echo x > .git/hooks/pre-commit')")"
check "a new git hook is reported" has 'hooks/pre-commit$' "${out}"
# shellcheck disable=SC2059
out="$(run_case "$(printf "${tamper}" 'printf "[core]\n\tfsmonitor = evil\n" >> .git/config')")"
check "a git config change is reported" has '\.git/config$' "${out}"
# shellcheck disable=SC2059
out="$(run_case "$(printf "${tamper}" 'mkdir .claude; echo "{}" > .claude/settings.json')")"
check "new project claude settings are reported" has '\.claude/settings\.json$' "${out}"
# shellcheck disable=SC2059
out="$(run_case "$(printf "${tamper}" 'printf "[branch \"main\"]\n\tremote = origin\n" >> .git/config')")"
check "branch tracking is not reported" lacks 'changed files' "${out}"
# shellcheck disable=SC2059
out="$(run_case "$(printf "${tamper}" 'echo code > main.go')")"
check "ordinary edits are not reported" lacks 'changed files' "${out}"

exit "${FAILED}"
