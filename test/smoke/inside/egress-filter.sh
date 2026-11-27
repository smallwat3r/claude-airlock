# shellcheck shell=bash
# A session with the egress filter (CLAUDE_AIRLOCK_NET_FILTER=1).

check "an allowed domain is reachable" curl -fsS -m 15 -o /dev/null https://api.github.com
# The proxy itself must refuse it. A proxy that is down would also make the
# request fail, but not with a 403.
check "another domain is blocked with a 403" \
  bash -c "curl -sS -m 15 -o /dev/null https://example.com 2>&1 | grep -q 403"
# An address of GitHub whose reverse DNS names an allowed domain. The filter
# must not trust the name that the owner of an address gives it.
check "an address is blocked whatever its reverse DNS says" \
  bash -c "curl -sS -m 15 -o /dev/null https://140.82.121.4 2>&1 | grep -q 403"
check_fails "direct connections fail" curl -fsS -m 5 --noproxy "*" -o /dev/null https://1.1.1.1
# A domain of the list, at a port the filter does not open
check "another port of an allowed domain is blocked with a 403" \
  bash -c "curl -sS -m 15 -o /dev/null https://api.github.com:8443 2>&1 | grep -q 403"
# Nothing is looked up past the proxy, of a domain of the list neither:
# docker's resolver knows the containers and sends nothing on
check_fails "a name outside is not looked up" getent hosts example.com
check_fails "nor one of an allowed domain" getent hosts api.github.com

# What ssh says of a host through the proxy, as git runs it. No key is
# given, so GitHub's refusal of the key is what says it was reached.
said_by_ssh() { # host
  sh -c "${GIT_SSH_COMMAND} -o BatchMode=yes -o ConnectTimeout=15 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -T git@$1" 2>&1
}
ssh_reached() { # host
  said_by_ssh "$1" | grep -q "Permission denied (publickey)"
}
ssh_refused() { # host
  said_by_ssh "$1" | grep -q 403
}
check "git over SSH goes through the proxy to an allowed host" ssh_reached github.com
check "and to another host it is blocked with a 403" ssh_refused example.com
