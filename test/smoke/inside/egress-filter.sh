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
