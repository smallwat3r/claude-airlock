# shellcheck shell=bash
# A session with both the egress filter and the network capture.

check "an allowed domain is reachable" curl -fsS -m 15 -o /dev/null https://api.github.com
check_fails "direct connections fail" curl -fsS -m 5 --noproxy "*" -o /dev/null https://1.1.1.1
