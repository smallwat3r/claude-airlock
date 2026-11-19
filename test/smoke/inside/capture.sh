# shellcheck shell=bash
# A session with the network capture. run.sh then looks for these three
# connections in the capture (checks/capture.py).

check "egress is still open" curl -fsS -m 15 -o /dev/null https://example.com
check "a connection that is not HTTP works" bash -c "exec 3<>/dev/tcp/1.1.1.1/53"
check "a datagram goes out" bash -c "echo probe >/dev/udp/1.1.1.1/9999"
check "holds no capabilities" grep -q "^CapEff:.0000000000000000$" /proc/self/status
