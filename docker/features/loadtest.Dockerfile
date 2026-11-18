# claude-feat: loadtest
# claude-feat-md: HTTP load testing: wrk, hey. Only against services the user owns or started in this sandbox

# Both from apt, so nothing to pin. Scenario tools (k6, locust) are left out,
# add one when ramp profiles or pass/fail thresholds are needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wrk hey \
    && rm -rf /var/lib/apt/lists/*
