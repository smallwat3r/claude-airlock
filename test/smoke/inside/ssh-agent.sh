# shellcheck shell=bash
# A session with the SSH agent (CLAUDE_AIRLOCK_SSH_AGENT=1).

# ssh-add exits with 0 when it lists keys and 1 when the agent has none.
# Either way the agent answered.
check "the agent answers through the launcher" bash -c "ssh-add -l; [ \$? -le 1 ]"
