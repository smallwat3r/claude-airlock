# shellcheck shell=bash
# A session with the socket proxy (CLAUDE_AIRLOCK_DOCKER_SOCKET=1).

if ! command -v docker >/dev/null; then
  echo "skip the docker feature is not in this image"
  exit 0
fi
check "docker ps works" docker ps
check_fails "other docker calls are denied" docker volume ls
# Tells run.sh that docker was used, so the record of its calls can be checked
touch .smoke-docker-used
# The launcher polls for the address of the session every 0.2s and only
# reads the calls once it has it, so a shorter session is not noted
sleep 1
