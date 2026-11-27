# shellcheck shell=bash
# A session with the socket proxy (CLAUDE_AIRLOCK_DOCKER_SOCKET=1).

if ! command -v docker >/dev/null; then
  echo "skip the docker feature is not in this image"
  exit 0
fi
proxy=claude-airlock-ps-proxy
check "docker ps works" docker ps
check_fails "other docker calls are denied" docker volume ls
# docker logs inspects the container first, which is answered with a stub
check "docker logs works" docker logs --tail 1 "${proxy}"
check "inspect shows nothing of a container" \
  bash -c "[ \"\$(docker inspect --format '{{json .Config.Env}}' ${proxy})\" = null ]"
check "the proxy answers a read it allows" curl -fsS "${SOCKET_API}/json"
check_socket_denials
check "so is what runs in it" denied "${SOCKET_API}/${NO_CONTAINER}/top"
# Tells run.sh that docker was used, so the record of its calls can be checked
touch .smoke-docker-used
# The launcher polls for the address of the session every 0.2s and only
# reads the calls once it has it, so a shorter session is not noted
sleep 1
