# shellcheck shell=bash
# A session with the socket proxy in full (CLAUDE_AIRLOCK_DOCKER_SOCKET=full).

if ! command -v docker >/dev/null; then
  echo "skip the docker feature is not in this image"
  exit 0
fi
proxy=claude-airlock-proxy
check "docker ps works" docker ps
check "docker inspect is the real one" \
  bash -c "[ \"\$(docker inspect --format '{{len .Id}}' ${proxy})\" = 64 ]"
check "docker logs works" docker logs --tail 1 "${proxy}"
check "docker top works" docker top "${proxy}"
check "docker stats works" docker stats --no-stream "${proxy}"
check "the info of the daemon is read" docker info
check_fails "other docker calls are denied" docker volume ls
check_socket_denials
check "a read that asks to become a WebSocket is denied" \
  denied -H "Connection: Upgrade" -H "Upgrade: websocket" \
  "${SOCKET_API}/${NO_CONTAINER}/json"
# Tells run.sh that docker was used, see socket-proxy.sh
touch .smoke-docker-full-used
sleep 1
