# shellcheck shell=bash
# A session with the socket proxy (CLAUDE_AIRLOCK_DOCKER_SOCKET=1).

if ! command -v docker >/dev/null; then
  echo "skip the docker feature is not in this image"
  exit 0
fi
check "docker ps works" docker ps
check_fails "other docker calls are denied" docker volume ls
# Straight to the proxy, as a session can: what writes to a container or
# hands out its files is refused, whatever the method it comes by
api="http://${DOCKER_HOST#tcp://}"
own="$(docker ps --quiet | head -n 1)"
check "the proxy answers a read it allows" curl -fsS "${api}/containers/json"
check_fails "a write is denied" curl -fsS -X POST "${api}/containers/${own}/stop"
check_fails "the input of a container is out of reach" \
  curl -fsS "${api}/containers/${own}/attach/ws?stream=1&stdin=1"
check_fails "the files of a container are out of reach" \
  curl -fsS "${api}/containers/${own}/archive?path=/etc"
check_fails "so is the whole of one" curl -fsS "${api}/containers/${own}/export"
# Tells run.sh that docker was used, so the record of its calls can be checked
touch .smoke-docker-used
# The launcher polls for the address of the session every 0.2s and only
# reads the calls once it has it, so a shorter session is not noted
sleep 1
