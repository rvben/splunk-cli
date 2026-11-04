#!/usr/bin/env bash
# Docker contexts / DOCKER_HOST can target a native x86 homelab machine.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${SPLUNK_ACCEPT_LICENSE:-} != yes ]]; then
    printf '%s\n' 'Set SPLUNK_ACCEPT_LICENSE=yes after accepting the Splunk license and current General Terms.' >&2
    exit 2
fi
architecture=$(docker info --format '{{.Architecture}}')
if [[ $architecture != x86_64 ]]; then
    printf '%s\n' 'Live tests require a native x86_64 Docker daemon; select an x86 homelab Docker context.' >&2
    exit 2
fi
case ${SPLUNK_TEST_VERSION:-10.6.1.1} in
    10.6.1.1) image=splunk/splunk@sha256:6d5227ed82bceaa277d79b1b3e97d8bd460ac6cf0f5df6c1cec95559284a796e ;;
    9.4.9) image=splunk/splunk@sha256:203b430ac01d251fd8b4797ae7986a0cdb004fd8807ab54c887d2892642c2695 ;;
    *) printf '%s\n' 'Unsupported SPLUNK_TEST_VERSION; choose 10.6.1.1 or 9.4.9.' >&2; exit 2 ;;
esac
id="splunk-cli-live-$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
runner="$id-runner"
server="$id-server"
cleanup() {
    result=$?
    if (( result != 0 )); then
        docker inspect --format 'Splunk state={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' "$server" 2>/dev/null || true
    fi
    docker rm -fv "$runner" "$server" >/dev/null 2>&1 || true
    docker image rm "$runner" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Compile before starting Splunk to avoid competing for host memory.
docker build -f tests/live/Dockerfile -t "$runner" .
docker pull "$image"
SPLUNK_PASSWORD=$(python3 -c 'import secrets; print("Aa1!" + secrets.token_urlsafe(32))')
export SPLUNK_PASSWORD
docker run -d --name "$server" --hostname splunk-cli-live \
    --network none \
    --label splunk-cli.live-test=true --memory 2g --memory-swap 2g --cpus 2 \
    --shm-size 256m --ulimit nofile=65536:65536 \
    -e SPLUNK_PASSWORD -e SPLUNK_START_ARGS=--accept-license \
    -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com "$image" >/dev/null
printf '%s\n' 'Waiting for Splunk provisioning and its image healthcheck (up to 600 seconds)...'
deadline=$((SECONDS + 600))
while :; do
    state=$(docker inspect --format '{{.State.Status}} {{.State.Health.Status}}' "$server")
    if [[ $state == 'running healthy' ]]; then
        break
    fi
    if [[ $state != running\ * ]] || (( SECONDS >= deadline )); then
        printf 'Splunk did not become healthy: %s\n' "$state" >&2
        exit 1
    fi
    sleep 2
done
# Sharing only this container's network gives loopback access without publishing
# a port on the host or connecting the CLI to a persistent Splunk installation.
docker run --init --name "$runner" --network "container:$server" \
    --label splunk-cli.live-test=true \
    --memory 512m --memory-swap 512m --cpus 1 --cap-drop ALL \
    --security-opt no-new-privileges -e SPLUNK_PASSWORD "$runner"
