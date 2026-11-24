#!/bin/sh
# Build the fixture node from the verified upstream arm64 release archive.
set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s BUILD_DIRECTORY\n' "$0" >&2
    exit 2
fi
mkdir -p "$1"
build_dir=$(cd "$1" && pwd)
archive="$build_dir/kubernetes-server-linux-arm64.tar.gz"
archive_url=https://dl.k8s.io/v1.36.6/kubernetes-server-linux-arm64.tar.gz
archive_sha=b98364acbd4ce469bc38c57668dbee057008846b029f0980d613861dd3a10817
base_image=docker.io/kindest/base@sha256:f10f029b85aa89e7b47a2e6afacf560595c8abcefaa0e96096b854361b740127
image=saf-lab-kindest:v1.36.6-b98364acbd4c

export DOCKER_CONTEXT=${DOCKER_CONTEXT:-desktop-linux}
export KIND_EXPERIMENTAL_PROVIDER=docker
unset DOCKER_HOST KUBECONFIG KIND_CLUSTER_NAME
endpoint=$(docker context inspect "$DOCKER_CONTEXT" --format '{{.Endpoints.docker.Host}}')
case "$endpoint" in
    unix://*) ;;
    *) printf 'Select a local Docker Unix socket.\n' >&2; exit 2 ;;
esac
case "$(docker info --format '{{.Architecture}}')" in
    arm64|aarch64) ;;
    *) printf 'This fixture requires a Linux/arm64 Docker engine.\n' >&2; exit 2 ;;
esac
case "$(kind version)" in
    'kind v0.32.0 '*) ;;
    *) printf 'Use the verified Kind v0.32.0 builder for this fixture.\n' >&2; exit 2 ;;
esac

current=$(curl --fail --silent --show-error --location --retry 2 --max-time 60 "$archive_url.sha256")
[ "$(printf '%s' "$current" | tr -d '[:space:]')" = "$archive_sha" ]
verify_archive() {
    printf '%s  %s\n' "$archive_sha" "$archive" | shasum -a 256 -c -
}
if ! verify_archive >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --continue-at - --max-time 1200         --output "$archive" "$archive_url"
fi
verify_archive >&2

docker pull --platform linux/arm64 "$base_image" >&2
kind build node-image "$archive" --arch arm64 --type file --base-image "$base_image" --image "$image" >&2
docker image inspect "$image" --format '{{.Id}}'
