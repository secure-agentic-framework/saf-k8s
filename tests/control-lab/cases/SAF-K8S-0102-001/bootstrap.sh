#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${SAF_K8S_0102_001_DISPOSABLE_GUEST:-}" = I_OWN_THIS_DISPOSABLE_VM ]] \
  || die 'run only in the explicitly owned disposable guest'
[[ "$(id -u)" = 0 ]] || die 'root is required inside the guest'
[[ -r /etc/os-release ]] || die 'OS metadata unavailable'
. /etc/os-release
[[ "${ID:-}" = debian && "${VERSION_ID:-}" = 13 ]] || die 'Debian 13 guest required'
[[ "$(dpkg --print-architecture)" = arm64 ]] || die 'receipt pins cover ARM64 only'
systemd-detect-virt --vm >/dev/null || die 'a virtual machine is required'
[[ -z "$(findmnt -rn -t virtiofs,9p || true)" ]] || die 'guest must have no host shares'

unset DOCKER_HOST DOCKER_CONTEXT KUBECONFIG KIND_CLUSTER_NAME
export KIND_EXPERIMENTAL_PROVIDER=docker

tmp=$(mktemp -d /var/tmp/saf-k8s-0102-001-bootstrap.XXXXXXXX)
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT INT TERM HUP

# Keep Debian's signed repository metadata and package signatures mandatory;
# do not add third-party repositories or allow unauthenticated packages.
apt-get -o APT::Get::AllowUnauthenticated=false \
  -o Acquire::AllowInsecureRepositories=false \
  -o Acquire::AllowDowngradeToInsecureRepositories=false update
DEBIAN_FRONTEND=noninteractive apt-get \
  -o APT::Get::AllowUnauthenticated=false \
  -o Acquire::AllowInsecureRepositories=false \
  install -y --no-install-recommends \
  bash ca-certificates coreutils cryptsetup curl docker-cli docker.io e2fsprogs \
  findutils grep openssl python3 systemd util-linux

systemctl enable --now docker
systemctl is-active --quiet docker || die 'guest Docker daemon is not active'
[[ "$(docker context show)" = default ]] || die 'guest Docker context must be default'
endpoint=$(docker context inspect default --format '{{ .Endpoints.docker.Host }}')
[[ "$endpoint" = unix:///var/run/docker.sock ]] \
  || die 'Docker default context is not the guest-local Unix socket'

kind_url=https://kind.sigs.k8s.io/dl/v0.32.0/kind-linux-arm64
kubectl_url=https://dl.k8s.io/release/v1.36.1/bin/linux/arm64/kubectl
curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
  "$kind_url" -o "$tmp/kind"
curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
  "$kubectl_url" -o "$tmp/kubectl"
printf '%s  %s\n' \
  b92cd615e97585de8ddade28ed5cd7feb4248d717c233eea5b03c37298900f5d "$tmp/kind" \
  59f7ee8e477fae658447607dc3c8790ac17a1b016c01c622c12070e969e2d4e7 "$tmp/kubectl" \
  | sha256sum --check --status || die 'download checksum did not match the verified receipt'
install -o root -g root -m 0755 "$tmp/kind" /usr/local/bin/kind
install -o root -g root -m 0755 "$tmp/kubectl" /usr/local/bin/kubectl

[[ "$(kind version)" = "kind v0.32.0 go"* ]] || die 'installed Kind version mismatch'
[[ "$(kubectl version --client -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["clientVersion"]["gitVersion"])')" = v1.36.1 ]] \
  || die 'installed kubectl version mismatch'
[[ "$(docker context show)" = default ]] || die 'Docker context changed during installation'
[[ "$(docker context inspect default --format '{{ .Endpoints.docker.Host }}')" = unix:///var/run/docker.sock ]] \
  || die 'Docker endpoint changed during installation'
printf 'GUEST_BOOTSTRAP_VERIFIED=true\n'
printf 'GUEST_DOCKER_CONTEXT=default-local-unix-socket\n'
printf 'KIND_VERSION=v0.32.0\nKUBECTL_VERSION=v1.36.1\n'
