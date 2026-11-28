#!/usr/bin/env bash
set -euo pipefail

bundle=${1:?absolute staged bundle directory required}
manifest_digest=${2:?operator manifest SHA-256 required}
context=${3:-desktop-linux}
[[ $bundle == /* && -d $bundle ]]
endpoint=$(docker context inspect "$context" --format '{{.Endpoints.docker.Host}}')
[[ $endpoint == unix://* ]] || { printf 'Use a local Docker context.\n' >&2; exit 1; }
python3 -B "$bundle/run-case.py" --manifest-sha256 "$manifest_digest" verify-bundle

docker --context "$context" run --rm --platform linux/amd64 --network none \
  --mount "type=bind,src=$bundle,dst=/bundle,readonly" --entrypoint /bin/sh \
  docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 \
  -ec '
    assets=/bundle/bootstrap-assets
    outcome=$(python -B /bundle/bootstrap_assets.py prepare-k3s "$assets")
    test "$outcome" = installed
    install -d /tmp/fixture-systemd /tmp/fixture-bin
    # The official installer writes the service file and does not start it.
    printf "%s\n" "#!/bin/sh" "exit 66" >/tmp/fixture-bin/systemctl
    chmod 0755 /tmp/fixture-bin/systemctl
    PATH="/tmp/fixture-bin:$PATH" INSTALL_K3S_VERSION=v1.36.6+k3s1 INSTALL_K3S_BIN_DIR=/usr/local/bin \
      INSTALL_K3S_SYSTEMD_DIR=/tmp/fixture-systemd INSTALL_K3S_SKIP_DOWNLOAD=true \
      INSTALL_K3S_SKIP_ENABLE=true INSTALL_K3S_SKIP_START=true INSTALL_K3S_EXEC=server \
      sh "$assets/install-k3s.sh"
    grep -F "ExecStart=/usr/local/bin/k3s" /tmp/fixture-systemd/k3s.service
    grep -F -- "server" /tmp/fixture-systemd/k3s.service
    /usr/local/bin/k3s --version >/tmp/fixture-version
    test "$(awk '"'"'NR == 1 {print $3}'"'"' /tmp/fixture-version)" = v1.36.6+k3s1
    cat /tmp/fixture-version
    outcome=$(python -B /bundle/bootstrap_assets.py prepare-k3s "$assets" --active)
    test "$outcome" = reused
    printf "%s\n" "verified staged install and exact retry"
  '
