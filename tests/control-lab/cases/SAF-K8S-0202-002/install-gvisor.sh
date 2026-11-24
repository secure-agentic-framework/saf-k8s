set -eu
work=$(mktemp -d /tmp/saf-gvisor.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
tar -xzf - -C "$work" --no-same-owner --no-same-permissions
test ! -e /usr/local/bin/runsc
test ! -e /usr/local/bin/containerd-shim-runsc-v1
test ! -e /usr/local/bin/gvisor-bin
install -m 0755 "$work/runsc" /usr/local/bin/runsc
install -m 0755 "$work/containerd-shim-runsc-v1" /usr/local/bin/containerd-shim-runsc-v1
install -d -m 0755 /usr/local/bin/gvisor-bin
for sidecar in "$work"/gvisor-bin/*; do
  install -m 0755 "$sidecar" /usr/local/bin/gvisor-bin/"${sidecar##*/}"
done
/usr/local/bin/runsc --version | grep -F release-20261116.0
cat > /etc/containerd/runsc-saf-gvisor.toml <<'INNER'
[runsc_config]
platform = "systrap"
INNER
chmod 0644 /etc/containerd/runsc-saf-gvisor.toml
