#!/usr/bin/env bash
set -euo pipefail
test "$(hostname)" = lima-mounttest
if findmnt -rn -t virtiofs,9p | grep -q .; then exit 41; fi
cd /tmp/saf-cri-candidate
sha256sum -c SHA256SUMS
if ldd ./crio | grep -q 'not found'; then exit 42; fi
sudo -n install -m 0755 crio pinns /usr/local/bin
sudo -n install -m 0755 -d /etc/crio/crio.conf.d /etc/cni/net.d
saf_pause=$(kubeadm config images list --kubernetes-version v1.37.0 | grep '/pause:')
test "$(printf '%s\n' "$saf_pause" | wc -l)" = 1
printf 'Sandbox image %s\n' "$saf_pause"
sudo -n tee /etc/crio/crio.conf.d/99-saf-mount-fixture.conf >/dev/null <<EOF
[crio.runtime]
default_runtime = "crun"
cgroup_manager = "systemd"
pinns_path = "/usr/local/bin/pinns"

[crio.runtime.runtimes.crun]
runtime_path = "/usr/bin/crun"
runtime_type = "oci"
monitor_path = "/usr/bin/conmon"

[crio.image]
pause_image = "$saf_pause"

[crio.network]
network_dir = "/etc/cni/net.d/"
plugin_dirs = ["/opt/cni/bin/"]
EOF
for saf_plugin in bridge host-local loopback; do test -x "/opt/cni/bin/$saf_plugin"; done
sudo -n tee /etc/cni/net.d/10-saf-fixture.conflist > /dev/null <<'EOF'
{"cniVersion":"1.0.0","name":"saf-mount-fixture","plugins":[{"type":"bridge","bridge":"cni0","isGateway":true,"ipMasq":true,"hairpinMode":true,"ipam":{"type":"host-local","subnet":"10.85.0.0/16","routes":[{"dst":"0.0.0.0/0"}]}}]}
EOF
sudo -n sysctl -w net.ipv4.ip_forward=1
sudo -n tee /etc/systemd/system/saf-crio-candidate.service >/dev/null <<'EOF'
[Unit]
Description=CRI-O candidate for disposable SAF mount-options review
After=network-online.target
Before=kubelet.service

[Service]
Type=notify
ExecStart=/usr/local/bin/crio
Delegate=yes
TasksMax=infinity
TimeoutStartSec=90
EOF
sudo -n systemctl daemon-reload
if ! sudo -n systemctl restart saf-crio-candidate.service; then
  sudo -n journalctl -u saf-crio-candidate.service -n 24 --no-pager
  exit 43
fi
sudo -n crictl --runtime-endpoint unix:///var/run/crio/crio.sock version
sudo -n crictl --runtime-endpoint unix:///var/run/crio/crio.sock info |
  python3 -c 'import json,sys; d=json.load(sys.stdin); f=d.get("features",{}); print(json.dumps({"features":f,"status":d["status"]},sort_keys=True)); assert f.get("mountOptions", f.get("mount_options")) is True'
dpkg-query -W -f='${Package}=${Version}\n' kubeadm kubelet kubectl cri-tools kubernetes-cni crun conmon libgpgme11t64
sha256sum /usr/local/bin/crio /usr/local/bin/pinns /usr/bin/{crun,conmon,crictl,kubeadm,kubectl,kubelet}
crun --version
