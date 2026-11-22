#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(hostname)" = lima-mounttest
if findmnt -rn -t virtiofs,9p | grep -q .; then exit 41; fi
cd /tmp/saf-cri-candidate
if sudo -n test -e /etc/kubernetes/admin.conf; then
  printf '%s\n' 'Existing guest control-plane state requires inspection before another initialization'
  exit 44
fi
cat > kubeadm.yaml <<'EOF'
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
nodeRegistration:
  name: lima-mounttest
  criSocket: unix:///var/run/crio/crio.sock
  taints: []
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: v1.37.0
networking:
  podSubnet: 10.85.0.0/16
apiServer:
  extraArgs:
    - name: feature-gates
      value: VolumeBindMountOptions=true
dns:
  disabled: true
proxy:
  disabled: true
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
featureGates:
  VolumeBindMountOptions: true
EOF
if ! sudo -n kubeadm init --config kubeadm.yaml --skip-token-print --skip-phases=bootstrap-token,show-join-command > kubeadm-private.log 2>&1; then
  grep -E '(^\[preflight\].*[Ee]rror|^\[ERROR |^error execution phase|connection refused|failed to pull|error pulling|timed out|container runtime)' kubeadm-private.log | tail -22 || true
  exit 45
fi
kubectl() { sudo -n /usr/bin/kubectl --kubeconfig /etc/kubernetes/admin.conf "$@"; }
kubectl wait --for=condition=Ready node/lima-mounttest --timeout=120s
kubectl version -o json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["serverVersion"]["gitVersion"]); assert d["serverVersion"]["gitVersion"]=="v1.37.0"'
kubectl get node lima-mounttest -o json | python3 -c 'import json,sys; d=json.load(sys.stdin)["status"]; feature="VolumeBindMountOptions" in d.get("declaredFeatures",[]); print(json.dumps({"nodeDeclaresFeature":feature, "runtime":d["nodeInfo"]["containerRuntimeVersion"], "kubelet":d["nodeInfo"]["kubeletVersion"]})); assert feature and d["nodeInfo"]["containerRuntimeVersion"].startswith("cri-o://")'
