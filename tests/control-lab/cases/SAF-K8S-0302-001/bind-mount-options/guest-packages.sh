#!/usr/bin/env bash
# Opens signed APT repositories and installs the specific fixture dependencies.
set -euo pipefail
test "$(hostname)" = lima-mounttest
if findmnt -rn -t virtiofs,9p | grep -q .; then exit 41; fi
cd /tmp/saf-cri-candidate
sudo -n apt-get update -o Acquire::Retries=2 -o Acquire::Languages=none
sudo -n apt-get -y --no-install-recommends install \
    conmon=2.1.12-4 crun=1.21-1 libgpgme11t64=1.24.2-3+deb13u1 \
    gpg=2.4.7-21+deb13u1+b5 conntrack=1:1.4.8-2+b1 \
    golang-github-containers-common=0.62.2+ds1-2
curl --retry 2 -fsSL https://pkgs.k8s.io/core:/stable:/v1.37/deb/Release.key -o kubernetes-release.asc
key_fingerprint=$(gpg --batch --with-colons --show-keys kubernetes-release.asc | awk -F: '$1=="fpr" && !seen++ { print $10 }')
test "$key_fingerprint" = DE15B14486CD377B9E876E1A234654DA9A296436
sudo -n install -d -m 755 /etc/apt/keyrings
gpg --batch --dearmor < kubernetes-release.asc |
    sudo -n tee /etc/apt/keyrings/saf-kubernetes-v1.37.gpg >/dev/null
printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/saf-kubernetes-v1.37.gpg] https://pkgs.k8s.io/core:/stable:/v1.37/deb/ /' |
    sudo -n tee /etc/apt/sources.list.d/saf-kubernetes-v1.37.list >/dev/null
sudo -n apt-get update -o Acquire::Retries=2 -o Acquire::Languages=none
sudo -n apt-get -y --no-install-recommends install \
    kubelet=1.37.0-1.1 kubeadm=1.37.0-1.1 kubectl=1.37.0-1.1 cri-tools=1.37.0-1.1 kubernetes-cni=1.9.1-1.1
