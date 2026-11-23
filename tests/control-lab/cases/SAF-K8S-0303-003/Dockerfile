FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends \
      linux-image-6.12.118+deb13-arm64=6.12.118-1 qemu-system-arm=1:10.0.13+ds-0+deb13u1 \
      busybox-static=1:1.37.0-6+b9 cpio selinux-policy-default=2:2.20250213-13~deb13u1 \
      policycoreutils=3.8.1-2 coreutils=9.7-3 libselinux1=3.8.1-1 && rm -rf /var/lib/apt/lists/*
