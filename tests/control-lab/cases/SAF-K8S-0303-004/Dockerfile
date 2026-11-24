FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
    && apt-get install -y --no-install-recommends linux-image-arm64=6.12.118-1 busybox-static=1:1.37.0-6+b9 \
       qemu-system-arm=1:10.0.13+ds-0+deb13u1 apparmor=4.1.0-1 gcc libc6-dev cpio \
    && rm -rf /var/lib/apt/lists/*
COPY seccomp-probe.c /usr/local/share/saf/seccomp-probe.c
RUN gcc -static -std=c11 -O2 -Wall -Wextra -Werror -o /usr/local/bin/saf-record /usr/local/share/saf/seccomp-probe.c
