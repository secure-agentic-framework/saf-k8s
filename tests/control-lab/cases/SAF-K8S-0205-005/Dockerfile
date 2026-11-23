FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS compile
RUN apt-get update && apt-get install -y --no-install-recommends clang=1:19.0-63 && rm -rf /var/lib/apt/lists/*
COPY marker.c /fixture/marker.c
RUN clang --target=bpfel -O2 -g -c /fixture/marker.c -o /fixture/marker.o

FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
    && apt-get install -y --no-install-recommends linux-image-arm64=6.12.118-1 busybox-static=1:1.37.0-6+b9 \
       qemu-system-arm=1:10.0.13+ds-0+deb13u1 bpftool=7.5.0+6.12.117-1 openssl=3.5.9-1~deb13u1 cpio \
    && rm -rf /var/lib/apt/lists/*
COPY --from=compile /fixture/marker.o /fixture/marker.o
