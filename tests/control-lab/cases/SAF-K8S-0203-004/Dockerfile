FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS compile
RUN apt-get update && apt-get install -y --no-install-recommends clang lld && rm -rf /var/lib/apt/lists/*
COPY marker.c /build/marker.c
RUN clang --target=aarch64-pc-windows-msvc -ffreestanding -fno-stack-protector -fshort-wchar -Os -c /build/marker.c -o /build/marker.obj \
    && lld-link /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 /out:/build/marker.efi /build/marker.obj

FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
    && apt-get install -y --no-install-recommends qemu-system-arm qemu-efi-aarch64 python3-virt-firmware openssl sbsigntool \
    && rm -rf /var/lib/apt/lists/*
COPY --from=compile /build/marker.efi /fixture/marker.efi
