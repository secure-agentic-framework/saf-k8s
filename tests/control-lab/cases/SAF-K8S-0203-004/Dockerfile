FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS compile
RUN apt-get update && apt-get install -y --no-install-recommends clang=1:19.0-63 lld=1:19.0-63 && rm -rf /var/lib/apt/lists/*
COPY marker.c /build/marker.c
RUN clang --target=aarch64-pc-windows-msvc -ffreestanding -fno-stack-protector -fshort-wchar -Os -c /build/marker.c -o /build/marker.obj \
    && lld-link /subsystem:efi_application /entry:efi_main /nodefaultlib /machine:arm64 /out:/build/marker.efi /build/marker.obj

FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
    && apt-get install -y --no-install-recommends qemu-system-arm=1:10.0.13+ds-0+deb13u1 qemu-efi-aarch64=2025.02-8+deb13u1 \
       python3-virt-firmware=24.11-2 openssl=3.5.9-1~deb13u1 sbsigntool=0.9.4-3.2+deb13u1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=compile /build/marker.efi /fixture/marker.efi
