FROM docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
ARG SOURCE_SHA=cab6acc7cd24156461b54f94a64f2f33f9be34dc
RUN apt-get -q update && apt-get -qy --no-install-recommends install \
    gcc libbtrfs-dev libseccomp-dev libsubid-dev libsystemd-dev make pkg-config
RUN apt-get -qy --no-install-recommends install libgpgme-dev
WORKDIR /work
COPY source.tgz /tmp/source.tgz
RUN printf '%s  %s\n' f5f187169ee5bb43a4c603cf65c089d93f46778d1271b59539d9986d22519374 /tmp/source.tgz | sha256sum -c - \
    && tar -xzf /tmp/source.tgz --strip-components=1
ENV GOTOOLCHAIN=local
ENV GOFLAGS="-mod=vendor -trimpath"
RUN make -j2 binaries BUILD_COMMIT="$SOURCE_SHA" BUILD_DATE=2026-11-21T00:00:00Z \
    && mkdir /result \
    && cp bin/crio bin/pinns /result/ \
    && go version > /result/toolchain.txt \
    && dpkg-query -W gcc libbtrfs-dev libgpgme-dev libseccomp-dev libsubid-dev libsystemd-dev make pkg-config > /result/build-packages.txt \
    && cd /result && sha256sum crio pinns > SHA256SUMS
FROM scratch
COPY --from=build /result/ /
