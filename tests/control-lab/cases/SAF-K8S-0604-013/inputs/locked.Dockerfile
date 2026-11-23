FROM scratch
ADD busybox-rootfs.tar /
SHELL ["/bin/busybox", "sh", "-c"]
COPY inputs/ /fixture/
ARG MARKER_URL
WORKDIR /fixture
RUN --network=none if /bin/busybox wget -q -T 2 -O /tmp-owned-marker "$MARKER_URL"; then       echo "ISOLATION_UNEXPECTED_NETWORK"; exit 33;     fi     && echo "OWNED_MARKER_UNREACHABLE"     && { [ -f package.txt ] || { echo "LOCKED_FIXTURE_INPUT_MISSING"; exit 35; }; }     && { /bin/busybox sha256sum -c dependencies.sha256 || { echo "LOCKED_FIXTURE_INPUT_MISMATCH"; exit 36; }; }     && /bin/busybox cp package.txt /approved-payload
USER 65534:65534
ENTRYPOINT ["/bin/busybox", "cat", "/approved-payload"]
