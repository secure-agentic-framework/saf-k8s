FROM scratch
ADD busybox-rootfs.tar /
SHELL ["/bin/busybox", "sh", "-c"]
ARG MARKER_URL
RUN /bin/busybox wget -q -T 4 -O /owned-marker "$MARKER_URL"     && /bin/busybox grep -qx known-owned-marker /owned-marker     && echo "OWNED_MARKER_REACHED"
