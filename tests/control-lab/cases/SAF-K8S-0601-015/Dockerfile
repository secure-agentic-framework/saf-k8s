FROM docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec AS runtime-base

FROM runtime-base AS builder
COPY runtime-marker.txt /fixture/runtime-marker
COPY build-only-marker.txt /fixture/build-only-marker

FROM runtime-base AS image-with-build-marker
COPY --from=builder /fixture/runtime-marker /fixture/runtime-marker
COPY --from=builder /fixture/build-only-marker /fixture/build-only-marker
ENTRYPOINT ["/bin/busybox"]

FROM runtime-base AS image-runtime-only
COPY --from=builder /fixture/runtime-marker /fixture/runtime-marker
ENTRYPOINT ["/bin/busybox"]
