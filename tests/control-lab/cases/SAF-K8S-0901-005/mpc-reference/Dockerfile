ARG base=docker.io/library/debian:bullseye-slim@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd
ARG upstream_platform=linux/amd64
FROM --platform=$upstream_platform ${base} AS upstream_runtime
FROM ${base}
COPY --from=upstream_runtime /lib/x86_64-linux-gnu /opt/mp-spdz/x86_64
COPY malicious-rep-bin-party.x /opt/mp-spdz/
COPY Programs /opt/mp-spdz/Programs
RUN test -x /opt/mp-spdz/x86_64/ld-2.31.so
