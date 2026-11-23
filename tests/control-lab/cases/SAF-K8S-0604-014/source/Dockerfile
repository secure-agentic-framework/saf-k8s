FROM docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
ARG SAF_SOURCE_COMMIT
ARG SAF_SOURCE_ARCHIVE_SHA256
ARG SAF_LOCK_SHA256
ARG SAF_CONFIG_SHA256
LABEL org.opencontainers.image.revision="$SAF_SOURCE_COMMIT" \
      org.saf.source.snapshot.sha256="$SAF_SOURCE_ARCHIVE_SHA256" \
      org.saf.lock.sha256="$SAF_LOCK_SHA256" \
      org.saf.config.sha256="$SAF_CONFIG_SHA256"
COPY payload.txt /fixture-payload
USER 65534:65534
