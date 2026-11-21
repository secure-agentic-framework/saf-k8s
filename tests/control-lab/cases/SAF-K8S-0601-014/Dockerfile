FROM scratch
ARG PROBE_UID
COPY --chmod=0755 probe /probe
COPY --chmod=0666 fixture-marker /fixture-marker
USER ${PROBE_UID}:${PROBE_UID}
ENTRYPOINT ["/probe"]
