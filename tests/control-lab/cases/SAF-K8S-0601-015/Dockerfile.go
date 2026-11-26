# syntax=docker/dockerfile:1.7
# Docker Official Image multi-platform index; see README for provenance.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS go-builder
ARG TARGETOS
ARG TARGETARCH
ARG BUILDARCH
WORKDIR /src
COPY go.mod server.go ./
RUN set -eux; \
    test -x /usr/local/go/bin/go; \
    test -x "/usr/local/go/pkg/tool/linux_${BUILDARCH}/compile"; \
    test -x /sbin/apk; \
    go version; \
    "/usr/local/go/pkg/tool/linux_${BUILDARCH}/compile" -V; \
    apk --version; \
    mkdir -p /out; \
    env GO111MODULE=on GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
      CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/server .; \
    go version -m /out/server; \
    sha256sum /out/server

FROM scratch AS go-runtime
ARG TARGETOS
ARG TARGETARCH
LABEL org.opencontainers.image.title="SAF 0601-015 static readiness fixture" \
      org.opencontainers.image.description="Inert standard-library HTTP readiness and metadata server" \
      saf-k8s.example.target-os="${TARGETOS}" \
      saf-k8s.example.target-arch="${TARGETARCH}" \
      saf-k8s.example.builder="docker.io/library/golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab"
COPY --from=go-builder --chown=65532:65532 /out/server /server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
