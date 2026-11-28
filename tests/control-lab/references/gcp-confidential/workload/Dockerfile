ARG GO_BUILDER_IMAGE=golang:1.25-alpine
ARG RUNTIME_IMAGE=alpine:3.22

FROM --platform=$BUILDPLATFORM ${GO_BUILDER_IMAGE} AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod main.go ./
ARG BUILD_VARIANT=baseline
ARG WIF_PROJECT_NUMBER
ARG WIF_POOL
ARG WIF_PROVIDER=attestation-verifier
ARG FIXTURE_BUCKET=
ARG FIXTURE_OBJECT=fixture.marker
ARG FIXTURE_SHA256
ARG RESOURCE_MODE=gcs
ARG KMS_KEY_NAME
RUN test -n "${WIF_PROJECT_NUMBER}" && test -n "${WIF_POOL}" && test -n "${FIXTURE_SHA256}" && \
    if [ "${RESOURCE_MODE}" = "gcs" ]; then test -n "${FIXTURE_BUCKET}" && test -n "${FIXTURE_OBJECT}"; \
    elif [ "${RESOURCE_MODE}" = "kms" ]; then test -n "${KMS_KEY_NAME}"; \
    else exit 1; fi
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.buildVariant=${BUILD_VARIANT} -X main.wifProjectNumber=${WIF_PROJECT_NUMBER} -X main.wifPool=${WIF_POOL} -X main.wifProvider=${WIF_PROVIDER} -X main.fixtureBucket=${FIXTURE_BUCKET} -X main.fixtureObject=${FIXTURE_OBJECT} -X main.fixtureSHA256=${FIXTURE_SHA256} -X main.resourceMode=${RESOURCE_MODE} -X main.kmsKeyName=${KMS_KEY_NAME}" -o /out/cpu-reference .

FROM ${RUNTIME_IMAGE}
RUN apk add --no-cache ca-certificates && adduser -D -u 65532 workload
COPY --from=build /out/cpu-reference /usr/local/bin/cpu-reference
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cpu-reference"]
LABEL "tee.launch_policy.nonroot_container"="nonrootonly"
LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.allow_env_override"="MODE,CPU_ROUNDS,EXPECT_ACCESS,NEGATIVE_CASE,KMS_CIPHERTEXT_B64,CHALLENGE_NONCE,CHALLENGE_AUDIENCE"
