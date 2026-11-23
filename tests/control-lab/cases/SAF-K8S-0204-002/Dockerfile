FROM docker.io/falcosecurity/falcoctl:0.14.3@sha256:2230fb4802aafe09455b58d38f8f1faedd8f09f042e9a18fffd397e63488c023 AS plugin
USER 0
WORKDIR /plugins
RUN ["/usr/bin/falcoctl", "artifact", "install", "--resolve-deps=false", "--plugins-dir=/plugins", "ghcr.io/falcosecurity/plugins/plugin/k8saudit@sha256:1ff068506c425d8d7651758ededf02c3c35834189265c4753ad674c87504048b"]

FROM docker.io/falcosecurity/falco:0.45.2@sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e
COPY --from=plugin /plugins/libk8saudit.so /usr/share/falco/plugins/libk8saudit.so
