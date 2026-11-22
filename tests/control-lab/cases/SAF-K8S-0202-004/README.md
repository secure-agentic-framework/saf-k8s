# SAF-K8S-0202-004 — Runtime socket mount prevention

Run via `lab.py test SAF-K8S-0202-004` in the SAF control lab. The fixture sets
the namespace's Pod Security Admission (PSA) `enforce=baseline` policy pinned
to v1.36, confirms two harmless hostPath Pod requests are admitted before the
policy and denied after it, then proves a restricted no-hostPath Pod is admitted
and Ready. Both hostPath probes use nonexistent paths and server dry-run only;
they are never persisted or run.

The case also runs the exact pinned Kaniko v1.28.5 image against a ConfigMap
build context with `--no-push`, `--no-push-cache`, `--cache=false`, and no
hostPath. It preserves the original docker-save archive payload check and
independently verifies the OCI layout index, manifest, config and layer
descriptors against exact blob bytes and their hashes. `--reproducible` strips
timestamps; output digests are still retained as raw measurements and are not
used as stable check observations. `lab.evidence/kaniko-image-measurements.raw.json`
is the raw measurement filename in the runner's evidence directory.

This is a local Kubernetes v1.36.1 fixture result. It does not establish
production namespace coverage, PSA exemptions or configuration, behavior for
other admission paths, protection of non-Pod resources, a cluster-wide
runtime-socket policy, or production CI builder identity/configuration.
