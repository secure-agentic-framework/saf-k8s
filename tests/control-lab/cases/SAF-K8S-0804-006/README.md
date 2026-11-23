# SAF-K8S-0804-006 Authenticated artifact context

Requires a local Go toolchain, kubectl and Kind. The Go standard library encrypts a public fixture marker under an in-memory key. Kubernetes stores only ciphertext and a synthetic context in an immutable ConfigMap. The test compares an unbound baseline with authenticated context, observes denial for the wrong context and modified ciphertext, and opens the retrieved record using the expected context.

Run via the standard control lab entry point. Hardware-backed sealing, external key release and provider assurance require deployment evidence. This fixture does not persist the key or use a real platform measurement.
