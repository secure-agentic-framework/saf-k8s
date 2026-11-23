# SAF-K8S-0802-001 Minimized driver rollout example

This case uses an actual Kubernetes DaemonSet to demonstrate version evidence, a controlled rollout, a readiness failure and recovery to the prior approved release. It observes the live process marker as well as Pod readiness. The release markers are synthetic. No vendor driver, kernel, GPU, vulnerability, or compatibility setting is exercised.
