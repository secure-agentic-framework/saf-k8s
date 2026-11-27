# SAF-K8S-0908-006 Flower SecAgg+ reference

This runner is called after the outer eight-check network case. It performs two
bounded Flower 1.29.0 SecAgg+ rounds over three fixed, harmless numeric vectors
and groups exact-digest release of both aggregate-only receipts into one check.

## Topology and pins

The case-owned topology is four Pods: one Flower SuperLink and three SuperNodes.
It uses Flower's documented `subprocess` mode, so the ServerApp and each
ClientApp run under their parent process in the same Pod. This keeps each app subprocess inside its runtime Pod. All services stay inside the disposable Kind
cluster. The pinned images' unprivileged UID and GID are 49999. SuperNode runtime API uses loopback; the only Service exposes the
case-owned internal Fleet API. There are no host ports, Kubernetes API grants,
or real credentials.

`image-pins.json` records the official Flower 1.29.0 Docker Hub OCI index
digests and the Linux amd64/arm64 child descriptors retrieved for review.
`case.py` verifies the local image alias has the same Docker image ID as the
platform-manifest-pinned source before loading it into the case cluster. The app declares
`flwr==1.29.0` and declares its other direct import, `numpy`. Flower 1.29
defaults runtime dependency installation off for both SuperLink and SuperNode;
the candidate leaves it off. The 1.29 subprocess guide requires app dependencies
to be preinstalled in the parent images. A grouped preflight checks that the
digest-pinned images expose Flower 1.29.0 and NumPy in all four parent
environments before submitting the run. Flower's package metadata is pinned
exactly; NumPy's compatible range is recorded, while the selected NumPy build
is fixed by each immutable image digest. This does not create a portable lock
file for rebuilding those image contents. Rebuilding requires a separately
reviewed lock and derived-image build; this candidate itself does not build or
install images.

Flower 1.29 moved SuperLink connection profiles out of app `pyproject.toml`
into its configuration file. The candidate mounts a read-only Flower config
under `FLWR_HOME`, names the `fixture` connection, and binds the SuperLink
Control API explicitly to loopback at `127.0.0.1:9093`. The invocation is
`flwr run . fixture --stream` from a disposable writable copy of the mounted app. The app TOML
contains app metadata, components and the bounded workflow parameters only.

The legacy Secure Aggregation workflow uses a `NumPyClient` adapter on
each participant so the SecAgg+ mod consumes the expected FitRes fields.

The app runs two rounds with `num_shares=1.0`,
`reconstruction_threshold=1.0`, clipping range `8.0`, quantization range
`65536`, modulus `2**30`, max weight `3.0`, and a 45-second workflow timeout.
The fixed vectors are `[1.25, -2.5]`, `[3.75, 4.0]`, and `[5.5, 2.25]`. Round
one retains equal `num_examples=1` weights and checks `[3.5, 1.25]`; round two
uses fixed weights `1, 2, 3` and checks `[4.208333, 2.041667]` within the
quantization tolerance. Each round writes a distinct aggregate-only receipt.
Flower logs are not parsed as proof that no component ever observed an
individual update.

The runner executes the four Kubernetes checks in `base_case.py` before the
Flower round. Run `python3 lab.py test SAF-K8S-0908-006` from the control lab.

## Authorize the exact aggregates

After the Flower Pods are retired, the fixture starts five bounded support Pods
from the existing pinned helper and initializes its case-owned share records.
A separate release Pod using a projected Kubernetes ServiceAccount identity
reads each round receipt under named-resource permissions. For each round, a
wrong digest is refused; approval for the exact file digest and cohort returns
only that round's aggregate. The release identity cannot read an individual
share, and a different fixture identity cannot invoke the release policy or
read an aggregate. Both rounds are covered in one grouped assertion; the
helper's four unrelated lifecycle assertions are not run here.

## Evidence boundary

A successful run would prove that these pinned Flower components executed the
named SecAgg+ workflow for the fixed fixture and returned its aggregate. It
would not prove a formal security property, malicious-client resistance,
production trust/key custody, collusion assumptions, durable replay fencing,
operator separation, dropout recovery, or aggregate-disclosure policy. The
original synthetic dropout check remains a separate Kubernetes behavior.

## Primary sources

* [Flower 1.29 Secure Aggregation protocol overview](https://flower.ai/docs/framework/1.29/en/explanation-ref-secure-aggregation-protocols.html)
* [Flower 1.29 SecAggPlusWorkflow API](https://flower.ai/docs/framework/1.29/en/ref-api/flwr.server.workflow.SecAggPlusWorkflow.html)
* [Flower 1.29 Kubernetes deployment example](https://flower.ai/docs/framework/1.29/en/how-to-run-flower-on-gcp.html)
* [Flower 1.29 deployment runtime](https://flower.ai/docs/framework/1.29/en/how-to-run-flower-with-deployment-engine.html)
* [Flower 1.29 CLI reference](https://flower.ai/docs/framework/1.29/en/ref-api-cli.html)
* [Flower 1.29 configuration file](https://flower.ai/docs/framework/1.29/en/ref-flower-configuration.html)
* [Flower 1.29 run apps as subprocesses](https://flower.ai/docs/framework/1.29/en/docker/run-as-subprocess.html)
* [Official SuperLink image](https://hub.docker.com/r/flwr/superlink)
* [Official SuperNode image](https://hub.docker.com/r/flwr/supernode)
