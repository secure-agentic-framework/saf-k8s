# SAF-K8S-0903-006 — authenticated inference queue controls

From the SAF-K8S repository root, run this case with Docker, Kind, kubectl, Python and OpenSSL:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0903-006 --docker-context desktop-linux
```

The disposable Kind v1.36.1 fixture runs one application queue on a namespaced HTTPS Service. The digest-pinned Python workloads use ephemeral fixture certificates. Separate standard and priority clients present one authorized URI SAN each. The server derives the permitted class exclusively from the verified certificate.

The seven checks compare unbounded backlog, arrival-order dispatch, and execution of expired work with the enforced queue. An approved ordinary job runs exactly once. Unauthenticated state and submit requests are rejected, and a standard client remains denied when it sends a priority label. Two approved requests are accepted while dispatch is held. The next fixed request receives HTTP 429 and no work is executed for it. On release, the approved priority request runs first. Advancing the logical fixture clock expires another waiting request with zero executions.

## Adopter verification

- Inventory the actual admission, gateway and model-server queues, including retry paths. Record who owns each queue, how requests cross the boundary, and where identity is authenticated.
- In an authorized rehearsal, verify permitted and denied classes using deployment-owned test identities. Confirm priority derives from approved identity policy and verify missing credentials do not enqueue or disclose protected state.
- Exercise an approved small backlog against the configured depth, timeout, normal dispatch and eligible priority boundaries. Verify the exceeded request is shed, the expired request never begins work, authorized ordinary traffic still advances, and client retry guidance is correct.
- Check the real deadline and queue bounds through each deployed replica and relevant restart or failover. Retain before-and-after queue state, effective policy, bounded request IDs, timestamps and actual execution counts. Confirm receipt durability, monitoring and ownership where required.

[Inference queue policy in Triton](https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/user_guide/batcher.html) · [Kubernetes Pod scheduling priority](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/)
