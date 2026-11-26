# Verify a Kubernetes CI handoff with separate evidence

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-018 --docker-context desktop-linux
```

A builder Job writes an inert artifact. A separate observer Job reads the
artifact and writes signed evidence. Each Job uses a projected Kubernetes
identity with distinct RBAC permissions. Only the observer mounts the
disposable signing key.

A receiving Job under its own ServiceAccount recomputes the artifact digest,
verifies the enrolled public key and observer signature, and checks the
evidence subject. Its identity reads the named inputs and can write the release
receipt. The test checks that it cannot write the artifact or evidence, and
that a correctly signed handoff with a wrong expected digest leaves its
release receipt empty.

In a deployment, inventory governed handoffs and the identities and permissions
on both sides. Retain the immutable artifact and evidence digest, signer
enrollment and version, and receiving-stage decision. Show an accepted handoff
and a wrong-subject or untrusted-signer rejection. Verify that production
builders cannot modify the evidence, enrolled trust policy, or release
decision. Record the release target and rollback procedure.
