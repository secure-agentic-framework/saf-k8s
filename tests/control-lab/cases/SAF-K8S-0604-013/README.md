# Verify an isolated build using locked inputs

```sh
python3 lab.py test SAF-K8S-0604-013 --docker-context desktop-linux
```

This case pre-resolves its pinned BusyBox filesystem and stages a small file
with a committed SHA-256 lock. An isolated test network hosts one owned marker.
The connected BuildKit step reads it. The offline build checks the same marker
path is unavailable, then rejects missing or changed dependency bytes and
builds with the matching bytes. Kind executes the exact resulting OCI manifest
and emits those bytes.

The case uses a disposable BuildKit daemon and fixture network. The measured
scope is one execution step. Production fetch, cache, remote context and
reproducibility policies require separate evidence.

## Adopter verification

1. Map deployed builders, execution steps, source and remote contexts, base
   images, mirrors, caches, credentials, and direct/transitive dependencies.
2. Retain policy and builder evidence that each required input is pinned and
   verified, unapproved network paths are unavailable, and cache import/export
   cannot introduce unreviewed bytes.
3. In an isolated production-equivalent pipeline, compare approved locked
   inputs with a changed/missing dependency and a blocked egress marker. Retain
   repeatability evidence separately from the single-step fixture result.

Open child: `saf-lab-0604-013.2`. Native receipt: 5 checks.
