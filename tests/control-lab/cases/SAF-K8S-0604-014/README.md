# Verify the approved source-to-image link

```sh
python3 lab.py test SAF-K8S-0604-014 --docker-context desktop-linux
```

A case-owned Git commit is matched against its reviewed tree and its lock and
build configuration hashes. The build uses only the archived commit, even
after the working copy changes. BuildKit emits provenance and Cosign
authenticates the registry-stored evidence. Kind runs the same image digest
after the release check accepts its source and build inputs.

The named fixture key and synthetic source cover this lab exercise. Production
builder trust, source approvals, and reproduced image bytes require separate
evidence.
