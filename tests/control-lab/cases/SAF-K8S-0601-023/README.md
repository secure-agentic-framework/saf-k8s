# SAF-K8S-0601-023 — scoped pull-credential rotation reference

Run `python3 lab.py test SAF-K8S-0601-023` from the control-lab directory.

## Design and evidence boundary

The first three checks cover suspended scheduling, a controller-owned
scheduled marker update, and live ConfigMap propagation to the same two Pods.
The 0601-022 helper creates a pinned case-owned registry, issues synthetic
basic-auth credentials, tests a wrong-credential denial, synchronizes a
private pull Secret through pinned ESO, and proves that a Pod pulls the exact
image digest with an empty cache.

This case rotates the credential after the 0601-022 helper confirms the
first pull and before it cleans up the registry. It receives case-owned
identifiers, the exact image and digest, and paths in the helper's private
temporary directory. It reads the synthetic credential from its fixture file.

The callback rotates only this fixture's credential. It writes a new bcrypt
hash into the exact mounted htpasswd file, verifies the file changed in place
and its mtime changed, updates the local webhook provider's Secret, and changes
the ExternalSecret's bounded periodic interval to five seconds. It then checks
that the Secret owned by the exact ExternalSecret has a changed fingerprint,
contains the new in-memory fixture value, is Ready, has a later refreshTime,
and has a sanitized provider HTTP 200 read. Passwords, auth JSON, bcrypt hashes,
raw Secret bytes, and logs are not placed in command output or evidence.

It sends one old and one new Basic-auth request to the owned registry through
its 127.0.0.1-mapped port and retains only HTTP statuses and the matching
access-log status/path records. The old credential must receive 401 and the new
one 200. It then deletes the initial successful pull Pod and removes only its
exact stopped runtime container and image digest from the owned Kind node. A
new Pod must pull that same exact digest using the refreshed Kubernetes Secret,
with a registry manifest 200 and a successful inert marker command. This rules
out using the previously cached image as the positive result.

The nine checks cover the original three scheduled marker comparisons,
four checks from the existing private-pull helper, and two credential
rotation checks. The helper exercises both ESO authorization and the
authenticated private image pull.
This is a local, synthetic registry rotation and periodic ESO reconciliation
proof. It does not establish provider-wide expiration, real issuer behavior,
managed-registry revocation, or customer fleet coverage; keep
`saf-lab-0601-023.1` open for adopter-specific issuance, expiry, scheduling,
revocation and deployment evidence.

## Pinned-source rationale

- The companion case pins registry `registry:3.0.0` by digest. The official
  [Distribution v3.0.0 htpasswd authenticator source](https://github.com/distribution/distribution/blob/v3.0.0/registry/auth/htpasswd/access.go)
  checks the configured file's modification time and re-parses the file when
  it changes. This is the basis for the fixture's in-place mtime rotation; the
  candidate also requires direct 401/200 observations instead of relying on a
  changed-file marker.
- The companion pins External Secrets Operator chart/image v2.15.0. Its
  [versioned ExternalSecret API documentation](https://github.com/external-secrets/external-secrets/blob/v2.15.0/docs/api/externalsecret.md)
  describes `Periodic` refresh and `refreshInterval`; the candidate observes
  the new `status.refreshTime` and target Secret result after a scoped 5-second
  test interval. The fixture does not claim an external provider watch or a
  universal refresh deadline.
- The companion [case README](../SAF-K8S-0601-022/README.md)
  lists its ESO v2.15.0 release, API, and Kubernetes v1.36 image-pull sources.
  Its code pins the registry image, ESO chart/image, Skopeo and BusyBox digest.
- [Kubernetes v1.36 imagePullSecrets](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod)
  documents the Pod reference used by the post-rotation pull.

All auth requests stay on the case-owned registry's loopback mapping or its
private Docker network. The provider URL and target Secret remain the existing
0601-022 fixture objects. No arbitrary registry, real credential, or external
provider is contacted.
