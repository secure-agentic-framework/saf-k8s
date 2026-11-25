# Feature store scoped access case

This is a live Kubernetes case source for the SAF Kind runner. It is designed to run in namespace `saf-test`; it does not create a cluster. The runner creates the namespace and supplies `lab`, `fixtures.py`, and an evidence directory.

`case.py` loads `HERE.parent / "SAF-K8S-0908-001" / "case.py"` and calls its `load_runtime(lab)` to obtain the verified local Python fixture image. It does not use a scratch copy of that helper. The case creates its own ServiceAccounts, least-privilege TokenReview ClusterRole/Binding, TLS certificate/Secret, ConfigMaps, Services, and Pods through the runner's Kubernetes API.

## What it measures

- One named reader has a projected, 10-minute service-account token for audience `saf-feature-store`.
- Both gateway Pods authenticate each request by calling the live Kubernetes `authentication.k8s.io/v1` TokenReview API. The gateway checks authenticated identity and returned audience before policy evaluation.
- The coarse baseline grants that authenticated reader both groups and both named stores. The scoped gateway grants only `fixture-customer-profile` in both its online and offline paths; `fixture-device-health` is denied before returning feature data.
- Fixed, owned values are used. The offline response retains two event-time rows; the online response returns the latest entity value. Each has an explicit feature-definition version label; a mismatched label yields no data.
- The retained JSON contains response rows and a deterministic sanitized access log. Tokens, runtime observation timestamps, cluster IDs, and externally sourced data are omitted; the fixed event-time fields are benign fixture data.

The expected runner interface is `run(lab)`, `SCOPE`, and checks named `red`, `green`, and `positive`. PVCs are not used, so there are no PVC consumers or binding waits in this case.

## Evidence limits

This is an owned synthetic HTTP feature gateway, not Feast, Tecton, Vertex Feature Store, or a native database/object-store ACL. The check proves the gateway path in the live Kind control plane, not access through alternate endpoints or directly to storage. Review `../review.md` for primary references, store/version distinctions, and the production evidence needed before making deployment claims.

No Docker/Kind commands are run by this case itself. It relies on the paired runner's `load_runtime(lab)` contract for fixture image setup.

Each synthetic group and store has a separate immutable ConfigMap. The gateway
identities have independent named-object RBAC for online and offline backing
stores. Direct in-pod Kubernetes API requests prove the scoped gateway cannot
read either backing object for the denied group even if its application check
regresses. These backing objects model separate data paths. Repeat the checks
against the actual feature registry, data engines, and alternate access paths
where the control is deployed.

## Verify an adopting implementation

Verify the real feature-store identity and audience using authenticated API
requests. Test each online/offline feature group, deny paths, backing-store
ACLs and alternate direct access. The case uses Kubernetes TokenReview and
an owned synthetic HTTP feature gateway, not a native Feast/Tecton/cloud
store integration. The in-Pod backing-object requests also compare exact
named ConfigMap authorization under Kubernetes RBAC for both synthetic
stores. Repeat at the production backing permission boundary.
