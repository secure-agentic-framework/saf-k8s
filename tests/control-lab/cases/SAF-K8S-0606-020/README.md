# SAF-K8S-0606-020 Verify Helm values and dependency integrity

Run `python3 tests/control-lab/lab.py test SAF-K8S-0606-020 --docker-context desktop-linux` from the framework checkout. The case was verified with Helm 3.17.0 and uses OpenSSL for fixture signatures.

Real Helm resolves local chart dependencies and produces the release archive. The first comparison keeps the same resolution lock while the package bytes change. A separate byte check refuses the changed dependency. The reference also validates the merged security setting and checks the rendered workload.

The signed comparison pins a synthetic publisher key before producing release evidence. Helm 3.17.0 serializes the subchart trees inside the parent package. The signed record binds the complete archive and canonical file inventories for the root, direct, and transitive charts. The verifier refuses the altered nested chart and an independently valid signature from an unpinned key. Independent API reads find no release or workload objects for either refusal.

The same gate passes the exact verified archive bytes to Helm for the approved release. Kubernetes readback verifies the merged values for the root and subcharts and disabled token automount for the zero-replica Deployment. Helm separately refuses an invalid token automount override before it stores a release. No fixture workload Pods run.

## Verify an adopting implementation

1. Inventory the actual Helm and GitOps deployment paths, sources, mirrors, dependency trees and value inputs. Record which values have security impact and the approved values for each deployed chart.
2. Preserve the approved dependency resolution and independently establish the expected integrity or signer for every consumed chart artifact. Bind the exact package, supplier identity, source and complete dependency closure to the approved trust policy. Control access to trust configuration and release outputs through actual deployment identities.
3. Exercise the same gate using representative allowed releases and separately scoped altered artifacts or unapproved test signer comparisons. Observe refusal before release creation. Independently verify the final rendered and installed security settings and selected deployment paths.
4. Collect the approved source, lock and provenance records, authenticated producer, key version, exact artifact digest, effective merged values, acceptance or denial, and the deployed release revision. Verify how update, rotation, mirrors and reviewed exceptions are handled.

The signed fixture establishes cryptographic behavior with case-owned keys and explicit public-key inputs. Adopters must establish genuine supplier identity, signing authority, independent trust custody and coverage of their deployment paths.

- [Helm v3.17.0 archive serialization](https://github.com/helm/helm/blob/v3.17.0/pkg/chartutil/save.go)
- [Helm v3.17.0 chart load behavior](https://github.com/helm/helm/blob/v3.17.0/pkg/chart/loader/load.go)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
