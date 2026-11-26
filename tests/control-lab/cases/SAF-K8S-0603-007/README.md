# Verify build attestations against signer policy

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0603-007 --docker-context desktop-linux
```

Inert artifacts and case-generated test keys exercise signatures, exact subjects and payloads for the build environment and process. An immutable policy supplied to the consumer before the envelope pins the approved signer for each category, the predicate type, the exact subject and the expected payload hash. Both approved categories verify. A valid signature over the same environment payload from the process signer is refused by the environment policy. The receipt records decisions and booleans.

For adoption, capture the platform and applicable build transformations during an actual build, bind both evidence categories to the released artifact digest, and verify separation from developer-controlled steps. Supply approved signer identities through an independently managed trust policy. Exercise a known approved build and compare a signer or digest mismatch at the actual promotion boundary. Record the policy version, approved producer, build and artifact identity, verification outcome and retention instructions. The portable case covers consumer policy with its own test keys. Trusted producer isolation, concurrent capture, key custody and the deployment decision remain follow-up scope.

[NIST SP 800-204D section 5.1.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf#page=25)

## Scratch observed-build supplement

The additive candidate preserves all 12 published checks and adds three local
checks (15 total). One pinned Python Job performs a deterministic transformation
of an inert JSON input, records the running Python version, platform, command,
script digest, input/output digests, test result and timestamp, and writes only
the output ConfigMap. Its scoped ServiceAccount receives HTTP 403 when it tries
to write collector evidence. A separate collector identity reads the producer
Job, Pod, output and source; it reconciles the actual Pod image/image ID, node
name and Node OS/kernel/architecture/runtime/kubelet facts with the transformed
output, then writes environment and process statements to a separate evidence
ConfigMap. Host API readback independently cross-checks the collected Job, Pod
and Node identity.

The harness creates distinct ephemeral environment and process signing keys in
a temporary directory, signs the collected in-toto Statement payloads, and
passes them to a separate consumer program. The consumer checks exact subject
digest, category predicate, signer pin, actual Pod/Node facts and process input,
tool, output and test facts. A wrong-subject policy comparator is refused. Keys
are deleted with the temporary directory and are not retained in the receipt.

This is an isolated portable mechanism demonstration, not a production builder
or attestor. The host harness signs the collector's recorded statements; it
does not establish an independently managed signing service, tamper-resistant
runner telemetry, full workflow coverage, managed runner provenance, registry
binding, organization key custody, or deployment gate enforcement. NIST
SP 800-204D treats process collection as best effort; adopters must document the
collection source, omissions and trust boundary.

## Adopter evidence

1. Inventory each in-scope pipeline, runner pool/image, platform, toolchain,
   transformation/test stage, input, output and responsible identity. Capture
   actual execution-time platform facts and process/tool facts from a trusted
   collector, including omissions and non-hermetic inputs.
2. Bind both categories to the immutable artifact digest. Preserve the exact
   input and output digests, commands, tool versions, test outcomes, producer
   identity and event times. Show the evidence collector's permissions and
   prove ordinary build identities cannot alter evidence or signing policy.
3. Use organization-managed distinct trust for environment and process
   attestations. Record signer identity, key/policy version, custody, rotation,
   revocation and exception handling. Verify category, predicate, subject,
   artifact and actual workflow against independently maintained expectations.
4. Exercise a real promotion/deployment consumer with one approved build and
   one altered subject, unapproved signer or missing category. Retain the exact
   decision, artifact identity and evidence references.
5. For managed builders, retain provider attestations or equivalent source
   records for runner image, node/platform and process capture. Reconcile those
   records to the deployed pipeline and state explicitly which stages are not
   covered by the provider's best-effort collection.

The canonical control has no crosswalk rows, so this candidate proposes no
crosswalk change. The primary normative reference is [NIST SP 800-204D §5.1.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf#page=25).
Reusable local patterns are [0606-018 case README](../SAF-K8S-0606-018/README.md) for separate workload identities and [0905-047 case README](../SAF-K8S-0905-047/README.md) for real bounded build steps and signed in-toto statements.
