# SAF-K8S-1006-001 framework mapping metadata review

Run from the control-lab root:

```sh
python3 lab.py test SAF-K8S-1006-001 --docker-context desktop-linux
```

The lab harness creates a disposable Kind cluster pinned to Kubernetes v1.36.1.
Tokenless, non-root reviewer Jobs use a digest-pinned Docker Official Python
image. Each Job reads only the synthetic mapping ConfigMap and emits a JSON
report to its logs. The harness captures those reports, the Pod specifications,
the input ConfigMaps, and the ordinary raw command transcript under the case's
evidence directory. No secrets are placed in the fixtures.

The first Job reviews a deliberately bad draft. It must expose three authority
misattributions, including an unconditional treatment of the EU provision, missing evidence, and unsupported applicability scope.
The second Job reviews the metadata-complete fixture against synthetic,
preapproved applicability inputs. It must confirm that those inputs are the
only applicability labels accepted, preserve gaps and missing evidence, and
record fictional interim safeguards. A third Job rejects cross-framework scope, a missing reference and premature closure. A separate assertion checks that nine open
gaps remain visible, including missing evidence for EU AI Act Article 15 and
both AICPA criteria. The report expressly leaves framework coverage incomplete.

## Source and authority notes

- Regulation (EU) 2024/1689 is the primary legal text. Its published Article 12
  concerns record-keeping and Article 15 concerns accuracy, robustness and
  cybersecurity for high-risk AI systems. Those provisions are conditional on
  the Regulation's scope and the relevant system/actor facts. The example uses fictional scope inputs. [EUR-Lex, Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- NIST AI RMF 1.0 publishes GOVERN 1.1 as an outcome. NIST describes the AI
  RMF as intended for voluntary use. The fixture therefore labels it a
  voluntary framework outcome, not a law. [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/),
  [NIST AI RMF overview](https://airc.nist.gov/airmf-resources/airmf/)
- AICPA's 2017 Trust Services Criteria, revised points of focus in 2022, are
  criteria used in attestation or consulting engagements. The case recognizes
  CC6.1 and CC7.2 as criteria, not regulations and not standalone universal
  obligations. Their engagement scope and applicability are represented only
  by fictional scenario inputs. [AICPA 2017 TSC (revised 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
- Kind documents pinning a node image by version and digest. The lab harness
  pins the Kind node to v1.36.1; this case separately pins the reviewer image
  by digest. [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/)

These identifier checks are a small explicit catalog for the IDs used in this
fixture, not an automated legal database or a complete framework crosswalk. The
mapping rows express relationships to a SAF control; they do not prove that a
Kubernetes control satisfies a whole law, framework outcome, or criterion.

Applicability values are fictional, preapproved test inputs. A scenario input
that says `high-risk`, `provider`, or `deployer` is not a legal conclusion.
There is no determination of jurisdiction, actor status, risk classification,
transition date, exemption, territorial scope, SOC 2 report scope, or legal
compliance. Metadata review does not show that controls operate effectively.
The example makes no claim that SAF-K8S-1006-001 itself is legally required.

Coverage limits: the case checks identifiers, labels, evidence references,
review completeness, and visible gap/safeguard records in synthetic metadata.
It does not retrieve external laws or live feeds, validate the truth or quality
of supporting evidence, test actual logging/security controls, evaluate
compensating safeguards, verify an audit, or decide that a gap is acceptable.

## Edition and source-revision review

After checking mapping integrity, the case runs a tokenless, non-root reviewer
Job to check the declared source records. The supplemental fixture records six named source identities
used by this example: the 27 July 2026 EUR-Lex consolidated text for Regulation
(EU) 2024/1689, NIST AI RMF 1.0, NIST SP 800-53 Release 5.2.0, SSDF 1.1,
SP 800-218A final, and AICPA 2017 Trust Services Criteria with revised points
of focus 2022. The reviewer binds each fixed synthetic mapping key to its expected framework
name, edition, official source URI and reviewed publication revision.

The added assertion expects all six to match the pinned fixture catalog, rejects
a wrong edition, reports `unknown` for missing source identity metadata, and
reports `review-required` when a controlled counterfactual advances the source
revision after review. The changed revision is a synthetic input to the pure
reviewer; it is not a claim that a new publication was released. The test does
not fetch or monitor sources, interpret their requirements, decide whether a
framework or law applies, validate legal/attestation scope, or establish
compliance. The source records are examples for edition tracking and not a
complete registry of legal or adopted requirements.

Primary edition references: [EUR-Lex current consolidated text, 27 July 2026](https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng); [NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf); [NIST SP 800-53 Release 5.2.0 notice](https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls); [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final); [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final); [AICPA 2017 Trust Services Criteria with 2022 revised points of focus](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022).
