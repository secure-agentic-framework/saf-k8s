# SAF-K8S-1004-005

The pod serves synthetic review records and computes the review decisions inside the cluster.
The case rejects the draft NISTIR 8269 reference, an unsupported incident/class and actor
assertion, contradictory evidence, evidence from another tenant, and stale or incomplete
records. An approved predictive-AI observation has evidence for the system and lifecycle
metadata. The actor and class stay unknown and the record remains pending human review.

NIST lists IR 8269 as a 2019 initial public draft. The final March 2025 edition is
NIST AI 100-2e2025. Its predictive and generative taxonomy and terminology inform this
case-owned review schema. Kubernetes namespace and fixture freshness fields are local
policy. Deployment, production classification, incident attribution and the complete pattern
library require separate evidence.

- [2019 NIST draft](https://csrc.nist.gov/pubs/ir/8269/ipd)
- [Final NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)

The complementary records use synthetic metadata for both the predictive and
generative branches of the final publication. The in-cluster evaluator accepts
both evidence-backed records for human review. If scoped source records disagree
on system type, the evaluator rejects the asserted concrete type and accepts an
explicit unknown with rationale for review. All inputs are abstract metadata.
Deployed detections, incident attribution, and analyst workflow need deployment
evidence.

- [NIST AI 100-2e2025, Sections 2 and 3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)
