# SAF-K8S-1004-006

Two native Kubernetes Jobs compare technical severity with a case-owned contextual triage
rule over synthetic records. The rule joins cluster, namespace and workload, checks a
five-minute observation window and a review cutoff, and requires one valid business context
record for a priority increase. A qualifying medium-severity event moves ahead of a
high-severity event while the critical event stays first. Another namespace, events arriving
after the review, expired context and overlapping business records cannot produce a boost.

The output is advisory to a human reviewer and carries no attribution. NIST SP 800-53
AU-6(9) supports nontechnical context in audit analysis and identifies privacy considerations.
This case leaves deployed SIEM/SOAR, source authorization, processing of sensitive input,
and analyst operating evidence to separate review.

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
