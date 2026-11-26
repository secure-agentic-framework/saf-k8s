# SAF-K8S-0703-014 scoped automated budget response

Run `python3 lab.py test SAF-K8S-0703-014` from the control-lab directory. The first three checks exercise a live HPA and its enforced replica maximum.

## Added behavior

The fixture creates two disposable, sleeping BusyBox Jobs in `saf-budget-0703-014`: `owned-training` and `unrelated-training`. Five ConfigMaps provide fixed synthetic integer “spend units,” named target, freshness, and an armed/unarmed decision flag. These values are not currency or provider billing records.

Two successive pinned Python evaluator Jobs receive the fixed event names, uses a projected short-lived ServiceAccount token and the namespace API CA, and connects to the Kubernetes API with certificate verification. Its Role permits `get` only for the five named event ConfigMaps, `patch` only for five pre-created marker ConfigMaps, and `patch` only for the `owned-training` Job. The ServiceAccount's automatic token mount is disabled; the evaluator receives the explicit projected token volume only. The token, authorization header, and API response bodies are never written to logs or evidence.

The first evaluator handles the non-enforcing events. The runner verifies both Jobs remain active before it starts the second evaluator with the armed threshold. Each writes one response marker per event. The runner reads those markers and both Jobs independently:

4. **Red:** an unarmed hard-limit event yields `alert` and leaves the target Job active.
5. **Positive:** a warning, stale event, and event targeting the other Job yield `alert`/`hold`; neither Job changes.
6. **Green:** an armed current hard-limit event suspends only the approved Job. A server-side dry-run patch against the unrelated Job must return `Forbidden`, and independent API reads verify it remains active.

The response is performed by a real in-cluster process presenting its projected ServiceAccount token. A successful target patch and marker patch show the API accepted that identity's scoped operations; the marker alone is not treated as audit attribution. The evaluator checks fixed event names and exact namespace/target before action. The server-side dry-run comparator cannot persist a change.

## Limits and adoption

This proves a Kubernetes-native reference event evaluator and one bounded Job-suspension response. It does not connect to a provider billing feed, measure actual spend, enforce GPU/node-group ceilings, prove invoice semantics, or validate a deployed controller's operation. Actual provider event authentication, account/project scope, budget threshold semantics, freshness/missing-event behavior, response permissions, notification, rollback, and provider compute limits remain adopter verification in an approved nonproduction account.

The six checks use pinned BusyBox and Python images and case-owned Kubernetes resources.
