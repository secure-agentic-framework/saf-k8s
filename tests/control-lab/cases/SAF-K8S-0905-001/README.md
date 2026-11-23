# SAF-K8S-0905-001

Run `python3 lab.py test SAF-K8S-0905-001` from the control lab directory.
A Kubernetes-native policy matches marked AI Deployments in the case
namespace against a named, stored classification registry. The registry
assigns profiles to both train-verify-lock and continuous-learning systems.
The policy checks the `ai.kais.io/update-model` labels and the registry,
system and profile declarations.

The same incomplete Deployment update is admitted before activation and
denied afterward. The test also checks unknown and mismatched evidence,
then persists both matched profiles and an unscoped comparator. The case
uses inert zero-replica Deployments. Deployed registry authority, human
classification decisions and rollout coverage require separate evidence.

[Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) ·
[Kubernetes v1.36 CustomResourceDefinitions](https://v1-36.docs.kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/)
