# SAF-K8S-0704-018 — Emergency access activation and closure

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0704-018 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The disposable Kubernetes fixture compares missing and complete synthetic
approvals for a named emergency read. The live binding refers to the
approved fixture record. Actual API requests are refused before activation,
accepted for the exact authorized ConfigMap during the window, and refused
again after the test's logical expiry removes the binding. The unrelated
resource remains denied while the grant is active.

[SAF-K8S-0405-024 separately verifies automatic withdrawal of a temporary grant](https://github.com/secure-agentic-framework/saf-k8s/blob/81d23560f0b71d069820ebb0868b659cf9c3c39d/tests/control-lab/cases/SAF-K8S-0405-024/README.md).

## Verify an adopted recovery path

1. Inventory the actual emergency IAM, identity providers, Kubernetes
   bindings and recovery credentials. Record ownership, custody, permitted
   operations, approvals, standing exceptions and required availability
   when ordinary identity dependencies fail.
2. Conduct a scheduled exercise with approved test resources. Independently
   observe refused access before activation, exact permitted instructions
   and refused unrelated operations during the window. Verify monitoring
   and the review recipient for the application and provider decisions.
3. Remove the real temporary grant or complete applicable issuer
   invalidation and credential recovery. Verify the previous emergency
   access is refused and the ordinary approved route still works.
   Where permanent recovery custody is required, verify its distinct
   review, monitoring and key retirement procedures.
4. Retain approval identities, time bounds, the exact role and observed
   operations, grant withdrawal or credential retirement observations,
   monitoring evidence and the post-use reviewer.

[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/).
