# SAF-K8S-0503-006 cloud load-balancer security group admission

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0503-006 --docker-context desktop-linux
```

This case uses an AWS Load Balancer Controller NLB annotation as a Kubernetes admission prerequisite. It stores two synthetic security-group IDs in a governed Kubernetes policy parameter. A scoped Service writer can read that parameter. Kubernetes rejects attempts by the writer to change it. The real API accepts an unapproved group before policy activation, rejects unapproved or missing groups afterward, and preserves legitimate create and update requests.

The fixture covers AWS-class Service admission. Collect deployed cloud evidence for the effective frontend rules, backend rules, controller settings and approved source checks. The example identifiers represent lab values.

[AWS Load Balancer Controller Service annotations](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v3.2/guide/service/annotations/) and [Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).
