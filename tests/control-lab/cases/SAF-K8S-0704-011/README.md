# Verify metadata-like egress restriction and workload identity on Kind

```sh
python3 lab.py test SAF-K8S-0704-011 --docker-context desktop-linux
```

NetworkPolicy excludes a case-owned public comparison marker. The approved
path remains reachable and separately performs a Kubernetes TokenReview for
its exact service account and audience. The fixture retains only outcome
metadata.

The endpoints are synthetic. Verify the real provider metadata endpoints,
node and Pod policy coverage, and provider workload permissions separately.

The approved endpoint observes a Kubernetes ServiceAccount through TokenReview. Verify provider federation and cloud grants on the adopted path.
