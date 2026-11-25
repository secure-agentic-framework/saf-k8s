# APF HTTP 429 response contract

The Kubernetes apiserver v0.36.1 test creates one in-process HTTP test
server and injects a rejection decision into the APF filter. It asserts
HTTP 429 and the request and termination metrics. The test result supports
the filter response once APF has decided to reject. The native Kind case
covers actual configuration and sampled classifications separately.

## Reproduce

Use Go 1.26 and the pinned public apiserver module. From a trusted module
cache containing the pinned source, run from the apiserver module directory.

```sh
go mod download -json k8s.io/apiserver@v0.36.1
# Change to the Dir reported for the pinned module.
go test -p 2 -vet=off -count=1 -v -run '^TestApfRejectRequest$' ./pkg/server/filters
```

## Recorded result

Go 1.26.4. The pinned module checksum was `h1:iMS5V+rPUertv5P9RaqJgmHHTuh4quWpoxchvMUY+JY=`.
The run reported `PASS: TestApfRejectRequest`.

The fixture injects the decision. Review live queue depth, wait durations,
and rejection rates under representative observed demand when adopting
a priority policy.

- [Kubernetes apiserver v0.36.1 test source](https://github.com/kubernetes/apiserver/blob/v0.36.1/pkg/server/filters/priority-and-fairness_test.go)
