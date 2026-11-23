# SAF-K8S-0601-020 registry authentication and repository roles

The case starts a local Distribution registry with real signed-token
enforcement and a fixture issuer. Before applying repository roles a
fixture reader can write. A ConfigMap supplies explicit reader,
publisher and adjacent-repository permissions. New token requests
use those scopes. The basic identity, signed tokens and private key
are disposable and excluded from persistent evidence.

Anonymous reads and bad credentials are rejected. The reader can pull
the exact fixture but cannot publish. The publisher can write to the
approved repository and cannot read or write the adjacent repository.
The published fixture uses loopback HTTP. Production TLS, credential
rotation, cloud IAM, and lifecycle need separate evidence.

[CNCF Distribution token authentication](https://distribution.github.io/distribution/spec/auth/token/)
