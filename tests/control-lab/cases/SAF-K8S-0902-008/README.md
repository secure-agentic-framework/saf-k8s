# SAF-K8S-0902-008 — Inference endpoint authentication and authorization

## Case scope

This draft targets a disposable Kind cluster running Kubernetes v1.36.1. It runs a case-owned Python fixture gateway and two separate case-owned backend Services, `model-alpha` and `model-beta`. Each backend returns one fixed synthetic marker. The only application calls are fixed, bodyless `GET` requests to `/v1/models/{model}/infer` on the in-cluster gateway.

Two fixed synthetic identities have disjoint model grants:

| Identity | Authorized model |
| --- | --- |
| `synthetic-client-a` | `model-alpha` |
| `synthetic-client-b` | `model-beta` |

The case creates a fresh 256-bit HS256 test key for each run. The test probe signs only short-lived tokens for those two fixed identities and their fixed grants. The gateway checks the signature in constant time, the fixed issuer and audience, expiry, subject allowlist, and exact model grant. The key is mounted only into the gateway and probe as a Kubernetes Secret volume. It is not read back, printed, included in raw evidence, or included in logs. Tokens and authorization headers are never logged.

## Independent red, green, and positive observations

The red phase starts the same gateway in an explicitly open baseline mode. It sends the two normal requests that will later be rejected: one without an Authorization header to `model-alpha`, and one with a valid `synthetic-client-a` token to `model-beta`. Both should reach their exact owned backend and return the fixed marker. This demonstrates that the requests and endpoint fixtures work before enforcement.

The gateway is then replaced with its enforced mode. The same absent-authorization and wrong-model requests must receive `401 authentication-required` and `403 model-not-authorized`. Gateway logs record the event ID, model, fixed synthetic principal when verified, decision, response code, and backend response code. Backend logs independently record only event ID, model ID, and that a fixed marker was served. A deny must have no corresponding backend event.

Positive requests use `synthetic-client-a` with `model-alpha` and `synthetic-client-b` with `model-beta`. Each must return its own backend's exact marker. The case compares gateway decisions with independent backend events and requires agreement for every red, green, and positive event. Raw request observations, gateway logs, backend logs, sanitized Pod/Service API objects, endpoint addresses, and a scope receipt are retained under the harness evidence directory. No Secret object or Secret data is read back.

## What this demonstrates and leaves open

If both supervisor runs pass, this case demonstrates that, in one disposable Kind v1.36.1 environment, this fixture gateway distinguishes no token, a verified identity asking for an ungranted model, and each of two granted identity/model pairs. It also demonstrates backend non-invocation on those two deny outcomes through an independent backend event log.

It does not establish that the SAF-K8S source claims generally hold. The local test issuer and shared HMAC test key are test fixtures, not an approved identity provider or production key-management design. Production OAuth/OIDC issuer discovery, asymmetric key rotation and revocation, mTLS identity, token exchange, ingress/gateway configuration, TLS termination, externally reachable routes, rate limits, audit retention, and multi-replica consistency are not exercised. The fixture does not claim that raw inference outputs are safe, that a model itself is protected from extraction, or that arbitrary model inputs are safe. Direct backend reachability from other Pods is not restricted or assessed. The control does not specify token claims, model naming, deny semantics, ingress products, or what evidence constitutes continuous enforcement; those remain source-contract clarifications and production evidence obligations.

The EU AI Act and NIST crosswalk text in the pinned control is not tested by this case. No high-risk AI human-oversight workflow, public-content moderation, DLP, access-only behavior, normalization, guardrail, availability, performance, or model-integrity requirement is inferred from the demonstration.

## Images and primary sources

- Kind node image: `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`, the v1.36.1 image published for [Kind v0.32.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0).
- Fixture image: `docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`, from [Docker Official Images Python metadata](https://github.com/docker-library/official-images/blob/master/library/python).
- [RFC 7518, JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.html) defines HS256 as HMAC using SHA-256 and requires constant-time MAC comparison. The fixture has a fresh 32-byte key per run and uses a constant-time signature comparison.
- [RFC 7519, JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519.html) defines the issuer, subject, audience, and expiration claims used in this local test profile.
- [Kubernetes v1.36 Service Accounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/) documents disabling automatic service-account credential mounts. Every case Pod sets `automountServiceAccountToken: false`; none calls the Kubernetes API.
- [Kubernetes v1.36 Secrets](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/) documents Secret volumes. The case uses a temporary Secret only to mount the ephemeral test key into the two local fixture processes; evidence omits its object and data.

The images are digest-pinned, Pods run as non-root with a read-only root filesystem, drop all Linux capabilities, and receive only bounded CPU/memory requests and limits. The harness supervisor is expected to execute and independently verify the red and enforced runs. This authoring draft does not run Docker or Kubernetes, write Beads, or publish artifacts.

The enforced gateway also rejects a normally issued synthetic token whose
expiration has passed. The runner creates the ephemeral key from a private
file and keeps key bytes and credential headers out of the transcript.
