# Projected service account token lifetime bounds

The fixture configures the kube-apiserver issuer with a one-hour cap and
disables the compatibility extension for admission-injected tokens. A
namespace policy requires expiration requests between 600 and 3600 seconds
on Pod volume projections. The values are sample settings for this lab.

The case observes the actual auto-injected lifetime, contrasts Pod admission
before and after the policy, and checks the lifetime of a running Pod's
explicit projection. Direct TokenRequest probes cover a short request and a
two-hour request clipped to one hour, including an explicitly named sample
relying-party audience. Evidence contains only derived JWT claims.
