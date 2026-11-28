# Signed A100 boot and module admission witness

Run the collector on the disposable Google Compute Engine A100 guest. On the
operator workstation, use the published
[binder instructions](https://github.com/secure-agentic-framework/saf-k8s/blob/0571085d63cadf7517cdf0f6978ea3025301fe09/tests/control-lab/cases/SAF-K8S-0802-008/a100-reference/README.md)
to create a review of the provider events for the exact guest and boot. The
binder checks the provider records against the guest boot timestamp,
instance identity, both loaded module signature artifacts, and both
provider integrity decisions. Keep the original exports with the review.

Capture and review both boots of the same disposable VM. Export the first
capture before the second startup. Install each provider review and its
separate module receipt as root-owned files in a root-owned directory. The
runner requires the same provider instance, distinct kernel boot references,
an increasing provider boot counter and ordered captures. It compares the
second review with the current guest and Kubernetes Node. It verifies that
each review binds exactly its paired module bytes and passing early and late
provider events. These checks depend on trusted operator inputs.

```sh
sudo python3 prove-signed-admission.py \
  /root/reviewed/boot-1.json /root/reviewed/modules-1.json \
  /root/reviewed/boot-2.json /root/reviewed/modules-2.json \
  /root/reviewed/result.json
```

The Kubernetes check requires specific policy and binding denials before it
runs the CPU witness on the reviewed accelerator host. A real impersonated
patch must receive the exact RBAC denial, and the independent readback must
confirm the parameter's UID and data. The offline test `python3 -B ../campaign/boot-order-test.py -v` checks one
ordered pair and rejects six incorrect pairs. It uses the retained boot-1
reference and synthetic second-boot records. The live K3s acceptance result
still requires two fresh captures.
