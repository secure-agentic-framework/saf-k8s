# SAF-K8S-0801-002 Accelerator profile accounting

A disposable Kind node initially has no fixture profile. The case observes the scheduler reject an explicit request, adds exactly two units of a synthetic extended resource, and observes the same Pod run with those two units. Another profile and an additional request remain unschedulable for the respective resource.

Only the Kubernetes profile name and quantity accounting are real. The resource keys are synthetic. Vendor configuration, installed device plugin behavior and the physical isolation properties of a supported GPU require separate evidence.

## Adopter verification

1. Record physical GPU model, driver and plugin configuration, MIG mode, sharing strategy and supported profile inventory for each enrolled node pool.
2. Reconcile administrator-visible device geometry and partition identity with the resources advertised by Kubernetes. Test an approved Pod against the exact advertised profile and verify the allocated device from the workload.
3. Show attributable outcomes for the approved profile, an unknown profile and an exhausted profile. Check that a tenant receives only the approved slice and applicable telemetry.
4. Retain compatibility sources, configuration and allocation evidence. Repeat after GPU reset, node replacement or driver and plugin changes.
