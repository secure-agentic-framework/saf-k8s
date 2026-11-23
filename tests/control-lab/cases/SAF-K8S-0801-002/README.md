# SAF-K8S-0801-002 Accelerator profile accounting

A disposable Kind node initially has no fixture profile. The case observes the scheduler reject an explicit request, adds exactly two units of a synthetic extended resource, and observes the same Pod run with those two units. Another profile and an additional request remain unschedulable for the respective resource.

Only the Kubernetes profile name and quantity accounting are real. The resource keys are synthetic. Vendor configuration, installed device plugin behavior and the physical isolation properties of a supported GPU require separate evidence.
