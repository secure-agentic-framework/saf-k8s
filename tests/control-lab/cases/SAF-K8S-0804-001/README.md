# SAF-K8S-0804-001 Modeled confidential placement gate

The API rejects the ordinary runtime and missing placement on a labeled fixture namespace. The matching request stays Pending until the owned Kind node receives the modeled approval label. The exact same Pod then becomes Ready.

Both fixture classes resolve to runc and use only a CPU workload. The test exercises admission and scheduling only. Hardware TEE, memory protection, confidential GPU behavior and attestation require separate deployed evidence.
