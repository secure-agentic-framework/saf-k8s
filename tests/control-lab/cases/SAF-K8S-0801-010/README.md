# SAF-K8S-0801-010 Accelerator request admission

This disposable Kind case checks actual Kubernetes identity and profile admission, an extended-resource namespace quota and a successfully scheduled Pod. Two units of a synthetic resource are advertised on the owned node while the namespace is restricted to one unit. The workload only runs a CPU sleep command. No accelerator, driver, device plugin, real allocation, or device isolation is exercised.
