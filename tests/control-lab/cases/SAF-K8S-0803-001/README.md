# SAF-K8S-0803-001 Placement policy around accelerator domains

The test uses two disposable Kind nodes and CPU-only Pods. It observes a denied contrary domain and verifies successful scheduling to two separate selected nodes. Those nodes and labels model an approved assignment boundary. They do not expose or isolate an NVLink, NVSwitch, GPU topology, or physical fabric.
