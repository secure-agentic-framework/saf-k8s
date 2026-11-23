# Verify fixture runtime observation with Tetragon

```sh
python3 lab.py test SAF-K8S-0606-007 --docker-context desktop-linux
```

The fixture installs a pinned Tetragon chart and images on an owned Kind node.
The exported JSON is scoped to the case namespace. The comparison reads a
public marker before and after a namespaced tracing rule. The test correlates
the filename observation and execution by process ID and checks a separate
public file remains outside the rule. The case needs Helm and a compatible
kernel with supported BPF hooks.

Production audit delivery, connection coverage, credentials and detection
latency need their own deployed evidence.
