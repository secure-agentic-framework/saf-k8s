# SAF-K8S-0905-033 model preflight

Run `python3 lab.py test SAF-K8S-0905-033` from the control-lab directory.

The case downloads the approved official SafeTensors 0.8.0 wheel from PyPI,
verifies its SHA-256, and loads it inside a disposable Kind Pod. The fixed
test assets are tiny, inert numeric tensors. The unchecked baseline accepts
a native-format tensor whose type violates the application policy. With
preflight enabled, the Pod rejects that tensor and a plainly wrong length
before native loading. It loads the approved tensor and reports its exact
values. Coverage of other formats, operators and deployed policies requires
a separate review.
