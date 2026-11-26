# Verify Zot audit forwarding to an authenticated receiver

    python3 tests/control-lab/lab.py test SAF-K8S-0905-040 --docker-context desktop-linux

The case compares local access and audit observations with and without
Fluent Bit forwarding. It covers the fixture registry's OCI publication,
pull, tag and deletion actions, the HTTPS receiver's enrolled credential,
and retained readback after receiver Pod replacement.

The administrative check submits only a fixed public fixture key. The
registry compares the publisher and scoped administrator requests. The
observer verifies the administrator's attributed local audit and access
records and the matching forwarded events.

For a deployment, inventory covered administrative and OCI actions, the
authenticated collector and independent protected receiver, loss and retry
handling, and durable retention. Capture ordinary authorized comparisons
through the adopted registry and audit delivery path.
