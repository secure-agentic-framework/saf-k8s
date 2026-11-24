# SAF-K8S-0910-024 model provenance during registry replication

Run `python3 lab.py test SAF-K8S-0910-024` from the control-lab directory.

The fixture writes an inert model-metadata artifact to a digest-pinned
Distribution registry in a disposable Kind cluster. With the control off,
the second cluster receives the same model bytes and loses the signed
lineage. The governed path preserves the original manifest and signed
lineage. A separate validator reads the actual destination registry and
uses OpenSSL to verify the signature and its model subject. The fixture
also checks refusals for missing, stale, mismatched, and invalid evidence.

Each run issues a fresh disposable RSA key. The peer receives only the
public key. Both peer components call the OpenSSL library in the pinned
Python runtime. The example covers a known artifact and route. Production
trust, long-term custody and complete workflow coverage require additional
deployment evidence.
