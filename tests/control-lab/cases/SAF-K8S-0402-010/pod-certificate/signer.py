"""Purpose-built, single-workload signer for the v1.37 release follow-up.

The signer only processes the named synthetic workload in the named namespace.
It stores its one-off CA key in process memory and emits no request or credential
data. Requires Python 3.11+ and `cryptography` in the supervisor-built image.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


NAMESPACE = os.environ.get("FIXTURE_NAMESPACE", "saf-0402-010-pcr")
POD_NAME = os.environ.get("FIXTURE_POD_NAME", "authorized-workload")
WORKLOAD_SA = os.environ.get("FIXTURE_WORKLOAD_SA", "pod-workload")
SIGNER_SA = "podcert-test-signer"
IDENTITY_DOMAIN = os.environ.get("FIXTURE_DOMAIN", "identity.example.test")
SIGNER_NAME = os.environ.get("FIXTURE_SIGNER_NAME", f"{IDENTITY_DOMAIN}/pod-workload")
CTB_NAME = os.environ.get("FIXTURE_CTB_NAME", "identity.example.test:pod-workload:selected")
CTB_LABEL_KEY = "saf-k8s.example/peer-root"
CTB_LABEL_VALUE = os.environ.get("FIXTURE_CTB_LABEL", "domain-a")
SERVER_DNS = os.environ.get("FIXTURE_SERVER_DNS", "peer-a.fixture.invalid")
EXPECTED_NODE_NAME = os.environ["EXPECTED_NODE_NAME"]
EXPECTED_NODE_UID = os.environ["EXPECTED_NODE_UID"]
MAX_LIFETIME = 3600
REFRESH_OFFSET_SECONDS = 600
API_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"


def api(path: str, method: str = "GET", body: dict | None = None):
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    with open(API_TOKEN, encoding="utf-8") as stream:
        token = stream.read().strip()
    request = urllib.request.Request(
        f"https://{host}:{port}{path}",
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/json",
                 "Content-Type": "application/json"},
    )
    context = ssl.create_default_context(cafile=API_CA)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=10) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                            f"saf-k8s synthetic pod signer {IDENTITY_DOMAIN}")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before((now - dt.timedelta(minutes=1)).replace(tzinfo=None))
            .not_valid_after((now + dt.timedelta(days=2)).replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False),
                           critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def live_identity():
    pod = api(f"/api/v1/namespaces/{NAMESPACE}/pods/{POD_NAME}")
    sa = api(f"/api/v1/namespaces/{NAMESPACE}/serviceaccounts/{WORKLOAD_SA}")
    spec = pod["spec"]
    if (pod["metadata"]["namespace"] != NAMESPACE
            or pod["metadata"]["name"] != POD_NAME
            or spec.get("serviceAccountName") != WORKLOAD_SA
            or not spec.get("nodeName")
            or not pod.get("metadata", {}).get("uid")
            or not sa.get("metadata", {}).get("uid")):
        raise ValueError("identity is not the designated scheduled workload")
    return pod, sa


def issue(pcr: dict, ca_key, ca_cert):
    spec = pcr["spec"]
    if pcr["metadata"].get("namespace") != NAMESPACE:
        return None
    if spec.get("signerName") != SIGNER_NAME:
        return None
    if spec.get("unverifiedUserAnnotations"):
        return None
    if spec.get("maxExpirationSeconds") != MAX_LIFETIME:
        return None
    if (spec.get("podName") != POD_NAME
            or spec.get("serviceAccountName") != WORKLOAD_SA
            or spec.get("keyType") not in (None, "ECDSAP256")):
        return None

    pod, sa = live_identity()
    if (spec.get("podUID") != pod["metadata"].get("uid")
            or spec.get("serviceAccountUID") != sa["metadata"].get("uid")
            or spec.get("nodeName") != pod["spec"].get("nodeName")
            or spec.get("nodeName") != EXPECTED_NODE_NAME
            or spec.get("nodeUID") != EXPECTED_NODE_UID):
        return None

    csr_der = base64.b64decode(spec["stubPKCS10Request"], validate=True)
    csr = x509.load_der_x509_csr(csr_der)
    pub = csr.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        return None

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    not_before = now - dt.timedelta(seconds=30)
    not_after = not_before + dt.timedelta(seconds=MAX_LIFETIME)
    san = f"spiffe://{IDENTITY_DOMAIN}/ns/{NAMESPACE}/sa/{WORKLOAD_SA}"
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, POD_NAME)]))
            .issuer_name(ca_cert.subject).public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before.replace(tzinfo=None))
            .not_valid_after(not_after.replace(tzinfo=None))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san),
                                                           x509.DNSName(SERVER_DNS)]),
                          critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False),
                           critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value),
                critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                                   ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    # Verify the just-built chain before placing any certificate into API status.
    ca_cert.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                                ec.ECDSA(leaf.signature_hash_algorithm))
    chain = (leaf.public_bytes(serialization.Encoding.PEM)
             + ca_cert.public_bytes(serialization.Encoding.PEM)).decode("ascii")
    begin_refresh = not_before + dt.timedelta(seconds=REFRESH_OFFSET_SECONDS)
    return {
        "certificateChain": chain,
        "beginRefreshAt": begin_refresh.isoformat().replace("+00:00", "Z"),
        "notBefore": leaf.not_valid_before_utc.isoformat().replace("+00:00", "Z"),
        "notAfter": leaf.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
        "conditions": [{"type": "Issued", "status": "True",
                        "lastTransitionTime": now.isoformat().replace("+00:00", "Z"),
                        "reason": "SyntheticTestIssued",
                        "message": "Authorized synthetic workload test issuance"}],
    }


def publish_ctb(ca_cert):
    path = f"/apis/certificates.k8s.io/v1/clustertrustbundles/{urllib.parse.quote(CTB_NAME, safe='')}"
    current = api(path)
    labels = dict(current["metadata"].get("labels", {}))
    labels[CTB_LABEL_KEY] = CTB_LABEL_VALUE
    body = {"apiVersion": "certificates.k8s.io/v1", "kind": "ClusterTrustBundle",
            "metadata": {"name": CTB_NAME, "resourceVersion": current["metadata"]["resourceVersion"],
                         "labels": labels},
            "spec": {"signerName": SIGNER_NAME,
                     "trustBundle": ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")}}
    api(path, method="PUT", body=body)


def main():
    ca_key, ca_cert = make_ca()  # Never serialized; lost when this process exits.
    publish_ctb(ca_cert)
    collection = (f"/apis/certificates.k8s.io/v1/namespaces/{NAMESPACE}"
                  "/podcertificaterequests")
    while True:
        stage = "read-request-list"
        try:
            for pcr in api(collection).get("items", []):
                if (pcr.get("status", {}).get("certificateChain")
                        or pcr.get("status", {}).get("conditions")):
                    continue
                stage = "validate-and-sign"
                status = issue(pcr, ca_key, ca_cert)
                if status is None:
                    continue
                meta = pcr["metadata"]
                stage = "write-signer-status"
                api(f"{collection}/{urllib.parse.quote(meta['name'], safe='')}/status",
                    method="PUT", body={
                        "apiVersion": "certificates.k8s.io/v1",
                        "kind": "PodCertificateRequest",
                        "metadata": {"name": meta["name"], "namespace": NAMESPACE,
                                     "uid": meta["uid"], "resourceVersion": meta["resourceVersion"]},
                        "spec": pcr["spec"],
                        "status": status,
                    })
                print('{"issued":true}', flush=True)
        except urllib.error.HTTPError as error:
            if error.code not in (404, 409):
                print(json.dumps({"api_status": error.code, "stage": stage}), flush=True)
                raise SystemExit(1) from None
        except (KeyError, ValueError, OSError) as error:
            print(json.dumps({"fixture_error": type(error).__name__, "stage": stage}), flush=True)
            raise SystemExit(1) from None
        time.sleep(2)


if __name__ == "__main__":
    main()
